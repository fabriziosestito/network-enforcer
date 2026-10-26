package e2e_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

const (
	metricsReaderClusterRoleSuffix = "-metrics-reader"
	metricsComponentLabelSelector  = "app.kubernetes.io/component=controller"
	metricsLivenessSeries          = "go_goroutines"
	metricsUnattributedSeries      = "network_enforcer_violations_unattributed_total"
	metricsPort                    = 8443
	metricsScrapeTimeout           = time.Minute
	metricsScrapeInterval          = 2 * time.Second
	metricsStabilityWindow         = 20 * time.Second
	unattributedReasonNoTarget     = "no_target_policy"
)

func grantMetricsAccess(ctx context.Context, t *testing.T) {
	t.Helper()
	r := getSecurityV1Alpha1Client(ctx)
	namespace := getNamespace(ctx)
	name := "network-enforcer-e2e-metrics-" + namespace
	binding := &rbacv1.ClusterRoleBinding{
		Name: name,
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     defaultReleaseName + metricsReaderClusterRoleSuffix,
		},
		Subjects: []rbacv1.Subject{{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      simpleAppClientServiceAccount,
			Namespace: namespace,
		}},
	}
	if err := r.Create(ctx, binding); err != nil && !apierrors.IsAlreadyExists(err) {
		require.NoError(t, err, "failed to create metrics reader ClusterRoleBinding %q", name)
	}
	t.Cleanup(func() {
		if err := r.Delete(context.WithoutCancel(ctx), binding); err != nil && !apierrors.IsNotFound(err) {
			t.Logf("failed to delete metrics reader ClusterRoleBinding %q: %v", name, err)
		}
	})
}

func expectedMetricProvider(ctx context.Context) string {
	if getSuiteConfig(ctx).IsIstioProvider() {
		return string(securityv1alpha1.PolicyBackendIstio)
	}
	return string(securityv1alpha1.PolicyBackendKubernetes)
}

func stableUnattributedTotal(ctx context.Context, t *testing.T, provider, reason string) (float64, string) {
	t.Helper()
	var (
		baseline  float64
		identity  string
		startedAt time.Time
	)
	require.Eventually(t, func() bool {
		value, currentIdentity, err := tryScrapeUnattributedTotal(ctx, provider, reason)
		if err != nil {
			t.Logf("failed to scrape controller metrics: %v", err)
			return false
		}
		if startedAt.IsZero() || currentIdentity != identity || value != baseline {
			startedAt = time.Now()
			baseline = value
			identity = currentIdentity
			return false
		}
		return time.Since(startedAt) >= metricsStabilityWindow
	}, metricsStabilityWindow+metricsScrapeTimeout, metricsScrapeInterval,
		"the unattributed violations counter did not become stable before the traffic was sent")
	return baseline, identity
}

func requireUnattributedTotalIncreased(
	ctx context.Context,
	t *testing.T,
	provider, reason string,
	baseline float64,
	identity string,
	send func(),
) {
	t.Helper()
	var identityChanged bool
	require.Eventually(t, func() bool {
		send()
		value, currentIdentity, err := tryScrapeUnattributedTotal(ctx, provider, reason)
		if err != nil {
			t.Logf("failed to scrape controller metrics: %v", err)
			return false
		}
		if currentIdentity != identity {
			identityChanged = true
			return true
		}
		return value >= baseline+1
	}, defaultOperationTimeout, metricsScrapeInterval,
		"the unattributed violations counter did not increase for provider %q reason %q", provider, reason)
	require.False(t, identityChanged,
		"the controller metrics identity changed while observing unattributed violations")
}

func tryScrapeUnattributedTotal(ctx context.Context, provider, reason string) (float64, string, error) {
	pods, err := controllerPods(ctx)
	if err != nil {
		return 0, "", err
	}
	if len(pods) == 0 {
		return 0, "", errors.New("no controller pods found")
	}
	want := map[string]string{
		"provider":  provider,
		"direction": "Ingress",
		"reason":    reason,
	}
	var total float64
	identities := make([]string, 0, len(pods))
	for i := range pods {
		pod := pods[i]
		body, curlErr := curlControllerMetrics(ctx, pod.Status.PodIP)
		if curlErr != nil {
			return 0, "", curlErr
		}
		families, parseErr := parseMetrics(body)
		if parseErr != nil {
			return 0, "", parseErr
		}
		if _, ok := families[metricsLivenessSeries]; !ok {
			return 0, "", fmt.Errorf(
				"metrics endpoint on pod %q did not expose %q", pod.Name, metricsLivenessSeries)
		}
		total += sumCounter(families, metricsUnattributedSeries, want)
		identities = append(identities, fmt.Sprintf("%s/%s/%d", pod.UID, pod.Status.PodIP, restartCount(pod)))
	}
	return total, strings.Join(identities, ","), nil
}

func controllerPods(ctx context.Context) ([]corev1.Pod, error) {
	var pods corev1.PodList
	err := getSecurityV1Alpha1Client(ctx).
		WithNamespace(getSuiteConfig(ctx).releaseNS).
		List(ctx, &pods, resources.WithLabelSelector(metricsComponentLabelSelector))
	if err != nil {
		return nil, fmt.Errorf("failed to list controller pods: %w", err)
	}
	ready := make([]corev1.Pod, 0, len(pods.Items))
	for i := range pods.Items {
		pod := pods.Items[i]
		if pod.Status.PodIP == "" || pod.Status.Phase != corev1.PodRunning || pod.DeletionTimestamp != nil {
			continue
		}
		ready = append(ready, pod)
	}
	return ready, nil
}

func curlControllerMetrics(ctx context.Context, podIP string) (string, error) {
	var stdout, stderr bytes.Buffer
	execCtx, cancel := context.WithTimeout(ctx, defaultPodExecTimeout)
	defer cancel()
	command := []string{"sh", "-c", fmt.Sprintf(
		`curl -fsS -k --connect-timeout 5 --max-time 10 `+
			`-H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" `+
			`https://%s:%d/metrics`,
		podIP, metricsPort,
	)}
	if err := getSecurityV1Alpha1Client(ctx).ExecInDeployment(
		execCtx, getNamespace(ctx), simpleAppClientDeploymentName, command, &stdout, &stderr,
	); err != nil {
		return "", fmt.Errorf("failed to scrape controller metrics from %s: %w: %s", podIP, err, stderr.String())
	}
	return stdout.String(), nil
}

func parseMetrics(body string) (map[string]*dto.MetricFamily, error) {
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to parse metrics exposition: %w", err)
	}
	return families, nil
}

func sumCounter(families map[string]*dto.MetricFamily, name string, want map[string]string) float64 {
	family, ok := families[name]
	if !ok {
		return 0
	}
	var total float64
	for _, metric := range family.GetMetric() {
		if !metricHasLabels(metric, want) {
			continue
		}
		total += metric.GetCounter().GetValue()
	}
	return total
}

func metricHasLabels(metric *dto.Metric, want map[string]string) bool {
	got := make(map[string]string, len(metric.GetLabel()))
	for _, pair := range metric.GetLabel() {
		got[pair.GetName()] = pair.GetValue()
	}
	for name, value := range want {
		if got[name] != value {
			return false
		}
	}
	return true
}

func restartCount(pod corev1.Pod) int32 {
	var restarts int32
	for _, status := range pod.Status.ContainerStatuses {
		restarts += status.RestartCount
	}
	return restarts
}
