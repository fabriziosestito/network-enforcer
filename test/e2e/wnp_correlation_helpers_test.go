package e2e_test

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"istio.io/api/annotation"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

const (
	netshootImage            = "nicolaka/netshoot:v0.16"
	correlationAppLabel      = "app"
	correlationWorkloadLabel = "workload"
	correlationTierLabel     = "tier"
	correlationCanaryTier    = "canary"
	correlationTCPPayload    = "correlation-e2e-payload"
	correlationSleepDuration = "10d"

	wnpReadyConditionType    = "Ready"
	reasonSelectorScopeValid = "SelectorScopeValid"
	reasonSelectorOverlaps   = "SelectorOverlapsWorkload"

	attributionSettleWindow = 25 * time.Second
)

type correlationWNPSpec struct {
	name        string
	targetName  string
	direction   networkingv1.PolicyType
	mode        securityv1alpha1.WorkloadNetworkPolicyMode
	selector    map[string]string
	allowedPort int32
}

func createCorrelationDeployment(
	ctx context.Context,
	t *testing.T,
	name string,
	selectorLabels, templateLabels map[string]string,
	command []string,
) {
	t.Helper()
	namespace := getNamespace(ctx)
	replicas := int32(1)
	deployment := &appsv1.Deployment{
		Name: name, Namespace: namespace,
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: selectorLabels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: templateLabels},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:    name,
						Image:   netshootImage,
						Command: command,
					}},
				},
			},
		},
	}
	require.NoError(t, getSecurityV1Alpha1Client(ctx).Create(ctx, deployment),
		"failed to create Deployment %q", name)
	require.NoError(t,
		wait.For(conditions.New(getSecurityV1Alpha1Client(ctx)).DeploymentAvailable(name, namespace),
			wait.WithTimeout(defaultOperationTimeout)),
		"wait Deployment %q ready", name)
}

func correlationListenerCommand() []string {
	return []string{"sh", "-c", fmt.Sprintf(`set -eu
socat -d -d TCP-LISTEN:%d,reuseaddr,fork EXEC:/bin/cat >/tmp/tcp-listener.log 2>&1 &
socat -d -d TCP-LISTEN:%d,reuseaddr,fork EXEC:/bin/cat >/tmp/tcp-listener-violating.log 2>&1 &
socat -d -d UDP-RECVFROM:%d,reuseaddr,fork EXEC:/bin/cat >/tmp/udp-listener.log 2>&1 &
wait`,
		simpleAppTCPServicePort, simpleAppViolatingServicePort, simpleAppUDPServerPort)}
}

func newCorrelationWNP(
	ctx context.Context,
	spec correlationWNPSpec,
) *securityv1alpha1.WorkloadNetworkPolicy {
	namespace := getNamespace(ctx)
	wnp := &securityv1alpha1.WorkloadNetworkPolicy{
		Name: spec.name, Namespace: namespace,
		Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
			WorkloadTargetingSpec: securityv1alpha1.WorkloadTargetingSpec{
				TargetRef: securityv1alpha1.WorkloadTargetRef{
					Kind: securityv1alpha1.WorkloadKindDeployment,
					Name: spec.targetName,
				},
				Direction: spec.direction,
			},
			Mode: spec.mode,
		},
	}
	if getSuiteConfig(ctx).IsIstioProvider() {
		wnp.Spec.PolicyBackendSpec = istioBackendSpec(namespace, spec)
		return wnp
	}
	wnp.Spec.PolicyBackendSpec = kubernetesBackendSpec(namespace, spec)
	return wnp
}

func istioBackendSpec(namespace string, spec correlationWNPSpec) securityv1alpha1.PolicyBackendSpec {
	istioSpec := &securityv1alpha1.IstioAuthorizationPolicySpec{
		Selector: metav1.LabelSelector{MatchLabels: spec.selector},
	}
	if spec.allowedPort > 0 {
		istioSpec.Rules = []securityv1alpha1.IstioAuthorizationPolicyRule{{
			From: []securityv1alpha1.IstioFrom{{
				Source: securityv1alpha1.IstioSource{
					Principals: []string{istioPrincipal(namespace, simpleAppClientServiceAccount)},
				},
			}},
			To: []securityv1alpha1.IstioTo{{
				Operation: securityv1alpha1.IstioOperation{
					Ports: []string{strconv.FormatInt(int64(spec.allowedPort), 10)},
				},
			}},
		}}
	}
	return securityv1alpha1.PolicyBackendSpec{
		Backend: securityv1alpha1.PolicyBackendIstio,
		Istio:   istioSpec,
	}
}

func kubernetesBackendSpec(namespace string, spec correlationWNPSpec) securityv1alpha1.PolicyBackendSpec {
	k8sSpec := &networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{MatchLabels: spec.selector},
		PolicyTypes: []networkingv1.PolicyType{spec.direction},
	}
	if spec.allowedPort > 0 {
		port := intstr.FromInt32(spec.allowedPort)
		protocol := corev1.ProtocolTCP
		peer := networkingv1.NetworkPolicyPeer{
			NamespaceSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{corev1.LabelMetadataName: namespace},
			},
			PodSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{correlationAppLabel: simpleAppClientDeploymentName},
			},
		}
		switch spec.direction {
		case networkingv1.PolicyTypeIngress:
			k8sSpec.Ingress = []networkingv1.NetworkPolicyIngressRule{{
				From:  []networkingv1.NetworkPolicyPeer{peer},
				Ports: []networkingv1.NetworkPolicyPort{{Port: &port, Protocol: &protocol}},
			}}
		case networkingv1.PolicyTypeEgress:
			k8sSpec.Egress = []networkingv1.NetworkPolicyEgressRule{{
				To:    []networkingv1.NetworkPolicyPeer{peer},
				Ports: []networkingv1.NetworkPolicyPort{{Port: &port, Protocol: &protocol}},
			}}
		}
	}
	return securityv1alpha1.PolicyBackendSpec{
		Backend:    securityv1alpha1.PolicyBackendKubernetes,
		Kubernetes: k8sSpec,
	}
}

func createCorrelationWNP(
	ctx context.Context,
	t *testing.T,
	spec correlationWNPSpec,
) {
	t.Helper()
	require.NoError(t, getSecurityV1Alpha1Client(ctx).Create(ctx, newCorrelationWNP(ctx, spec)),
		"failed to create WorkloadNetworkPolicy %q", spec.name)
}

func getCorrelationWNP(ctx context.Context, t *testing.T, name string) securityv1alpha1.WorkloadNetworkPolicy {
	t.Helper()
	var wnp securityv1alpha1.WorkloadNetworkPolicy
	require.NoError(t, getSecurityV1Alpha1Client(ctx).Get(ctx, name, getNamespace(ctx), &wnp),
		"failed to get WorkloadNetworkPolicy %q", name)
	return wnp
}

func requireWNPCondition(
	ctx context.Context,
	t *testing.T,
	name string,
	status metav1.ConditionStatus,
	reason, messageContains string,
) {
	t.Helper()
	require.Eventually(t, func() bool {
		var wnp securityv1alpha1.WorkloadNetworkPolicy
		if err := getSecurityV1Alpha1Client(ctx).Get(ctx, name, getNamespace(ctx), &wnp); err != nil {
			return false
		}
		condition := apimeta.FindStatusCondition(wnp.Status.Conditions, wnpReadyConditionType)
		return condition != nil &&
			condition.Status == status &&
			condition.Reason == reason &&
			condition.ObservedGeneration == wnp.Generation &&
			strings.Contains(condition.Message, messageContains)
	}, defaultOperationTimeout, time.Second,
		"WorkloadNetworkPolicy %q never reached Ready=%s reason=%s containing %q",
		name, status, reason, messageContains)
}

func requireProtectPolicyRendered(ctx context.Context, t *testing.T, name string) {
	t.Helper()
	wnp := getCorrelationWNP(ctx, t, name)
	if getSuiteConfig(ctx).IsIstioProvider() {
		ap := getAuthorizationPolicy(ctx, t, name)
		require.True(t, metav1.IsControlledBy(ap, &wnp),
			"AuthorizationPolicy %q is not controlled by WorkloadNetworkPolicy %q", name, name)
		require.NotContains(t, ap.Annotations, annotation.IoIstioDryRun.Name,
			"AuthorizationPolicy %q must not carry the dry-run annotation in protect mode", name)
		require.Equal(t, wnp.Spec.Istio.Selector.MatchLabels, ap.Spec.GetSelector().GetMatchLabels(),
			"AuthorizationPolicy selector does not match the WorkloadNetworkPolicy selector")
		return
	}
	np := getNetworkPolicy(ctx, t, name)
	require.True(t, metav1.IsControlledBy(&np, &wnp),
		"NetworkPolicy %q is not controlled by WorkloadNetworkPolicy %q", name, name)
	require.Equal(t, wnp.Spec.Kubernetes.PodSelector, np.Spec.PodSelector,
		"NetworkPolicy selector does not match the WorkloadNetworkPolicy selector")
	require.ElementsMatch(t, wnp.Spec.Kubernetes.PolicyTypes, np.Spec.PolicyTypes,
		"NetworkPolicy policyTypes do not match the WorkloadNetworkPolicy")
}

func requireMonitorPolicyState(ctx context.Context, t *testing.T, name string) {
	t.Helper()
	wnp := getCorrelationWNP(ctx, t, name)
	require.Equal(t, securityv1alpha1.WorkloadNetworkPolicyModeMonitor, wnp.Spec.Mode,
		"WorkloadNetworkPolicy %q must remain in monitor mode", name)
	if getSuiteConfig(ctx).IsIstioProvider() {
		ap := getAuthorizationPolicy(ctx, t, name)
		require.True(t, metav1.IsControlledBy(ap, &wnp),
			"AuthorizationPolicy %q is not controlled by WorkloadNetworkPolicy %q", name, name)
		require.Equal(t, "true", ap.Annotations[annotation.IoIstioDryRun.Name],
			"AuthorizationPolicy %q must stay in dry-run while its WorkloadNetworkPolicy is in monitor mode", name)
		return
	}
	deadline := time.Now().Add(neverAssertionTime)
	for time.Now().Before(deadline) {
		var np networkingv1.NetworkPolicy
		err := getSecurityV1Alpha1Client(ctx).Get(ctx, name, getNamespace(ctx), &np)
		require.True(t, apierrors.IsNotFound(err),
			"monitor WorkloadNetworkPolicy %q must not render a NetworkPolicy, got: %v", name, err)
		time.Sleep(time.Second)
	}
}

func getAuthorizationPolicy(ctx context.Context, t *testing.T, name string) *istiosecurityv1.AuthorizationPolicy {
	t.Helper()
	var ap istiosecurityv1.AuthorizationPolicy
	require.NoError(t, getSecurityV1Alpha1Client(ctx).Get(ctx, name, getNamespace(ctx), &ap),
		"failed to get AuthorizationPolicy %q", name)
	return &ap
}

func getNetworkPolicy(ctx context.Context, t *testing.T, name string) networkingv1.NetworkPolicy {
	t.Helper()
	var np networkingv1.NetworkPolicy
	require.NoError(t, getSecurityV1Alpha1Client(ctx).Get(ctx, name, getNamespace(ctx), &np),
		"failed to get NetworkPolicy %q", name)
	return np
}

func setDeploymentTemplateLabel(ctx context.Context, t *testing.T, name, label, value string) {
	t.Helper()
	r := getSecurityV1Alpha1Client(ctx)
	require.NoError(t, retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var deployment appsv1.Deployment
		if err := r.Get(ctx, name, getNamespace(ctx), &deployment); err != nil {
			return err
		}
		deployment.Spec.Template.Labels[label] = value
		return r.Update(ctx, &deployment)
	}))
}

func readyPodIPs(ctx context.Context, t *testing.T, selector map[string]string) []string {
	t.Helper()
	var pods corev1.PodList
	require.NoError(t,
		getSecurityV1Alpha1Client(ctx).WithNamespace(getNamespace(ctx)).List(ctx, &pods),
		"failed to list pods")
	matcher := labels.SelectorFromSet(selector)
	ips := make([]string, 0, len(pods.Items))
	for i := range pods.Items {
		pod := pods.Items[i]
		if pod.Status.Phase != corev1.PodRunning || pod.Status.PodIP == "" || pod.DeletionTimestamp != nil {
			continue
		}
		if matcher.Matches(labels.Set(pod.Labels)) {
			ips = append(ips, pod.Status.PodIP)
		}
	}
	return ips
}

func sendClientTrafficToPort(ctx context.Context, port int32) {
	_, cmd := getProtoCmd(corev1.ProtocolTCP, port)
	_, _, _ = execInDeploymentRaw(ctx, simpleAppClientDeploymentName, cmd)
}

func sendTrafficFromDeploymentToPod(ctx context.Context, deployment, podIP string, port int32) {
	_, _, _ = execInDeploymentRaw(ctx, deployment, []string{"sh", "-c", fmt.Sprintf(
		"printf %s | nc -w 2 %s %d",
		strconv.Quote(correlationTCPPayload),
		podIP,
		port,
	)})
}

func sendTrafficUntilViolation(
	ctx context.Context,
	t *testing.T,
	send func(),
	wnpName string,
	match func(securityv1alpha1.ViolationRecord) bool,
	description string,
) {
	t.Helper()
	require.Eventually(t, func() bool {
		send()
		var wnp securityv1alpha1.WorkloadNetworkPolicy
		if err := getSecurityV1Alpha1Client(ctx).Get(ctx, wnpName, getNamespace(ctx), &wnp); err != nil {
			return false
		}
		return slices.ContainsFunc(wnp.Status.Violations, match)
	}, defaultOperationTimeout, 2*time.Second,
		"no %s on WorkloadNetworkPolicy %q", description, wnpName)
}

func requireNoViolationMatching(
	ctx context.Context,
	t *testing.T,
	wnpName string,
	match func(securityv1alpha1.ViolationRecord) bool,
	description string,
) {
	t.Helper()
	deadline := time.Now().Add(attributionSettleWindow)
	for time.Now().Before(deadline) {
		var wnp securityv1alpha1.WorkloadNetworkPolicy
		require.NoError(t, getSecurityV1Alpha1Client(ctx).Get(ctx, wnpName, getNamespace(ctx), &wnp),
			"failed to get WorkloadNetworkPolicy %q", wnpName)
		require.False(t, slices.ContainsFunc(wnp.Status.Violations, match), "%s", description)
		time.Sleep(time.Second)
	}
}

func isIngressClientToServerViolation(violation securityv1alpha1.ViolationRecord) bool {
	return violation.Action == securityv1alpha1.WorkloadNetworkPolicyModeProtect &&
		violation.Protocol == corev1.ProtocolTCP &&
		violation.DstPort == simpleAppViolatingServicePort &&
		violation.Source.OwnerName == simpleAppClientDeploymentName &&
		violation.Dest.OwnerName == simpleAppServerDeploymentName
}

func isEgressServerToClientViolation(violation securityv1alpha1.ViolationRecord) bool {
	return violation.Action == securityv1alpha1.WorkloadNetworkPolicyModeProtect &&
		violation.Protocol == corev1.ProtocolTCP &&
		violation.DstPort == simpleAppTCPServicePort &&
		violation.Source.OwnerName == simpleAppServerDeploymentName
}

func assertIngressViolationAttributed(ctx context.Context, t *testing.T, wnpName string) {
	t.Helper()
	namespace := getNamespace(ctx)
	sendTrafficUntilViolation(
		ctx, t,
		func() { sendClientTrafficToPort(ctx, simpleAppViolatingServicePort) },
		wnpName,
		func(violation securityv1alpha1.ViolationRecord) bool {
			return isIngressClientToServerViolation(violation) &&
				violation.DenyingPolicyNamespace == namespace &&
				violation.DenyingPolicyName == wnpName
		},
		"ingress violation of the client to server flow",
	)
}

func assertEgressViolationAttributed(ctx context.Context, t *testing.T, wnpName string) {
	t.Helper()
	clientIPs := readyPodIPs(ctx, t, map[string]string{correlationAppLabel: simpleAppClientDeploymentName})
	require.Len(t, clientIPs, 1, "expected exactly one client pod")
	namespace := getNamespace(ctx)
	sendTrafficUntilViolation(
		ctx, t,
		func() {
			sendTrafficFromDeploymentToPod(ctx, simpleAppServerDeploymentName, clientIPs[0], simpleAppTCPServicePort)
		},
		wnpName,
		func(violation securityv1alpha1.ViolationRecord) bool {
			return isEgressServerToClientViolation(violation) &&
				violation.DenyingPolicyNamespace == namespace &&
				violation.DenyingPolicyName == wnpName
		},
		"egress violation of the server to client flow",
	)
}

func assertNoIngressViolation(ctx context.Context, t *testing.T, wnpName string) {
	t.Helper()
	requireNoViolationMatching(ctx, t, wnpName, isIngressClientToServerViolation,
		"the ingress violation of the client to server flow was attributed to the wrong WorkloadNetworkPolicy "+wnpName)
}

func assertNoEgressViolation(ctx context.Context, t *testing.T, wnpName string) {
	t.Helper()
	requireNoViolationMatching(ctx, t, wnpName, isEgressServerToClientViolation,
		"the egress violation of the server to client flow was attributed to the wrong WorkloadNetworkPolicy "+wnpName)
}
