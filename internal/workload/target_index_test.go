package workload

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

const (
	wnpIndexWait = 10 * time.Second
	wnpIndexTick = 100 * time.Millisecond
)

func targetedWNP(
	namespace, name string,
	kind securityv1alpha1.WorkloadKind,
	target string,
	direction networkingv1.PolicyType,
) *securityv1alpha1.WorkloadNetworkPolicy {
	return &securityv1alpha1.WorkloadNetworkPolicy{
		Name:      name,
		Namespace: namespace,
		Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
			Mode: securityv1alpha1.WorkloadNetworkPolicyModeMonitor,
			PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
				Backend: securityv1alpha1.PolicyBackendKubernetes,
				Kubernetes: &networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": target}},
					PolicyTypes: []networkingv1.PolicyType{direction},
				},
			},
			WorkloadTargetingSpec: securityv1alpha1.WorkloadTargetingSpec{
				TargetRef: securityv1alpha1.WorkloadTargetRef{Kind: kind, Name: target},
				Direction: direction,
			},
		},
	}
}

func TestIndexWNPByTarget(t *testing.T) {
	t.Parallel()

	deploy := securityv1alpha1.WorkloadKindDeployment
	ingress := networkingv1.PolicyTypeIngress

	noDirection := targetedWNP(testNamespace, "no-direction", deploy, "web", ingress)
	noDirection.Spec.Direction = ""
	noKind := targetedWNP(testNamespace, "no-kind", "", "web", ingress)
	noName := targetedWNP(testNamespace, "no-name", deploy, "", ingress)

	cases := []struct {
		name string
		obj  client.Object
		want []string
	}{
		{name: "indexes kind, name and direction",
			obj: targetedWNP(testNamespace, "wnp", deploy, "web", ingress), want: []string{"Deployment/web/Ingress"}},
		{name: "missing direction is not indexed", obj: noDirection},
		{name: "missing kind is not indexed", obj: noKind},
		{name: "missing name is not indexed", obj: noName},
		{name: "non-WNP object is not indexed", obj: &corev1.Pod{}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, c.want, IndexWNPByTarget(c.obj))
		})
	}
}

// TestLookupWNPByTarget runs against a real API server and an informer cache
// with the WNPTargetIndexField index registered, as in production.
func TestLookupWNPByTarget(t *testing.T) {
	testEnv := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "charts", "network-enforcer", "templates", "crd")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := testEnv.Start()
	require.NoError(t, err, "cannot start envtest")
	t.Cleanup(func() { require.NoError(t, testEnv.Stop()) })

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, securityv1alpha1.AddToScheme(scheme))

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	require.NoError(t, mgr.GetFieldIndexer().IndexField(
		ctx, &securityv1alpha1.WorkloadNetworkPolicy{}, WNPTargetIndexField, IndexWNPByTarget))
	done := make(chan struct{})
	go func() {
		defer close(done)
		assert.NoError(t, mgr.Start(ctx))
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	require.True(t, mgr.GetCache().WaitForCacheSync(ctx))

	apiClient, err := client.New(cfg, client.Options{Scheme: scheme})
	require.NoError(t, err)

	const ns, otherNS = testNamespace, "other"
	require.NoError(t, apiClient.Create(ctx, &corev1.Namespace{Name: otherNS}))

	deploy := securityv1alpha1.WorkloadKindDeployment
	sts := securityv1alpha1.WorkloadKindStatefulSet
	ingress, egress := networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress
	objs := []*securityv1alpha1.WorkloadNetworkPolicy{
		targetedWNP(ns, "web-ingress", deploy, "web", ingress),
		targetedWNP(ns, "web-egress", deploy, "web", egress),
		targetedWNP(ns, "egress-only", deploy, "egress-only", egress),
		targetedWNP(ns, "dup-a", deploy, "dup", ingress),
		targetedWNP(ns, "dup-b", deploy, "dup", ingress),
		targetedWNP(ns, "web-sts-ingress", sts, "web", ingress),
		targetedWNP(otherNS, "other-ns-only", deploy, "other-ns-only", ingress),
	}
	for _, o := range objs {
		require.NoError(t, apiClient.Create(ctx, o))
	}

	cached := mgr.GetClient()
	require.Eventually(t, func() bool {
		var list securityv1alpha1.WorkloadNetworkPolicyList
		return cached.List(ctx, &list) == nil && len(list.Items) == len(objs)
	}, wnpIndexWait, wnpIndexTick)

	cases := []struct {
		name      string
		namespace string
		kind      securityv1alpha1.WorkloadKind
		target    string
		direction networkingv1.PolicyType
		wantName  string
		wantErr   error
	}{
		{name: "ingress lookup returns the ingress WNP", namespace: ns, kind: deploy, target: "web",
			direction: ingress, wantName: "web-ingress"},
		{name: "egress lookup returns the egress WNP", namespace: ns, kind: deploy, target: "web",
			direction: egress, wantName: "web-egress"},
		{name: "ingress lookup never returns an egress WNP", namespace: ns, kind: deploy, target: "egress-only",
			direction: ingress, wantErr: ErrTargetNotFound},
		{name: "kind is part of the key", namespace: ns, kind: sts, target: "web",
			direction: ingress, wantName: "web-sts-ingress"},
		{name: "duplicate target is an error", namespace: ns, kind: deploy, target: "dup",
			direction: ingress, wantErr: ErrDuplicateTarget},
		{name: "lookup is namespace-scoped", namespace: ns, kind: deploy, target: "other-ns-only",
			direction: ingress, wantErr: ErrTargetNotFound},
		{name: "unknown target is not found", namespace: ns, kind: deploy, target: "missing",
			direction: ingress, wantErr: ErrTargetNotFound},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wnp, lookupErr := LookupWNPByTarget(ctx, cached, c.namespace, c.kind, c.target, c.direction)
			if c.wantErr != nil {
				require.ErrorIs(t, lookupErr, c.wantErr)
				require.Nil(t, wnp)
				return
			}
			require.NoError(t, lookupErr)
			require.Equal(t, c.wantName, wnp.Name)
			require.Equal(t, c.direction, wnp.Spec.Direction)
		})
	}
}
