package controller

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apiMeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

func TestSelectorScopeWorkloadWatches(t *testing.T) {
	testEnv := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "charts", "network-enforcer", "templates", "crd")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := testEnv.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, testEnv.Stop()) })

	s := runtime.NewScheme()
	require.NoError(t, scheme.AddToScheme(s))
	require.NoError(t, securityv1alpha1.AddToScheme(s))
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: s, Metrics: metricsserver.Options{BindAddress: "0"}, HealthProbeBindAddress: "0",
		Controller: config.Controller{SkipNameValidation: new(true)},
	})
	require.NoError(t, err)
	r := &WorkloadNetworkPolicyReconciler{Client: mgr.GetClient(), Scheme: s}
	t.Cleanup(func() {
		metrics.Registry.Unregister(r.selectorOverlaps)
		metrics.Registry.Unregister(r.duplicateTargets)
	})
	require.NoError(t, SetupWNPIndexer(t.Context(), mgr))
	require.NoError(t, r.SetupWithManager(mgr))

	ctx, cancel := context.WithCancel(t.Context())
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
	apiClient, err := client.New(cfg, client.Options{Scheme: s})
	require.NoError(t, err)

	for _, kind := range []securityv1alpha1.WorkloadKind{
		securityv1alpha1.WorkloadKindDeployment, securityv1alpha1.WorkloadKindStatefulSet, securityv1alpha1.WorkloadKindDaemonSet,
	} {
		t.Run(string(kind), func(t *testing.T) {
			namespace := strings.ToLower(string(kind))
			require.NoError(t, apiClient.Create(ctx, &corev1.Namespace{Name: namespace}))
			wnp := scopePolicy(securityv1alpha1.PolicyBackendKubernetes)
			wnp.UID = ""
			wnp.Generation = 0
			wnp.Namespace = namespace
			wnp.Spec.TargetRef.Kind = kind
			require.NoError(t, apiClient.Create(ctx, wnp))
			waitForScopeCondition(t, apiClient, wnp.NamespacedName(), reasonTargetNotFound, metav1.ConditionFalse)

			target := scopeWorkload(kind, "web", namespace, map[string]string{"workload": "web", "app": "web"})
			require.NoError(t, apiClient.Create(ctx, target))
			waitForScopeCondition(t, apiClient, wnp.NamespacedName(), reasonSelectorScopeValid, metav1.ConditionTrue)

			sibling := scopeWorkload(
				kind,
				"canary",
				namespace,
				map[string]string{"workload": "canary", "app": "web", "tier": "canary"},
			)
			require.NoError(t, apiClient.Create(ctx, sibling))
			condition := waitForScopeCondition(
				t,
				apiClient,
				wnp.NamespacedName(),
				reasonSelectorOverlapsWorkload,
				metav1.ConditionFalse,
			)
			require.Contains(t, condition.Message, string(kind)+" "+namespace+"/canary")
			for _, app := range []string{"api", "web"} {
				patch := client.RawPatch(
					types.MergePatchType,
					[]byte(`{"spec":{"template":{"metadata":{"labels":{"app":"`+app+`"}}}}}`),
				)
				require.NoError(t, apiClient.Patch(ctx, sibling, patch))
				if app == "web" {
					waitForScopeCondition(
						t,
						apiClient,
						wnp.NamespacedName(),
						reasonSelectorOverlapsWorkload,
						metav1.ConditionFalse,
					)
				} else {
					waitForScopeCondition(
						t,
						apiClient,
						wnp.NamespacedName(),
						reasonSelectorScopeValid,
						metav1.ConditionTrue,
					)
				}
			}
			require.NoError(t, apiClient.Delete(ctx, sibling))
			waitForScopeCondition(t, apiClient, wnp.NamespacedName(), reasonSelectorScopeValid, metav1.ConditionTrue)
			testRetainedPolicyWorkloadWatch(t, apiClient, wnp)
			require.NoError(t, apiClient.Delete(ctx, target))
			waitForScopeCondition(t, apiClient, wnp.NamespacedName(), reasonTargetNotFound, metav1.ConditionFalse)
		})
	}
}

func testRetainedPolicyWorkloadWatch(
	t *testing.T,
	c client.Client,
	wnp *securityv1alpha1.WorkloadNetworkPolicy,
) {
	t.Helper()
	var np networkingv1.NetworkPolicy
	require.NoError(t, c.Get(t.Context(), wnp.NamespacedName(), &np))
	originalVersion := np.ResourceVersion
	patch := client.RawPatch(types.MergePatchType,
		[]byte(`{"spec":{"kubernetes":{"podSelector":{"matchLabels":{"app":"missing"}}}}}`))
	require.NoError(t, c.Patch(t.Context(), wnp, patch))
	waitForScopeCondition(t, c, wnp.NamespacedName(), reasonSelectorDoesNotMatchTarget, metav1.ConditionFalse)

	sibling := scopeWorkload(wnp.Spec.TargetRef.Kind, "retained-canary", wnp.Namespace,
		map[string]string{"workload": "retained-canary", "app": "web", "tier": "canary"})
	require.NoError(t, c.Create(t.Context(), sibling))
	condition := waitForScopeCondition(
		t,
		c,
		wnp.NamespacedName(),
		reasonSelectorOverlapsWorkload,
		metav1.ConditionFalse,
	)
	require.Contains(t, condition.Message, wnp.Namespace+"/retained-canary")
	require.Contains(t, condition.Message, "does not match")
	require.NoError(t, c.Get(t.Context(), wnp.NamespacedName(), &np))
	require.Equal(t, originalVersion, np.ResourceVersion)

	patch = client.RawPatch(types.MergePatchType,
		[]byte(`{"spec":{"template":{"metadata":{"labels":{"app":"other"}}}}}`))
	require.NoError(t, c.Patch(t.Context(), sibling, patch))
	waitForScopeCondition(t, c, wnp.NamespacedName(), reasonSelectorDoesNotMatchTarget, metav1.ConditionFalse)
	require.NoError(t, c.Delete(t.Context(), sibling))
	patch = client.RawPatch(types.MergePatchType,
		[]byte(`{"spec":{"kubernetes":{"podSelector":{"matchLabels":{"app":"web"}}}}}`))
	require.NoError(t, c.Patch(t.Context(), wnp, patch))
	waitForScopeCondition(t, c, wnp.NamespacedName(), reasonSelectorScopeValid, metav1.ConditionTrue)
}

func waitForScopeCondition(
	t *testing.T,
	c client.Client,
	key types.NamespacedName,
	reason string,
	status metav1.ConditionStatus,
) *metav1.Condition {
	t.Helper()
	var condition *metav1.Condition
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		var wnp securityv1alpha1.WorkloadNetworkPolicy
		if !assert.NoError(collect, c.Get(t.Context(), key, &wnp)) {
			return
		}
		condition = apiMeta.FindStatusCondition(wnp.Status.Conditions, conditionReady)
		if assert.NotNil(collect, condition) {
			assert.Equal(collect, reason, condition.Reason)
			assert.Equal(collect, status, condition.Status)
			assert.Equal(collect, wnp.Generation, condition.ObservedGeneration)
		}
		var np networkingv1.NetworkPolicy
		assert.NoError(collect, c.Get(t.Context(), key, &np))
	}, 10*time.Second, 50*time.Millisecond)
	return condition
}
