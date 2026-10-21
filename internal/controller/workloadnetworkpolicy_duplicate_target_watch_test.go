package controller

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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

func TestDuplicateTargetWatches(t *testing.T) {
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

	namespace := "duplicate-target"
	require.NoError(t, apiClient.Create(ctx, &corev1.Namespace{Name: namespace}))
	target := scopeWorkload(securityv1alpha1.WorkloadKindDeployment, "web", namespace,
		map[string]string{"workload": "web", "app": "web"})
	require.NoError(t, apiClient.Create(ctx, target))

	older := scopePolicy(securityv1alpha1.PolicyBackendKubernetes)
	older.Name = "dup-a"
	older.Namespace = namespace
	older.UID = ""
	older.Generation = 0
	require.NoError(t, apiClient.Create(ctx, older))
	require.Eventually(t, func() bool {
		return apiClient.Get(ctx, older.NamespacedName(), &networkingv1.NetworkPolicy{}) == nil
	}, 10*time.Second, 50*time.Millisecond)

	newer := scopePolicy(securityv1alpha1.PolicyBackendKubernetes)
	newer.Name = "dup-b"
	newer.Namespace = namespace
	newer.UID = ""
	newer.Generation = 0
	require.NoError(t, apiClient.Create(ctx, newer))

	waitForReadyCondition(t, apiClient, older.NamespacedName(), reasonDuplicateTarget, metav1.ConditionFalse)
	waitForReadyCondition(t, apiClient, newer.NamespacedName(), reasonDuplicateTarget, metav1.ConditionFalse)
	require.NoError(t, apiClient.Get(ctx, older.NamespacedName(), &networkingv1.NetworkPolicy{}))
	err = apiClient.Get(ctx, newer.NamespacedName(), &networkingv1.NetworkPolicy{})
	require.True(t, apierrors.IsNotFound(err), "expected the losing policy to render nothing, got %v", err)

	require.NoError(t, apiClient.Delete(ctx, older))
	waitForReadyCondition(t, apiClient, newer.NamespacedName(), reasonSelectorScopeValid, metav1.ConditionTrue)
	require.Eventually(t, func() bool {
		return apiClient.Get(ctx, newer.NamespacedName(), &networkingv1.NetworkPolicy{}) == nil
	}, 10*time.Second, 50*time.Millisecond)
	var surviving securityv1alpha1.WorkloadNetworkPolicy
	require.NoError(t, apiClient.Get(ctx, newer.NamespacedName(), &surviving))
}

func waitForReadyCondition(
	t *testing.T,
	c client.Client,
	key types.NamespacedName,
	reason string,
	status metav1.ConditionStatus,
) {
	t.Helper()
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		var wnp securityv1alpha1.WorkloadNetworkPolicy
		if !assert.NoError(collect, c.Get(t.Context(), key, &wnp)) {
			return
		}
		condition := apiMeta.FindStatusCondition(wnp.Status.Conditions, conditionReady)
		if assert.NotNil(collect, condition) {
			assert.Equal(collect, reason, condition.Reason)
			assert.Equal(collect, status, condition.Status)
		}
	}, 10*time.Second, 50*time.Millisecond)
}
