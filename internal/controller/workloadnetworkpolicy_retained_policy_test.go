package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apiMeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
	"github.com/kubewarden/network-enforcer/internal/workload"
)

func TestTargetMismatchPrecedesSiblingOverlap(t *testing.T) {
	t.Parallel()
	for _, backend := range []securityv1alpha1.PolicyBackend{
		securityv1alpha1.PolicyBackendKubernetes, securityv1alpha1.PolicyBackendIstio,
	} {
		t.Run(string(backend), func(t *testing.T) {
			t.Parallel()
			wnp := scopePolicy(backend)
			setPolicyAppSelector(wnp, "api")
			target := scopeWorkload(wnp.Spec.TargetRef.Kind, "web", wnp.Namespace, map[string]string{"app": "web"})
			sibling := scopeWorkload(wnp.Spec.TargetRef.Kind, "api", wnp.Namespace, map[string]string{"app": "api"})
			r := newTestWNPreconciler(t, wnp, target, sibling)
			condition := reconcileScopePolicy(t, r, wnp)
			require.Equal(t, metav1.ConditionFalse, condition.Status)
			require.Equal(t, reasonSelectorDoesNotMatchTarget, condition.Reason)
			err := r.Get(t.Context(), wnp.NamespacedName(), renderedPolicyObject(backend))
			require.True(t, apierrors.IsNotFound(err))
			require.InDelta(t, 0, testutil.ToFloat64(r.selectorOverlaps), 0)
		})
	}
}

func TestRetainedPolicyScope(t *testing.T) {
	t.Parallel()
	for _, backend := range []securityv1alpha1.PolicyBackend{
		securityv1alpha1.PolicyBackendKubernetes, securityv1alpha1.PolicyBackendIstio,
	} {
		t.Run(string(backend), func(t *testing.T) {
			t.Parallel()
			wnp := scopePolicy(backend)
			target := scopeWorkload(wnp.Spec.TargetRef.Kind, "web", wnp.Namespace, map[string]string{"app": "web"})
			requestedSibling := scopeWorkload(
				wnp.Spec.TargetRef.Kind,
				"api",
				wnp.Namespace,
				map[string]string{"app": "api"},
			)
			r := newTestWNPreconciler(t, wnp, target, requestedSibling)
			require.Equal(t, metav1.ConditionTrue, reconcileScopePolicy(t, r, wnp).Status)
			policy := renderedPolicyObject(backend)
			require.NoError(t, r.Get(t.Context(), wnp.NamespacedName(), policy))
			originalVersion := policy.GetResourceVersion()

			setPolicyAppSelector(wnp, "api")
			if wnp.Spec.IsKubernetesBackend() {
				wnp.Spec.Kubernetes.Ingress = nil
			} else {
				wnp.Spec.Istio.Rules = nil
			}
			wnp.Generation++
			require.NoError(t, r.Update(t.Context(), wnp))
			condition := reconcileScopePolicy(t, r, wnp)
			require.Equal(t, reasonSelectorDoesNotMatchTarget, condition.Reason)
			require.Contains(t, condition.Message, "retained policy")
			requireRetainedPolicyVersion(t, r, policy, originalVersion)

			sibling := scopeWorkload(
				wnp.Spec.TargetRef.Kind,
				"canary",
				wnp.Namespace,
				map[string]string{"app": "web", "tier": "canary"},
			)
			require.NoError(t, r.Create(t.Context(), sibling))
			condition = reconcileScopePolicy(t, r, wnp)
			require.Equal(t, metav1.ConditionFalse, condition.Status)
			require.Equal(t, reasonSelectorOverlapsWorkload, condition.Reason)
			require.Contains(t, condition.Message, "Deployment default/canary")
			require.Contains(t, condition.Message, "does not match")
			require.NotContains(t, condition.Message, "Deployment default/api")
			requireRetainedPolicyVersion(t, r, policy, originalVersion)
			version := wnp.ResourceVersion
			require.Equal(t, reasonSelectorOverlapsWorkload, reconcileScopePolicy(t, r, wnp).Reason)
			require.Equal(t, version, wnp.ResourceVersion)
			require.InDelta(t, 1, testutil.ToFloat64(r.selectorOverlaps), 0)

			patch := client.RawPatch(
				types.MergePatchType,
				[]byte(`{"spec":{"template":{"metadata":{"labels":{"app":"other"}}}}}`),
			)
			require.NoError(t, r.Patch(t.Context(), sibling, patch))
			require.Equal(t, reasonSelectorDoesNotMatchTarget, reconcileScopePolicy(t, r, wnp).Reason)
			requireRetainedPolicyVersion(t, r, policy, originalVersion)
			require.InDelta(t, 1, testutil.ToFloat64(r.selectorOverlaps), 0)

			setPolicyAppSelector(wnp, "web")
			wnp.Generation++
			require.NoError(t, r.Update(t.Context(), wnp))
			require.Equal(t, metav1.ConditionTrue, reconcileScopePolicy(t, r, wnp).Status)
			requireRenderedScopePolicy(t, r, wnp)
			if backend == securityv1alpha1.PolicyBackendIstio {
				var ap istiosecurityv1.AuthorizationPolicy
				require.NoError(t, r.Get(t.Context(), wnp.NamespacedName(), &ap))
				require.Empty(t, ap.Spec.GetRules())
			}
		})
	}
}

func TestRetainedPolicyScopeIgnoresForeignPolicy(t *testing.T) {
	t.Parallel()
	for _, backend := range []securityv1alpha1.PolicyBackend{
		securityv1alpha1.PolicyBackendKubernetes, securityv1alpha1.PolicyBackendIstio,
	} {
		t.Run(string(backend), func(t *testing.T) {
			t.Parallel()
			wnp := scopePolicy(backend)
			target := scopeWorkload(wnp.Spec.TargetRef.Kind, "web", wnp.Namespace, map[string]string{"app": "web"})
			r := newTestWNPreconciler(t, wnp, target)
			require.Equal(t, metav1.ConditionTrue, reconcileScopePolicy(t, r, wnp).Status)
			policy := renderedPolicyObject(backend)
			require.NoError(t, r.Get(t.Context(), wnp.NamespacedName(), policy))
			policy.SetOwnerReferences(nil)
			require.NoError(t, r.Update(t.Context(), policy))
			originalVersion := policy.GetResourceVersion()
			setPolicyAppSelector(wnp, "api")
			wnp.Generation++
			require.NoError(t, r.Update(t.Context(), wnp))
			sibling := scopeWorkload(wnp.Spec.TargetRef.Kind, "canary", wnp.Namespace, map[string]string{"app": "web"})
			require.NoError(t, r.Create(t.Context(), sibling))
			condition := reconcileScopePolicy(t, r, wnp)
			require.Equal(t, reasonSelectorDoesNotMatchTarget, condition.Reason)
			require.NotContains(t, condition.Message, "retained policy")
			requireRetainedPolicyVersion(t, r, policy, originalVersion)
			require.InDelta(t, 0, testutil.ToFloat64(r.selectorOverlaps), 0)
		})
	}
}

func TestMonitorAfterRetainedPolicyOverlap(t *testing.T) {
	t.Parallel()
	for _, backend := range []securityv1alpha1.PolicyBackend{
		securityv1alpha1.PolicyBackendKubernetes, securityv1alpha1.PolicyBackendIstio,
	} {
		t.Run(string(backend), func(t *testing.T) {
			t.Parallel()
			wnp := scopePolicy(backend)
			target := scopeWorkload(wnp.Spec.TargetRef.Kind, "web", wnp.Namespace, map[string]string{"app": "web"})
			r := newTestWNPreconciler(t, wnp, target)
			require.Equal(t, metav1.ConditionTrue, reconcileScopePolicy(t, r, wnp).Status)
			setPolicyAppSelector(wnp, "api")
			wnp.Generation++
			require.NoError(t, r.Update(t.Context(), wnp))
			sibling := scopeWorkload(wnp.Spec.TargetRef.Kind, "canary", wnp.Namespace, map[string]string{"app": "web"})
			require.NoError(t, r.Create(t.Context(), sibling))
			require.Equal(t, reasonSelectorOverlapsWorkload, reconcileScopePolicy(t, r, wnp).Reason)
			wnp.Spec.Mode = securityv1alpha1.WorkloadNetworkPolicyModeMonitor
			wnp.Generation++
			require.NoError(t, r.Update(t.Context(), wnp))
			require.Equal(t, reasonSelectorDoesNotMatchTarget, reconcileScopePolicy(t, r, wnp).Reason)
			requirePolicyMode(t, r, wnp)
		})
	}
}

func TestRetainedPolicyScopeReadFailure(t *testing.T) {
	t.Parallel()
	for _, backend := range []securityv1alpha1.PolicyBackend{
		securityv1alpha1.PolicyBackendKubernetes, securityv1alpha1.PolicyBackendIstio,
	} {
		t.Run(string(backend), func(t *testing.T) {
			t.Parallel()
			wnp := scopePolicy(backend)
			setPolicyAppSelector(wnp, "api")
			target := scopeWorkload(wnp.Spec.TargetRef.Kind, "web", wnp.Namespace, map[string]string{"app": "web"})
			r := newTestWNPreconciler(t, wnp, target)
			readErr := errors.New("policy unavailable")
			wnp.Status.Conditions = []metav1.Condition{
				{Type: conditionReady, Status: metav1.ConditionTrue, Reason: reasonSelectorScopeValid},
			}
			r.Client = fake.NewClientBuilder().WithScheme(r.Scheme).WithObjects(wnp, target).
				WithIndex(&securityv1alpha1.WorkloadNetworkPolicy{}, workload.WNPTargetIndexField, workload.IndexWNPByTarget).
				WithStatusSubresource(wnp).WithInterceptorFuncs(interceptor.Funcs{
				Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					switch obj.(type) {
					case *networkingv1.NetworkPolicy, *istiosecurityv1.AuthorizationPolicy:
						return readErr
					default:
						return c.Get(ctx, key, obj, opts...)
					}
				},
			}).Build()
			_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: wnp.NamespacedName()})
			require.ErrorIs(t, err, readErr)
			require.NoError(t, r.Get(t.Context(), wnp.NamespacedName(), wnp))
			condition := apiMeta.FindStatusCondition(wnp.Status.Conditions, conditionReady)
			require.NotNil(t, condition)
			require.Equal(t, metav1.ConditionFalse, condition.Status)
			require.Equal(t, reasonSelectorDoesNotMatchTarget, condition.Reason)
		})
	}
}

func setPolicyAppSelector(wnp *securityv1alpha1.WorkloadNetworkPolicy, app string) {
	if wnp.Spec.IsKubernetesBackend() {
		wnp.Spec.Kubernetes.PodSelector.MatchLabels["app"] = app
	} else {
		wnp.Spec.Istio.Selector.MatchLabels["app"] = app
	}
}

func requireRetainedPolicyVersion(
	t *testing.T,
	r *WorkloadNetworkPolicyReconciler,
	policy client.Object,
	version string,
) {
	t.Helper()
	require.NoError(t, r.Get(t.Context(), client.ObjectKeyFromObject(policy), policy))
	require.Equal(t, version, policy.GetResourceVersion())
}
