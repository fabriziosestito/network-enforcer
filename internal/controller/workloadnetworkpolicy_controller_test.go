package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apiMeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

func TestWorkloadNetworkPolicyMonitorAfterTargetMismatch(t *testing.T) {
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
			originalVersion := policy.GetResourceVersion()

			if wnp.Spec.IsKubernetesBackend() {
				wnp.Spec.Kubernetes.PodSelector.MatchLabels["app"] = "missing"
			} else {
				wnp.Spec.Istio.Selector.MatchLabels["app"] = "missing"
			}
			wnp.Generation++
			require.NoError(t, r.Update(t.Context(), wnp))
			require.Equal(t, reasonSelectorDoesNotMatchTarget, reconcileScopePolicy(t, r, wnp).Reason)
			require.NoError(t, r.Get(t.Context(), wnp.NamespacedName(), policy))
			require.Equal(t, originalVersion, policy.GetResourceVersion())

			wnp.Spec.Mode = securityv1alpha1.WorkloadNetworkPolicyModeMonitor
			wnp.Generation++
			require.NoError(t, r.Update(t.Context(), wnp))
			condition := reconcileScopePolicy(t, r, wnp)
			require.Equal(t, metav1.ConditionFalse, condition.Status)
			require.Equal(t, reasonSelectorDoesNotMatchTarget, condition.Reason)
			requirePolicyMode(t, r, wnp)
			require.Equal(t, reasonSelectorDoesNotMatchTarget, reconcileScopePolicy(t, r, wnp).Reason)
			requirePolicyMode(t, r, wnp)
		})
	}
}

func TestWorkloadNetworkPolicyOwnershipConflict(t *testing.T) {
	t.Parallel()
	for _, backend := range []securityv1alpha1.PolicyBackend{
		securityv1alpha1.PolicyBackendKubernetes, securityv1alpha1.PolicyBackendIstio,
	} {
		for _, mode := range []securityv1alpha1.WorkloadNetworkPolicyMode{
			securityv1alpha1.WorkloadNetworkPolicyModeProtect, securityv1alpha1.WorkloadNetworkPolicyModeMonitor,
		} {
			t.Run(string(backend)+"/"+string(mode), func(t *testing.T) {
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

				wnp.Spec.Mode = mode
				wnp.Generation++
				require.NoError(t, r.Update(t.Context(), wnp))
				_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: wnp.NamespacedName()})
				require.ErrorContains(t, err, "not controlled by this WorkloadNetworkPolicy")
				require.NoError(t, r.Get(t.Context(), wnp.NamespacedName(), wnp))
				condition := apiMeta.FindStatusCondition(wnp.Status.Conditions, conditionReady)
				require.NotNil(t, condition)
				require.Equal(t, metav1.ConditionFalse, condition.Status)
				require.Equal(t, "PolicyOwnershipConflict", condition.Reason)
				require.Equal(t, wnp.Generation, condition.ObservedGeneration)
				require.Contains(t, condition.Message, wnp.NamespacedName().String())
				require.NoError(t, r.Get(t.Context(), wnp.NamespacedName(), policy))
				require.Equal(t, originalVersion, policy.GetResourceVersion())

				version := wnp.ResourceVersion
				_, err = r.Reconcile(t.Context(), ctrl.Request{NamespacedName: wnp.NamespacedName()})
				require.Error(t, err)
				require.NoError(t, r.Get(t.Context(), wnp.NamespacedName(), wnp))
				require.Equal(t, version, wnp.ResourceVersion)

				require.NoError(t, r.Delete(t.Context(), policy))
				require.Equal(t, metav1.ConditionTrue, reconcileScopePolicy(t, r, wnp).Status)
				requirePolicyMode(t, r, wnp)
			})
		}
	}
}

func TestWorkloadNetworkPolicyRecreationFailure(t *testing.T) {
	t.Parallel()
	for _, backend := range []securityv1alpha1.PolicyBackend{
		securityv1alpha1.PolicyBackendKubernetes, securityv1alpha1.PolicyBackendIstio,
	} {
		for _, tc := range []struct {
			name     string
			patchErr error
		}{
			{name: "status succeeds"},
			{name: "status fails", patchErr: errors.New("status unavailable")},
		} {
			t.Run(string(backend)+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				wnp := scopePolicy(backend)
				target := scopeWorkload(wnp.Spec.TargetRef.Kind, "web", wnp.Namespace, map[string]string{"app": "web"})
				r := newTestWNPreconciler(t, wnp, target)
				require.Equal(t, metav1.ConditionTrue, reconcileScopePolicy(t, r, wnp).Status)
				generation := wnp.Generation
				policy := renderedPolicyObject(backend)
				require.NoError(t, r.Get(t.Context(), wnp.NamespacedName(), policy))
				require.NoError(t, r.Delete(t.Context(), policy))

				baseClient, ok := r.Client.(client.WithWatch)
				require.True(t, ok)
				backendErr := errors.New("policy creation denied by quota")
				patchErr := tc.patchErr
				r.Client = interceptor.NewClient(baseClient, interceptor.Funcs{
					Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
						return backendErr
					},
					SubResourcePatch: func(ctx context.Context, c client.Client, subresource string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
						if patchErr != nil {
							return patchErr
						}
						return c.SubResource(subresource).Patch(ctx, obj, patch, opts...)
					},
				})
				request := ctrl.Request{NamespacedName: wnp.NamespacedName()}
				_, err := r.Reconcile(t.Context(), request)
				require.ErrorIs(t, err, backendErr)
				if tc.patchErr != nil {
					require.ErrorIs(t, err, tc.patchErr)
					patchErr = nil
					_, err = r.Reconcile(t.Context(), request)
					require.ErrorIs(t, err, backendErr)
				}
				require.NoError(t, r.Get(t.Context(), wnp.NamespacedName(), wnp))
				condition := apiMeta.FindStatusCondition(wnp.Status.Conditions, conditionReady)
				require.NotNil(t, condition)
				require.Equal(t, metav1.ConditionFalse, condition.Status)
				require.Equal(t, "PolicyReconciliationFailed", condition.Reason)
				require.Equal(t, generation, condition.ObservedGeneration)
				require.Contains(t, condition.Message, backendErr.Error())
				require.True(t, apierrors.IsNotFound(r.Get(t.Context(), wnp.NamespacedName(), policy)))

				version := wnp.ResourceVersion
				_, err = r.Reconcile(t.Context(), request)
				require.ErrorIs(t, err, backendErr)
				require.NoError(t, r.Get(t.Context(), wnp.NamespacedName(), wnp))
				require.Equal(t, version, wnp.ResourceVersion)

				r.Client = baseClient
				require.Equal(t, metav1.ConditionTrue, reconcileScopePolicy(t, r, wnp).Status)
				require.Equal(t, generation, wnp.Generation)
				requireRenderedScopePolicy(t, r, wnp)
			})
		}
	}
}

func renderedPolicyObject(backend securityv1alpha1.PolicyBackend) client.Object {
	if backend == securityv1alpha1.PolicyBackendKubernetes {
		return &networkingv1.NetworkPolicy{}
	}
	return &istiosecurityv1.AuthorizationPolicy{}
}

func requirePolicyMode(
	t *testing.T,
	r *WorkloadNetworkPolicyReconciler,
	wnp *securityv1alpha1.WorkloadNetworkPolicy,
) {
	t.Helper()
	if wnp.Spec.IsKubernetesBackend() && wnp.Spec.Mode == securityv1alpha1.WorkloadNetworkPolicyModeMonitor {
		err := r.Get(t.Context(), wnp.NamespacedName(), &networkingv1.NetworkPolicy{})
		require.True(t, apierrors.IsNotFound(err))
		return
	}
	requireRenderedScopePolicy(t, r, wnp)
	if wnp.Spec.Backend == securityv1alpha1.PolicyBackendIstio {
		var ap istiosecurityv1.AuthorizationPolicy
		require.NoError(t, r.Get(t.Context(), wnp.NamespacedName(), &ap))
		if wnp.Spec.Mode == securityv1alpha1.WorkloadNetworkPolicyModeMonitor {
			require.Equal(t, "true", ap.Annotations[istioDryRunAnnotationKey])
		} else {
			require.NotContains(t, ap.Annotations, istioDryRunAnnotationKey)
		}
	}
}
