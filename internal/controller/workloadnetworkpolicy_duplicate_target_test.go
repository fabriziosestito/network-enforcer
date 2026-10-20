package controller

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

func duplicateScopePolicy(name string, created time.Time) *securityv1alpha1.WorkloadNetworkPolicy {
	wnp := scopePolicy(securityv1alpha1.PolicyBackendKubernetes)
	wnp.Name = name
	wnp.UID = types.UID(name + "-uid")
	wnp.CreationTimestamp = metav1.NewTime(created)
	return wnp
}

func requireNoRenderedPolicy(
	t *testing.T,
	r *WorkloadNetworkPolicyReconciler,
	wnp *securityv1alpha1.WorkloadNetworkPolicy,
) {
	t.Helper()
	err := r.Get(t.Context(), wnp.NamespacedName(), renderedPolicyObject(wnp.Spec.Backend))
	require.True(t, apierrors.IsNotFound(err), "expected no rendered policy, got error %v", err)
}

func renderedPolicyKey(wnp *securityv1alpha1.WorkloadNetworkPolicy) client.Object {
	obj := renderedPolicyObject(wnp.Spec.Backend)
	obj.SetName(wnp.Name)
	obj.SetNamespace(wnp.Namespace)
	return obj
}

func TestDuplicateTargetThreeWay(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	alpha := duplicateScopePolicy("alpha", created)
	bravo := duplicateScopePolicy("bravo", created)
	newest := duplicateScopePolicy("newest", created.Add(2*time.Hour))
	target := scopeWorkload(alpha.Spec.TargetRef.Kind, "web", alpha.Namespace, map[string]string{"app": "web"})
	bravoRendered := newOwnedNetworkPolicy(bravo)
	r := newTestWNPreconciler(t, alpha, bravo, newest, target, bravoRendered)

	for _, wnp := range []*securityv1alpha1.WorkloadNetworkPolicy{alpha, bravo, newest} {
		condition := reconcileScopePolicy(t, r, wnp)
		require.Equal(t, metav1.ConditionFalse, condition.Status)
		require.Equal(t, reasonDuplicateTarget, condition.Reason)
		require.Contains(t, condition.Message, "alpha, bravo, newest")
		require.Contains(t, condition.Message, "only the oldest, alpha")
	}

	requireRenderedScopePolicy(t, r, alpha)
	requireNoRenderedPolicy(t, r, bravo)
	requireNoRenderedPolicy(t, r, newest)
	require.InDelta(t, 3, testutil.ToFloat64(r.duplicateTargets), 0)

	require.Equal(t, reasonDuplicateTarget, reconcileScopePolicy(t, r, bravo).Reason)
	require.InDelta(t, 3, testutil.ToFloat64(r.duplicateTargets), 0)

	require.NoError(t, r.Delete(t.Context(), alpha))
	require.NoError(t, r.Delete(t.Context(), renderedPolicyKey(alpha)))
	for _, wnp := range []*securityv1alpha1.WorkloadNetworkPolicy{bravo, newest} {
		condition := reconcileScopePolicy(t, r, wnp)
		require.Equal(t, reasonDuplicateTarget, condition.Reason)
		require.Contains(t, condition.Message, "only the oldest, bravo")
	}
	requireRenderedScopePolicy(t, r, bravo)
	requireNoRenderedPolicy(t, r, newest)
	require.InDelta(t, 3, testutil.ToFloat64(r.duplicateTargets), 0)

	require.NoError(t, r.Delete(t.Context(), bravo))
	require.NoError(t, r.Delete(t.Context(), renderedPolicyKey(bravo)))
	require.Equal(t, metav1.ConditionTrue, reconcileScopePolicy(t, r, newest).Status)
	requireRenderedScopePolicy(t, r, newest)
	require.NoError(t, r.Get(t.Context(), newest.NamespacedName(), newest))
	require.InDelta(t, 3, testutil.ToFloat64(r.duplicateTargets), 0)
}

func TestDuplicateTargetClearsAfterRemoval(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	oldest := duplicateScopePolicy("oldest", created)
	newer := duplicateScopePolicy("newer", created.Add(time.Hour))
	target := scopeWorkload(oldest.Spec.TargetRef.Kind, "web", oldest.Namespace, map[string]string{"app": "web"})
	r := newTestWNPreconciler(t, oldest, newer, target)

	require.Equal(t, reasonDuplicateTarget, reconcileScopePolicy(t, r, oldest).Reason)
	require.Equal(t, reasonDuplicateTarget, reconcileScopePolicy(t, r, newer).Reason)

	require.NoError(t, r.Delete(t.Context(), oldest))
	require.NoError(t, r.Delete(t.Context(), renderedPolicyKey(oldest)))

	require.Equal(t, metav1.ConditionTrue, reconcileScopePolicy(t, r, newer).Status)
	requireRenderedScopePolicy(t, r, newer)
	require.NoError(t, r.Get(t.Context(), newer.NamespacedName(), newer))
}

func TestDuplicateTargetPolicies(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ingress := duplicateScopePolicy("ingress", created)
	sibling := duplicateScopePolicy("sibling", created)
	egress := duplicateScopePolicy("egress", created)
	egress.Spec.Direction = networkingv1.PolicyTypeEgress

	otherNamespace := ingress.DeepCopy()
	otherNamespace.Namespace = "other"
	otherNamespace.Name = "other-namespace"

	r := newTestWNPreconciler(t, ingress, sibling, egress, otherNamespace)
	requests := r.duplicateTargetPolicies(t.Context(), ingress)
	require.ElementsMatch(t, []ctrl.Request{
		{NamespacedName: sibling.NamespacedName()},
		{NamespacedName: egress.NamespacedName()},
	}, requests)
}

func TestDuplicateTargetDirectionIsolation(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ingress := duplicateScopePolicy("ingress", created)
	egress := duplicateScopePolicy("egress", created)
	egress.Spec.Direction = networkingv1.PolicyTypeEgress
	target := scopeWorkload(ingress.Spec.TargetRef.Kind, "web", ingress.Namespace, map[string]string{"app": "web"})
	r := newTestWNPreconciler(t, ingress, egress, target)

	require.Equal(t, metav1.ConditionTrue, reconcileScopePolicy(t, r, ingress).Status)
	require.Equal(t, metav1.ConditionTrue, reconcileScopePolicy(t, r, egress).Status)
	requireRenderedScopePolicy(t, r, ingress)
	requireRenderedScopePolicy(t, r, egress)
	require.InDelta(t, 0, testutil.ToFloat64(r.duplicateTargets), 0)
}
