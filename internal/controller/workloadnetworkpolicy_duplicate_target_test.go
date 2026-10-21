package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apiMeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

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
	requireRenderedScopePolicy(t, r, bravo)
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
	require.ElementsMatch(t, []ctrl.Request{{NamespacedName: sibling.NamespacedName()}}, requests)
}

func TestDuplicateTargetConditionAppliedWhenScopeCheckFails(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	oldest := duplicateScopePolicy("oldest", created)
	newer := duplicateScopePolicy("newer", created.Add(time.Hour))
	target := scopeWorkload(oldest.Spec.TargetRef.Kind, "web", oldest.Namespace, map[string]string{"app": "web"})
	r := newTestWNPreconciler(t, oldest, newer, target)

	base, ok := r.Client.(client.WithWatch)
	require.True(t, ok)
	listErr := errors.New("deployment list unavailable")
	r.Client = interceptor.NewClient(base, interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, isDeployments := list.(*appsv1.DeploymentList); isDeployments {
				return listErr
			}
			return c.List(ctx, list, opts...)
		},
	})

	_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: oldest.NamespacedName()})
	require.ErrorIs(t, err, listErr)
	require.NoError(t, r.Get(t.Context(), oldest.NamespacedName(), oldest))
	condition := apiMeta.FindStatusCondition(oldest.Status.Conditions, conditionReady)
	require.NotNil(t, condition)
	require.Equal(t, reasonDuplicateTarget, condition.Reason)
	require.InDelta(t, 1, testutil.ToFloat64(r.duplicateTargets), 0)
}

func TestDuplicateTargetHandlerEnqueuesOldAndNewSiblings(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	oldTarget := duplicateScopePolicy("moved", created)
	newTarget := oldTarget.DeepCopy()
	newTarget.Spec.TargetRef.Name = "api"
	oldSibling := duplicateScopePolicy("old-sibling", created)
	newSibling := duplicateScopePolicy("new-sibling", created)
	newSibling.Spec.TargetRef.Name = "api"

	r := newTestWNPreconciler(t, oldSibling, newSibling)
	q := workqueue.NewTypedRateLimitingQueue(
		workqueue.DefaultTypedControllerRateLimiter[reconcile.Request](),
	)
	t.Cleanup(q.ShutDown)

	r.duplicateTargetHandler().Update(t.Context(), event.UpdateEvent{
		ObjectOld: oldTarget,
		ObjectNew: newTarget,
	}, q)

	got := map[types.NamespacedName]bool{}
	for q.Len() > 0 {
		request, shutdown := q.Get()
		require.False(t, shutdown)
		got[request.NamespacedName] = true
		q.Done(request)
	}
	require.Equal(t, map[types.NamespacedName]bool{
		oldSibling.NamespacedName(): true,
		newSibling.NamespacedName(): true,
	}, got)
}

func TestDuplicateTargetMessageBounded(t *testing.T) {
	t.Parallel()

	const policyCount = 130
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	objs := make([]client.Object, 0, policyCount)
	var first *securityv1alpha1.WorkloadNetworkPolicy
	for i := range policyCount {
		wnp := duplicateScopePolicy(
			fmt.Sprintf("policy-%03d-%s", i, strings.Repeat("a", 240)),
			created,
		)
		if i == 0 {
			first = wnp
		}
		objs = append(objs, wnp)
	}

	r := newTestWNPreconciler(t, objs...)
	conflict, conflicting, err := r.checkDuplicateTarget(t.Context(), first)
	require.NoError(t, err)
	require.True(t, conflicting)
	require.LessOrEqual(t, len(conflict.condition.Message), 32768)
	require.Contains(t, conflict.condition.Message,
		fmt.Sprintf("targeted by %d WorkloadNetworkPolicies", policyCount))
	require.Contains(t, conflict.condition.Message,
		fmt.Sprintf("and %d more", policyCount-maxDuplicateTargetNamesInMessage))
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
