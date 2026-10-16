package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apiMeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

func scopePolicy(backend securityv1alpha1.PolicyBackend) *securityv1alpha1.WorkloadNetworkPolicy {
	wnp := createWorkloadNetworkPolicy(securityv1alpha1.WorkloadNetworkPolicyModeProtect)
	if backend == securityv1alpha1.PolicyBackendIstio {
		wnp = createIstioWorkloadNetworkPolicy(securityv1alpha1.WorkloadNetworkPolicyModeProtect)
	}
	wnp.Generation = 1
	wnp.Spec.WorkloadTargetingSpec = securityv1alpha1.WorkloadTargetingSpec{
		TargetRef: securityv1alpha1.WorkloadTargetRef{Kind: securityv1alpha1.WorkloadKindDeployment, Name: "web"},
		Direction: networkingv1.PolicyTypeIngress,
	}
	return wnp
}

func scopeWorkload(
	kind securityv1alpha1.WorkloadKind,
	name, namespace string,
	podLabels map[string]string,
) client.Object {
	template := corev1.PodTemplateSpec{
		Labels: podLabels,
		Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "web", Image: "nginx"}}},
	}
	selector := &metav1.LabelSelector{MatchLabels: map[string]string{"workload": name}}
	if kind == securityv1alpha1.WorkloadKindDeployment {
		return &appsv1.Deployment{Name: name, Namespace: namespace,
			Spec: appsv1.DeploymentSpec{Selector: selector, Template: template}}
	}
	if kind == securityv1alpha1.WorkloadKindStatefulSet {
		return &appsv1.StatefulSet{Name: name, Namespace: namespace,
			Spec: appsv1.StatefulSetSpec{Selector: selector, Template: template, ServiceName: name}}
	}
	return &appsv1.DaemonSet{Name: name, Namespace: namespace,
		Spec: appsv1.DaemonSetSpec{Selector: selector, Template: template}}
}

func reconcileScopePolicy(
	t *testing.T,
	r *WorkloadNetworkPolicyReconciler,
	wnp *securityv1alpha1.WorkloadNetworkPolicy,
) *metav1.Condition {
	t.Helper()
	_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: wnp.NamespacedName()})
	require.NoError(t, err)
	require.NoError(t, r.Get(t.Context(), wnp.NamespacedName(), wnp))
	condition := apiMeta.FindStatusCondition(wnp.Status.Conditions, conditionReady)
	require.NotNil(t, condition)
	require.Equal(t, wnp.Generation, condition.ObservedGeneration)
	return condition
}

func requireRenderedScopePolicy(
	t *testing.T,
	r *WorkloadNetworkPolicyReconciler,
	wnp *securityv1alpha1.WorkloadNetworkPolicy,
) {
	t.Helper()
	if wnp.Spec.IsKubernetesBackend() {
		var np networkingv1.NetworkPolicy
		require.NoError(t, r.Get(t.Context(), wnp.NamespacedName(), &np))
		require.Equal(t, *wnp.Spec.Kubernetes, np.Spec)
		require.True(t, metav1.IsControlledBy(&np, wnp))
	} else {
		var ap istiosecurityv1.AuthorizationPolicy
		require.NoError(t, r.Get(t.Context(), wnp.NamespacedName(), &ap))
		require.Equal(t, wnp.Spec.Istio.Selector.MatchLabels, ap.Spec.GetSelector().GetMatchLabels())
		require.True(t, metav1.IsControlledBy(&ap, wnp))
	}
}

func TestSelectorScopePartialOverlap(t *testing.T) {
	t.Parallel()
	for _, backend := range []securityv1alpha1.PolicyBackend{
		securityv1alpha1.PolicyBackendKubernetes, securityv1alpha1.PolicyBackendIstio,
	} {
		for _, kind := range []securityv1alpha1.WorkloadKind{
			securityv1alpha1.WorkloadKindDeployment, securityv1alpha1.WorkloadKindStatefulSet, securityv1alpha1.WorkloadKindDaemonSet,
		} {
			t.Run(string(backend)+"/"+string(kind), func(t *testing.T) {
				t.Parallel()
				wnp := scopePolicy(backend)
				target := scopeWorkload(wnp.Spec.TargetRef.Kind, "web", wnp.Namespace, map[string]string{"app": "web"})
				sibling := scopeWorkload(
					kind,
					"canary",
					wnp.Namespace,
					map[string]string{"app": "web", "tier": "canary"},
				)
				r := newTestWNPreconciler(t, wnp, target, sibling)

				condition := reconcileScopePolicy(t, r, wnp)
				require.Equal(t, metav1.ConditionFalse, condition.Status)
				require.Equal(t, reasonSelectorOverlapsWorkload, condition.Reason)
				require.Contains(t, condition.Message, string(kind)+" default/canary")
				requireRenderedScopePolicy(t, r, wnp)
				require.InDelta(t, 1, testutil.ToFloat64(r.selectorOverlaps), 0)

				version := wnp.ResourceVersion
				transition := condition.LastTransitionTime
				condition = reconcileScopePolicy(t, r, wnp)
				require.Equal(t, version, wnp.ResourceVersion)
				require.Equal(t, transition, condition.LastTransitionTime)
				require.InDelta(t, 1, testutil.ToFloat64(r.selectorOverlaps), 0)
			})
		}
	}
}

func TestSelectorScopeMatching(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		selector metav1.LabelSelector
		labels   map[string]string
		overlap  bool
	}{
		{name: "empty selector", selector: metav1.LabelSelector{}, overlap: true},
		{name: "partial overlap", selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			labels: map[string]string{"app": "web", "tier": "canary"}, overlap: true},
		{name: "narrow selector", selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web", "tier": "stable"}},
			labels: map[string]string{"app": "web", "tier": "canary"}},
		{name: "In", selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: "app", Operator: metav1.LabelSelectorOpIn, Values: []string{"web", "api"}},
		}}, labels: map[string]string{"app": "api"}, overlap: true},
		{name: "NotIn", selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: "app", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"db"}},
		}}, labels: map[string]string{"app": "db"}},
		{name: "Exists", selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: "app", Operator: metav1.LabelSelectorOpExists},
		}}, labels: map[string]string{"app": "api"}, overlap: true},
		{name: "DoesNotExist", selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: "excluded", Operator: metav1.LabelSelectorOpDoesNotExist},
		}}, overlap: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			wnp := scopePolicy(securityv1alpha1.PolicyBackendKubernetes)
			wnp.Spec.Kubernetes.PodSelector = tc.selector
			target := scopeWorkload(
				wnp.Spec.TargetRef.Kind,
				"web",
				wnp.Namespace,
				map[string]string{"app": "web", "tier": "stable"},
			)
			sibling := scopeWorkload(securityv1alpha1.WorkloadKindDeployment, "canary", wnp.Namespace, tc.labels)
			r := newTestWNPreconciler(t, wnp, target, sibling)
			condition := reconcileScopePolicy(t, r, wnp)
			if tc.overlap {
				require.Equal(t, reasonSelectorOverlapsWorkload, condition.Reason)
			} else {
				require.Equal(t, metav1.ConditionTrue, condition.Status)
			}
			requireRenderedScopePolicy(t, r, wnp)
		})
	}
}

func TestSelectorScopeUsesRenderedIstioSelector(t *testing.T) {
	t.Parallel()
	for _, matchLabels := range []map[string]string{{"app": "web"}, nil} {
		wnp := scopePolicy(securityv1alpha1.PolicyBackendIstio)
		wnp.Spec.Istio.Selector = metav1.LabelSelector{
			MatchLabels: matchLabels,
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"stable"}},
			},
		}
		target := scopeWorkload(wnp.Spec.TargetRef.Kind, "web", wnp.Namespace,
			map[string]string{"app": "web", "tier": "stable"})
		sibling := scopeWorkload(securityv1alpha1.WorkloadKindDeployment, "canary", wnp.Namespace,
			map[string]string{"app": "web", "tier": "canary"})
		r := newTestWNPreconciler(t, wnp, target, sibling)
		condition := reconcileScopePolicy(t, r, wnp)
		require.Equal(t, reasonSelectorOverlapsWorkload, condition.Reason)
		var ap istiosecurityv1.AuthorizationPolicy
		require.NoError(t, r.Get(t.Context(), wnp.NamespacedName(), &ap))
		require.Len(t, ap.Spec.GetSelector().GetMatchLabels(), len(matchLabels))
		for key, value := range matchLabels {
			require.Equal(t, value, ap.Spec.GetSelector().GetMatchLabels()[key])
		}
		require.NotEmpty(t, wnp.Spec.Istio.Selector.MatchExpressions)
	}
}

func TestSelectorScopeTargetIdentity(t *testing.T) {
	t.Parallel()
	for _, kind := range []securityv1alpha1.WorkloadKind{
		securityv1alpha1.WorkloadKindDeployment, securityv1alpha1.WorkloadKindStatefulSet, securityv1alpha1.WorkloadKindDaemonSet,
	} {
		t.Run(string(kind), func(t *testing.T) {
			t.Parallel()
			wnp := scopePolicy(securityv1alpha1.PolicyBackendKubernetes)
			wnp.Spec.TargetRef.Kind = kind
			target := scopeWorkload(kind, "web", wnp.Namespace, map[string]string{"app": "web"})
			otherNamespace := scopeWorkload(kind, "canary", "other", map[string]string{"app": "web"})
			r := newTestWNPreconciler(t, wnp, target, otherNamespace)
			require.Equal(t, metav1.ConditionTrue, reconcileScopePolicy(t, r, wnp).Status)
			otherKind := securityv1alpha1.WorkloadKindDeployment
			if kind == otherKind {
				otherKind = securityv1alpha1.WorkloadKindStatefulSet
			}
			require.NoError(
				t,
				r.Create(t.Context(), scopeWorkload(otherKind, "web", wnp.Namespace, map[string]string{"app": "web"})),
			)
			condition := reconcileScopePolicy(t, r, wnp)
			require.Equal(t, reasonSelectorOverlapsWorkload, condition.Reason)
			require.Contains(t, condition.Message, string(otherKind)+" default/web")
		})
	}
}

func TestSelectorScopeTargetLifecycle(t *testing.T) {
	t.Parallel()
	for _, backend := range []securityv1alpha1.PolicyBackend{
		securityv1alpha1.PolicyBackendKubernetes, securityv1alpha1.PolicyBackendIstio,
	} {
		t.Run(string(backend), func(t *testing.T) {
			t.Parallel()
			wnp := scopePolicy(backend)
			wnp.Status.ViolationCount = 7
			wnp.Status.Conditions = []metav1.Condition{
				{Type: "Other", Status: metav1.ConditionTrue, Reason: "Unchanged"},
			}
			r := newTestWNPreconciler(t, wnp)
			condition := reconcileScopePolicy(t, r, wnp)
			require.Equal(t, metav1.ConditionFalse, condition.Status)
			require.Equal(t, reasonTargetNotFound, condition.Reason)
			require.Contains(t, condition.Message, "Deployment default/web")
			requireRenderedScopePolicy(t, r, wnp)

			target := scopeWorkload(wnp.Spec.TargetRef.Kind, "web", wnp.Namespace, map[string]string{"app": "web"})
			require.NoError(t, r.Create(t.Context(), target))
			require.Equal(t, metav1.ConditionTrue, reconcileScopePolicy(t, r, wnp).Status)
			sibling := scopeWorkload(
				securityv1alpha1.WorkloadKindDeployment,
				"canary",
				wnp.Namespace,
				map[string]string{"app": "web"},
			)
			require.NoError(t, r.Create(t.Context(), sibling))
			require.Equal(t, reasonSelectorOverlapsWorkload, reconcileScopePolicy(t, r, wnp).Reason)
			require.NoError(t, r.Delete(t.Context(), target))
			require.Equal(t, reasonSelectorOverlapsWorkload, reconcileScopePolicy(t, r, wnp).Reason)
			require.NoError(t, r.Delete(t.Context(), sibling))
			require.Equal(t, reasonTargetNotFound, reconcileScopePolicy(t, r, wnp).Reason)
			requireRenderedScopePolicy(t, r, wnp)
			require.EqualValues(t, 7, wnp.Status.ViolationCount)
			require.Equal(t, "Unchanged", apiMeta.FindStatusCondition(wnp.Status.Conditions, "Other").Reason)
		})
	}
}

func TestSelectorScopeRelabel(t *testing.T) {
	t.Parallel()
	wnp := scopePolicy(securityv1alpha1.PolicyBackendKubernetes)
	target := scopeWorkload(wnp.Spec.TargetRef.Kind, "web", wnp.Namespace, map[string]string{"app": "web"})
	sibling := &appsv1.Deployment{
		Name:      "canary",
		Namespace: wnp.Namespace,
		Labels:    map[string]string{"app": "web"},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "api"}}},
		},
	}
	r := newTestWNPreconciler(t, wnp, target, sibling)
	require.Equal(t, metav1.ConditionTrue, reconcileScopePolicy(t, r, wnp).Status)
	for _, app := range []string{"web", "api", "web"} {
		require.NoError(t, r.Get(t.Context(), client.ObjectKeyFromObject(sibling), sibling))
		sibling.Spec.Template.Labels["app"] = app
		require.NoError(t, r.Update(t.Context(), sibling))
		condition := reconcileScopePolicy(t, r, wnp)
		if app == "web" {
			require.Equal(t, reasonSelectorOverlapsWorkload, condition.Reason)
		} else {
			require.Equal(t, metav1.ConditionTrue, condition.Status)
		}
		requireRenderedScopePolicy(t, r, wnp)
	}
	require.InDelta(t, 2, testutil.ToFloat64(r.selectorOverlaps), 0)
	wnp.Generation++
	require.NoError(t, r.Update(t.Context(), wnp))
	require.Equal(t, wnp.Generation, reconcileScopePolicy(t, r, wnp).ObservedGeneration)
}

func TestSelectorScopeTargetMismatch(t *testing.T) {
	t.Parallel()
	wnp := scopePolicy(securityv1alpha1.PolicyBackendKubernetes)
	target := scopeWorkload(wnp.Spec.TargetRef.Kind, "web", wnp.Namespace, map[string]string{"app": "api"})
	r := newTestWNPreconciler(t, wnp, target)
	condition := reconcileScopePolicy(t, r, wnp)
	require.Equal(t, metav1.ConditionFalse, condition.Status)
	require.Equal(t, reasonSelectorDoesNotMatchTarget, condition.Reason)
	var policies networkingv1.NetworkPolicyList
	require.NoError(t, r.List(t.Context(), &policies))
	require.Empty(t, policies.Items)
}

func TestSelectorScopeListFailure(t *testing.T) {
	t.Parallel()
	wnp := scopePolicy(securityv1alpha1.PolicyBackendKubernetes)
	r := newTestWNPreconciler(t, wnp)
	listErr := errors.New("list unavailable")
	r.Client = fake.NewClientBuilder().WithScheme(r.Scheme).WithObjects(wnp).
		WithStatusSubresource(wnp).WithInterceptorFuncs(interceptor.Funcs{
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
			return listErr
		},
	}).Build()
	_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: wnp.NamespacedName()})
	require.ErrorIs(t, err, listErr)
	require.NoError(t, r.Get(t.Context(), wnp.NamespacedName(), wnp))
	require.Empty(t, wnp.Status.Conditions)
}

func TestSelectorScopeStatusConflict(t *testing.T) {
	t.Parallel()
	wnp := scopePolicy(securityv1alpha1.PolicyBackendKubernetes)
	sibling := scopeWorkload(
		securityv1alpha1.WorkloadKindDeployment,
		"canary",
		wnp.Namespace,
		map[string]string{"app": "web"},
	)
	r := newTestWNPreconciler(t, wnp, sibling)
	require.NoError(t, r.Get(t.Context(), wnp.NamespacedName(), wnp))
	stale := wnp.DeepCopy()
	wnp.Status.Conditions = []metav1.Condition{{Type: "Other", Status: metav1.ConditionTrue, Reason: "Unchanged"}}
	require.NoError(t, r.Status().Update(t.Context(), wnp))
	condition, err := r.checkSelectorScope(t.Context(), stale)
	require.NoError(t, err)
	require.True(t, apierrors.IsConflict(r.updateReadyCondition(t.Context(), stale, condition)))
	require.InDelta(t, 0, testutil.ToFloat64(r.selectorOverlaps), 0)
	require.Equal(t, reasonSelectorOverlapsWorkload, reconcileScopePolicy(t, r, wnp).Reason)
	require.Equal(t, "Unchanged", apiMeta.FindStatusCondition(wnp.Status.Conditions, "Other").Reason)
	require.InDelta(t, 1, testutil.ToFloat64(r.selectorOverlaps), 0)
}

func TestPoliciesForWorkload(t *testing.T) {
	t.Parallel()
	wnp := scopePolicy(securityv1alpha1.PolicyBackendKubernetes)
	otherPolicy := wnp.DeepCopy()
	otherPolicy.Name = "another-target"
	otherPolicy.Spec.TargetRef.Name = "another-target"
	otherNamespace := wnp.DeepCopy()
	otherNamespace.Namespace = "other"
	r := newTestWNPreconciler(t, wnp, otherPolicy, otherNamespace)
	requests := r.policiesForWorkload(t.Context(), &appsv1.Deployment{Name: "canary", Namespace: wnp.Namespace})
	require.ElementsMatch(t, []ctrl.Request{
		{NamespacedName: wnp.NamespacedName()}, {NamespacedName: otherPolicy.NamespacedName()},
	}, requests)
}
