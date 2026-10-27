package controller

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

func scopeOwner(kind, name string, uid types.UID) metav1.OwnerReference {
	version := appsv1.SchemeGroupVersion.String()
	if kind == "Job" {
		version = "batch/v1"
	}
	return metav1.OwnerReference{
		APIVersion: version, Kind: kind, Name: name, UID: uid, Controller: new(true),
	}
}

func scopePod(namespace string, owner *metav1.OwnerReference) *corev1.Pod {
	pod := &corev1.Pod{
		Name: "selected-pod", Namespace: namespace, Labels: map[string]string{"app": "web"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "web", Image: "nginx"}}},
	}
	if owner != nil {
		pod.OwnerReferences = []metav1.OwnerReference{*owner}
	}
	return pod
}

type podScopeCase struct {
	name       string
	targetKind securityv1alpha1.WorkloadKind
	owner      *metav1.OwnerReference
	rsOwner    *metav1.OwnerReference
	rsUID      types.UID
	namespace  string
	podApp     string
	expression bool
	monitor    bool
	sibling    bool
	overlap    bool
	wantOwner  string
}

func podScopeCases() []podScopeCase {
	return []podScopeCase{
		{name: "standalone", overlap: true},
		{name: "Job in protect mode", owner: new(scopeOwner("Job", "batch", "job")),
			overlap: true, wantOwner: "Job default/batch"},
		{name: "Job in monitor mode", owner: new(scopeOwner("Job", "batch", "job")),
			monitor: true, overlap: true, wantOwner: "Job default/batch"},
		{name: "overlapping workload takes precedence", owner: new(scopeOwner("Job", "batch", "job")),
			sibling: true, overlap: true},
		{name: "target StatefulSet", targetKind: securityv1alpha1.WorkloadKindStatefulSet,
			owner: new(scopeOwner("StatefulSet", "web", "target"))},
		{name: "target DaemonSet", targetKind: securityv1alpha1.WorkloadKindDaemonSet,
			owner: new(scopeOwner("DaemonSet", "web", "target"))},
		{name: "target Deployment", owner: new(scopeOwner("ReplicaSet", "arbitrary-name", "rs")),
			rsOwner: new(scopeOwner("Deployment", "web", "target")), rsUID: "rs"},
		{name: "unrelated Deployment", owner: new(scopeOwner("ReplicaSet", "arbitrary-name", "rs")),
			rsOwner: new(scopeOwner("Deployment", "other", "other")), rsUID: "rs", overlap: true,
			wantOwner: "Deployment default/other"},
		{name: "missing ReplicaSet", owner: new(scopeOwner("ReplicaSet", "web-fakehash", "rs")), overlap: true,
			wantOwner: "ReplicaSet default/web-fakehash"},
		{name: "standalone ReplicaSet", owner: new(scopeOwner("ReplicaSet", "arbitrary-name", "rs")),
			rsUID: "rs", overlap: true, wantOwner: "ReplicaSet default/arbitrary-name"},
		{name: "replaced ReplicaSet", owner: new(scopeOwner("ReplicaSet", "arbitrary-name", "old-rs")),
			rsOwner: new(scopeOwner("Deployment", "web", "target")), rsUID: "rs", overlap: true,
			wantOwner: "ReplicaSet default/arbitrary-name"},
		{name: "replaced target", targetKind: securityv1alpha1.WorkloadKindStatefulSet,
			owner: new(scopeOwner("StatefulSet", "web", "old-target")), overlap: true,
			wantOwner: "StatefulSet default/web"},
		{name: "replaced Deployment", owner: new(scopeOwner("ReplicaSet", "arbitrary-name", "rs")),
			rsOwner: new(scopeOwner("Deployment", "web", "old-target")), rsUID: "rs", overlap: true,
			wantOwner: "Deployment default/web"},
		{name: "other namespace", namespace: "other"},
		{name: "nonmatching labels", podApp: "api"},
		{name: "matching expression", podApp: "api", expression: true, overlap: true},
		{name: "noncontroller reference", targetKind: securityv1alpha1.WorkloadKindStatefulSet,
			owner: &metav1.OwnerReference{
				APIVersion: "apps/v1", Kind: "StatefulSet", Name: "web", UID: "target",
			}, overlap: true},
		{name: "wrong API group", targetKind: securityv1alpha1.WorkloadKindStatefulSet,
			owner: &metav1.OwnerReference{
				APIVersion: "example.com/v1", Kind: "StatefulSet", Name: "web",
				UID: "target", Controller: new(true),
			}, overlap: true, wantOwner: "StatefulSet default/web"},
	}
}

func TestSelectorScopePods(t *testing.T) {
	t.Parallel()
	for _, backend := range []securityv1alpha1.PolicyBackend{
		securityv1alpha1.PolicyBackendKubernetes, securityv1alpha1.PolicyBackendIstio,
	} {
		for _, tc := range podScopeCases() {
			if tc.expression && backend == securityv1alpha1.PolicyBackendIstio {
				continue
			}
			t.Run(string(backend)+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				runPodScopeCase(t, backend, tc)
			})
		}
	}
}

func runPodScopeCase(t *testing.T, backend securityv1alpha1.PolicyBackend, tc podScopeCase) {
	t.Helper()
	wnp := podScopePolicy(backend, tc)
	r := newTestWNPreconciler(t, podScopeObjects(wnp, tc)...)
	require.Equal(t, metav1.ConditionTrue, reconcileScopePolicy(t, r, wnp).Status)
	if tc.monitor {
		wnp.Spec.Mode = securityv1alpha1.WorkloadNetworkPolicyModeMonitor
		require.NoError(t, r.Update(t.Context(), wnp))
	}
	require.NoError(t, r.Create(t.Context(), podScopePod(wnp, tc)))
	if tc.sibling {
		sibling := scopeWorkload(wnp.Spec.TargetRef.Kind, "other", wnp.Namespace, map[string]string{"app": "web"})
		require.NoError(t, r.Create(t.Context(), sibling))
	}
	requirePodScopeCondition(t, wnp, tc, reconcileScopePolicy(t, r, wnp))
	requirePolicyMode(t, r, wnp)
	if !tc.monitor {
		requireRenderedScopePolicy(t, r, wnp)
	}
}

func podScopePolicy(
	backend securityv1alpha1.PolicyBackend,
	tc podScopeCase,
) *securityv1alpha1.WorkloadNetworkPolicy {
	wnp := scopePolicy(backend)
	if tc.targetKind != "" {
		wnp.Spec.TargetRef.Kind = tc.targetKind
	}
	if backend == securityv1alpha1.PolicyBackendIstio {
		// The scope check drops Istio expressions; otherwise this one would exclude the Pod.
		wnp.Spec.Istio.Selector.MatchExpressions = []metav1.LabelSelectorRequirement{
			{Key: "app", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"web"}},
		}
	}
	if tc.expression {
		wnp.Spec.Kubernetes.PodSelector = metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "app", Operator: metav1.LabelSelectorOpExists},
			},
		}
	}
	return wnp
}

func podScopeObjects(wnp *securityv1alpha1.WorkloadNetworkPolicy, tc podScopeCase) []client.Object {
	target := scopeWorkload(wnp.Spec.TargetRef.Kind, "web", wnp.Namespace, map[string]string{"app": "web"})
	target.SetUID("target")
	objects := []client.Object{wnp, target}
	if tc.rsUID != "" {
		rs := &appsv1.ReplicaSet{Name: "arbitrary-name", Namespace: wnp.Namespace, UID: tc.rsUID}
		if tc.rsOwner != nil {
			rs.OwnerReferences = []metav1.OwnerReference{*tc.rsOwner}
		}
		objects = append(objects, rs)
	}
	return objects
}

func podScopePod(wnp *securityv1alpha1.WorkloadNetworkPolicy, tc podScopeCase) *corev1.Pod {
	pod := scopePod(wnp.Namespace, tc.owner)
	pod.Labels[appsv1.DefaultDeploymentUniqueLabelKey] = "fakehash"
	if tc.namespace != "" {
		pod.Namespace = tc.namespace
	}
	if tc.podApp != "" {
		pod.Labels["app"] = tc.podApp
	}
	return pod
}

func requirePodScopeCondition(
	t *testing.T,
	wnp *securityv1alpha1.WorkloadNetworkPolicy,
	tc podScopeCase,
	condition *metav1.Condition,
) {
	t.Helper()
	if !tc.overlap {
		require.Equal(t, metav1.ConditionTrue, condition.Status)
		return
	}
	require.Equal(t, metav1.ConditionFalse, condition.Status)
	require.Equal(t, reasonSelectorOverlapsWorkload, condition.Reason)
	switch {
	case tc.sibling:
		require.Contains(t, condition.Message, "workload "+string(wnp.Spec.TargetRef.Kind)+" default/other")
	case tc.wantOwner != "":
		require.Contains(t, condition.Message, "Pod default/selected-pod (owner: "+tc.wantOwner+")")
	default:
		require.Contains(t, condition.Message, "Pod default/selected-pod")
		require.NotContains(t, condition.Message, "(owner:")
	}
}

func TestSelectorScopeMissingTargetPods(t *testing.T) {
	t.Parallel()
	for _, backend := range []securityv1alpha1.PolicyBackend{
		securityv1alpha1.PolicyBackendKubernetes, securityv1alpha1.PolicyBackendIstio,
	} {
		t.Run(string(backend), func(t *testing.T) {
			t.Parallel()
			wnp := scopePolicy(backend)
			pod := scopePod(wnp.Namespace, new(scopeOwner("ReplicaSet", "web-rs", "rs")))
			rs := &appsv1.ReplicaSet{Name: "web-rs", Namespace: wnp.Namespace, UID: "rs",
				OwnerReferences: []metav1.OwnerReference{scopeOwner("Deployment", "web", "deleted")}}
			r := newTestWNPreconciler(t, wnp, pod, rs)
			require.Equal(t, reasonTargetNotFound, reconcileScopePolicy(t, r, wnp).Reason)

			standalone := scopePod(wnp.Namespace, nil)
			standalone.Name = "standalone"
			require.NoError(t, r.Create(t.Context(), standalone))
			condition := reconcileScopePolicy(t, r, wnp)
			require.Equal(t, reasonSelectorOverlapsWorkload, condition.Reason)
			require.Contains(t, condition.Message, "Pod default/standalone")
		})
	}
}

func TestRetainedPolicyPodScope(t *testing.T) {
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
			setPolicyAppSelector(wnp, "api")
			wnp.Generation++
			require.NoError(t, r.Update(t.Context(), wnp))
			requestedPod := scopePod(wnp.Namespace, nil)
			requestedPod.Name = "requested-selector-only"
			requestedPod.Labels["app"] = "api"
			require.NoError(t, r.Create(t.Context(), requestedPod))
			require.Equal(t, reasonSelectorDoesNotMatchTarget, reconcileScopePolicy(t, r, wnp).Reason)

			pod := scopePod(wnp.Namespace, new(scopeOwner("Job", "batch", "job")))
			require.NoError(t, r.Create(t.Context(), pod))
			condition := reconcileScopePolicy(t, r, wnp)
			require.Equal(t, reasonSelectorOverlapsWorkload, condition.Reason)
			require.Contains(t, condition.Message, "Retained policy selector")
			require.Contains(t, condition.Message, "Pod default/selected-pod")
			require.Contains(t, condition.Message, "Job default/batch")
			require.NotContains(t, condition.Message, requestedPod.Name)
			require.Equal(t, reasonSelectorOverlapsWorkload, reconcileScopePolicy(t, r, wnp).Reason)
			require.InDelta(t, 1, testutil.ToFloat64(r.selectorOverlaps), 0)
			requireRetainedPolicyVersion(t, r, policy, originalVersion)

			require.NoError(t, r.Delete(t.Context(), pod))
			require.Equal(t, reasonSelectorDoesNotMatchTarget, reconcileScopePolicy(t, r, wnp).Reason)
			pod.ResourceVersion = ""
			require.NoError(t, r.Create(t.Context(), pod))
			require.Equal(t, reasonSelectorOverlapsWorkload, reconcileScopePolicy(t, r, wnp).Reason)
			require.InDelta(t, 2, testutil.ToFloat64(r.selectorOverlaps), 0)
			requireRetainedPolicyVersion(t, r, policy, originalVersion)

			wnp.Spec.Mode = securityv1alpha1.WorkloadNetworkPolicyModeMonitor
			require.NoError(t, r.Update(t.Context(), wnp))
			require.Equal(t, reasonSelectorDoesNotMatchTarget, reconcileScopePolicy(t, r, wnp).Reason)
			requirePolicyMode(t, r, wnp)
		})
	}
}

func TestSelectorScopeMetadataChanges(t *testing.T) {
	t.Parallel()
	predicate := selectorScopeMetadataChanges()
	original := scopePod("default", nil)
	require.True(t, predicate.Create(event.CreateEvent{Object: original}))
	require.True(t, predicate.Delete(event.DeleteEvent{Object: original}))
	for _, tc := range []struct {
		name   string
		change func(*corev1.Pod)
		want   bool
	}{
		{name: "labels", change: func(p *corev1.Pod) { p.Labels["app"] = "api" }, want: true},
		{name: "owner", change: func(p *corev1.Pod) {
			p.OwnerReferences = []metav1.OwnerReference{scopeOwner("Job", "batch", "job")}
		}, want: true},
		{name: "status", change: func(p *corev1.Pod) { p.Status.Phase = corev1.PodRunning }},
		{name: "annotations", change: func(p *corev1.Pod) { p.Annotations = map[string]string{"note": "ignored"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			updated := original.DeepCopy()
			tc.change(updated)
			require.Equal(t, tc.want, predicate.Update(event.UpdateEvent{ObjectOld: original, ObjectNew: updated}))
		})
	}
}
