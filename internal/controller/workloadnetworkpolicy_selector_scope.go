package controller

import (
	"context"
	"fmt"
	"slices"

	"github.com/prometheus/client_golang/prometheus"
	appsv1 "k8s.io/api/apps/v1"
	apiMeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

const (
	conditionReady                   = "Ready"
	reasonSelectorScopeValid         = "SelectorScopeValid"
	reasonSelectorOverlapsWorkload   = "SelectorOverlapsWorkload"
	reasonTargetNotFound             = "TargetNotFound"
	reasonSelectorDoesNotMatchTarget = "SelectorDoesNotMatchTarget"
)

type workloadTemplate struct {
	target securityv1alpha1.WorkloadTargetRef
	labels map[string]string
	uid    types.UID
}

func newSelectorOverlapsCounter() prometheus.Counter {
	return prometheus.NewCounter(prometheus.CounterOpts{
		Name: "network_enforcer_selector_overlaps_total",
		Help: "Total number of WorkloadNetworkPolicy transitions into the SelectorOverlapsWorkload condition.",
	})
}

func (r *WorkloadNetworkPolicyReconciler) checkSelectorScope(
	ctx context.Context,
	wnp *securityv1alpha1.WorkloadNetworkPolicy,
) (metav1.Condition, error) {
	selectorSpec, err := wnp.Spec.GetSelector()
	if err != nil {
		return metav1.Condition{}, err
	}
	if wnp.Spec.Backend == securityv1alpha1.PolicyBackendIstio {
		selectorSpec.MatchExpressions = nil
	}
	selector, err := metav1.LabelSelectorAsSelector(&selectorSpec)
	if err != nil {
		return metav1.Condition{}, fmt.Errorf("invalid policy selector: %w", err)
	}
	templates, err := r.workloadTemplates(ctx, wnp.Namespace)
	if err != nil {
		return metav1.Condition{}, err
	}

	targetFound, targetMatches, overlaps := matchWorkloadTemplates(wnp, selector, templates)
	if len(overlaps) == 0 && (!targetFound || targetMatches) {
		overlaps, err = r.podSelectorOverlaps(ctx, wnp, selector, templates)
		if err != nil {
			return metav1.Condition{}, err
		}
	}
	return selectorScopeCondition(wnp, targetFound, targetMatches, overlaps), nil
}

func matchWorkloadTemplates(
	wnp *securityv1alpha1.WorkloadNetworkPolicy,
	selector labels.Selector,
	templates []workloadTemplate,
) (bool, bool, []string) {
	var targetFound, targetMatches bool
	var overlaps []string
	for _, template := range templates {
		matches := selector.Matches(labels.Set(template.labels))
		if template.target == wnp.Spec.TargetRef {
			targetFound = true
			targetMatches = matches
		} else if matches {
			overlaps = append(
				overlaps,
				fmt.Sprintf("workload %s %s/%s", template.target.Kind, wnp.Namespace, template.target.Name),
			)
		}
	}
	return targetFound, targetMatches, overlaps
}

func selectorScopeCondition(
	wnp *securityv1alpha1.WorkloadNetworkPolicy,
	targetFound, targetMatches bool,
	overlaps []string,
) metav1.Condition {
	switch {
	case targetFound && !targetMatches:
		return metav1.Condition{
			Type:               conditionReady,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: wnp.Generation,
			Reason:             reasonSelectorDoesNotMatchTarget,
			Message: fmt.Sprintf(
				"Policy selector does not match pod template labels of target workload %s %s/%s",
				wnp.Spec.TargetRef.Kind,
				wnp.Namespace,
				wnp.Spec.TargetRef.Name,
			),
		}
	case len(overlaps) > 0:
		slices.Sort(overlaps)
		return metav1.Condition{
			Type:               conditionReady,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: wnp.Generation,
			Reason:             reasonSelectorOverlapsWorkload,
			Message:            "Policy selector also selects " + overlaps[0],
		}
	case !targetFound:
		return metav1.Condition{
			Type:               conditionReady,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: wnp.Generation,
			Reason:             reasonTargetNotFound,
			Message: fmt.Sprintf("Target workload %s %s/%s does not exist yet",
				wnp.Spec.TargetRef.Kind, wnp.Namespace, wnp.Spec.TargetRef.Name),
		}
	default:
		return metav1.Condition{
			Type:               conditionReady,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: wnp.Generation,
			Reason:             reasonSelectorScopeValid,
			Message:            "Policy selector matches only the target workload",
		}
	}
}

func (r *WorkloadNetworkPolicyReconciler) workloadTemplates(
	ctx context.Context,
	namespace string,
) ([]workloadTemplate, error) {
	var deployments appsv1.DeploymentList
	if err := r.List(ctx, &deployments, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("failed to list Deployments: %w", err)
	}
	var statefulSets appsv1.StatefulSetList
	if err := r.List(ctx, &statefulSets, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("failed to list StatefulSets: %w", err)
	}
	var daemonSets appsv1.DaemonSetList
	if err := r.List(ctx, &daemonSets, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("failed to list DaemonSets: %w", err)
	}

	templates := make([]workloadTemplate, 0, len(deployments.Items)+len(statefulSets.Items)+len(daemonSets.Items))
	for _, deployment := range deployments.Items {
		templates = append(templates, workloadTemplate{
			target: securityv1alpha1.WorkloadTargetRef{
				Kind: securityv1alpha1.WorkloadKindDeployment,
				Name: deployment.Name,
			},
			labels: deployment.Spec.Template.Labels,
			uid:    deployment.UID,
		})
	}
	for _, statefulSet := range statefulSets.Items {
		templates = append(templates, workloadTemplate{
			target: securityv1alpha1.WorkloadTargetRef{
				Kind: securityv1alpha1.WorkloadKindStatefulSet,
				Name: statefulSet.Name,
			},
			labels: statefulSet.Spec.Template.Labels,
			uid:    statefulSet.UID,
		})
	}
	for _, daemonSet := range daemonSets.Items {
		templates = append(templates, workloadTemplate{
			target: securityv1alpha1.WorkloadTargetRef{
				Kind: securityv1alpha1.WorkloadKindDaemonSet,
				Name: daemonSet.Name,
			},
			labels: daemonSet.Spec.Template.Labels,
			uid:    daemonSet.UID,
		})
	}
	return templates, nil
}

func (r *WorkloadNetworkPolicyReconciler) updateReadyCondition(
	ctx context.Context,
	wnp *securityv1alpha1.WorkloadNetworkPolicy,
	condition metav1.Condition,
) error {
	previous := apiMeta.FindStatusCondition(wnp.Status.Conditions, conditionReady)
	newOverlap := condition.Reason == reasonSelectorOverlapsWorkload &&
		(previous == nil || previous.Reason != reasonSelectorOverlapsWorkload)
	newDuplicateTarget := condition.Reason == reasonDuplicateTarget &&
		(previous == nil || previous.Reason != reasonDuplicateTarget)
	base := client.MergeFromWithOptions(wnp.DeepCopy(), client.MergeFromWithOptimisticLock{})
	if !apiMeta.SetStatusCondition(&wnp.Status.Conditions, condition) {
		return nil
	}
	if err := r.Status().Patch(ctx, wnp, base); err != nil {
		return fmt.Errorf("failed to patch WorkloadNetworkPolicy Ready condition: %w", err)
	}
	if newOverlap && r.selectorOverlaps != nil {
		r.selectorOverlaps.Inc()
	}
	if newDuplicateTarget && r.duplicateTargets != nil {
		r.duplicateTargets.Inc()
	}
	return nil
}

func (r *WorkloadNetworkPolicyReconciler) policiesForWorkload(
	ctx context.Context,
	obj client.Object,
) []ctrl.Request {
	var policies securityv1alpha1.WorkloadNetworkPolicyList
	if err := r.List(ctx, &policies, client.InNamespace(obj.GetNamespace())); err != nil {
		log.FromContext(ctx).Error(err, "Failed to list WorkloadNetworkPolicies for workload change",
			"namespace", obj.GetNamespace(), "name", obj.GetName())
		return nil
	}
	requests := make([]ctrl.Request, 0, len(policies.Items))
	for _, policy := range policies.Items {
		requests = append(requests, ctrl.Request{NamespacedName: policy.NamespacedName()})
	}
	return requests
}
