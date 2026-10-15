package controller

import (
	"context"
	"fmt"
	"slices"

	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

func (r *WorkloadNetworkPolicyReconciler) checkRetainedPolicyScope(
	ctx context.Context,
	wnp *securityv1alpha1.WorkloadNetworkPolicy,
	mismatch metav1.Condition,
) (metav1.Condition, error) {
	selectorSpec, retained, err := r.retainedPolicySelector(ctx, wnp)
	if err != nil {
		return metav1.Condition{}, fmt.Errorf("failed to get retained policy selector: %w", err)
	}
	if !retained {
		return mismatch, nil
	}
	selector, err := metav1.LabelSelectorAsSelector(&selectorSpec)
	if err != nil {
		return metav1.Condition{}, fmt.Errorf("invalid retained policy selector: %w", err)
	}
	templates, err := r.workloadTemplates(ctx, wnp.Namespace)
	if err != nil {
		return metav1.Condition{}, err
	}
	_, _, overlaps := matchWorkloadTemplates(wnp, selector, templates)
	message := mismatch.Message + "; retained policy selector and rules remain unchanged until the selector is corrected"
	if len(overlaps) > 0 {
		overlapMessage := "Retained policy selector also selects workload " + slices.Min(overlaps)
		return metav1.Condition{
			Type:               conditionReady,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: wnp.Generation,
			Reason:             reasonSelectorOverlapsWorkload,
			Message:            overlapMessage + "; " + message,
		}, nil
	}
	return metav1.Condition{
		Type:               conditionReady,
		Status:             metav1.ConditionFalse,
		ObservedGeneration: wnp.Generation,
		Reason:             reasonSelectorDoesNotMatchTarget,
		Message:            message,
	}, nil
}

func (r *WorkloadNetworkPolicyReconciler) retainedPolicySelector(
	ctx context.Context,
	wnp *securityv1alpha1.WorkloadNetworkPolicy,
) (metav1.LabelSelector, bool, error) {
	if wnp.Spec.IsKubernetesBackend() {
		var np networkingv1.NetworkPolicy
		if err := r.Get(ctx, wnp.NamespacedName(), &np); err != nil {
			return metav1.LabelSelector{}, false, client.IgnoreNotFound(err)
		}
		return np.Spec.PodSelector, metav1.IsControlledBy(&np, wnp), nil
	}
	var ap istiosecurityv1.AuthorizationPolicy
	if err := r.Get(ctx, wnp.NamespacedName(), &ap); err != nil {
		return metav1.LabelSelector{}, false, client.IgnoreNotFound(err)
	}
	selector := metav1.LabelSelector{MatchLabels: ap.Spec.GetSelector().GetMatchLabels()}
	return selector, metav1.IsControlledBy(&ap, wnp), nil
}
