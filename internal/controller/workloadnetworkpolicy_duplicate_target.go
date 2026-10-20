package controller

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
	"github.com/kubewarden/network-enforcer/internal/workload"
)

const (
	reasonDuplicateTarget      = "DuplicateTarget"
	minDuplicateTargetPolicies = 2
)

type duplicateTargetConflict struct {
	condition metav1.Condition
	// winner is true when the reconciled WNP is the oldest of the conflicting
	// ones, i.e. the only one allowed to render a data-plane object
	winner bool
}

func newDuplicateTargetsCounter() prometheus.Counter {
	return prometheus.NewCounter(prometheus.CounterOpts{
		Name: "network_enforcer_duplicate_targets_total",
		Help: "Total number of WorkloadNetworkPolicy transitions into the DuplicateTarget condition.",
	})
}

// checkDuplicateTarget reports a conflict when more than one
// WorkloadNetworkPolicy in the namespace targets the same (targetRef,
// direction). It reports false when there is no conflict.
func (r *WorkloadNetworkPolicyReconciler) checkDuplicateTarget(
	ctx context.Context,
	wnp *securityv1alpha1.WorkloadNetworkPolicy,
) (duplicateTargetConflict, bool, error) {
	ref := wnp.Spec.TargetRef
	if ref.Kind == "" || ref.Name == "" || wnp.Spec.Direction == "" {
		return duplicateTargetConflict{}, false, nil
	}

	var wnpList securityv1alpha1.WorkloadNetworkPolicyList
	if err := r.List(ctx, &wnpList,
		client.InNamespace(wnp.Namespace),
		client.MatchingFields{workload.WNPTargetIndexField: workload.WNPTargetIndexKey(
			ref.Kind, ref.Name, wnp.Spec.Direction,
		)},
	); err != nil {
		return duplicateTargetConflict{}, false, fmt.Errorf(
			"failed to list WorkloadNetworkPolicies targeting %s %s/%s %s: %w",
			ref.Kind, wnp.Namespace, ref.Name, wnp.Spec.Direction, err,
		)
	}
	if len(wnpList.Items) < minDuplicateTargetPolicies {
		return duplicateTargetConflict{}, false, nil
	}

	oldest := oldestWorkloadNetworkPolicy(wnpList.Items)
	names := make([]string, 0, len(wnpList.Items))
	for i := range wnpList.Items {
		names = append(names, wnpList.Items[i].Name)
	}
	slices.Sort(names)

	return duplicateTargetConflict{
		condition: metav1.Condition{
			Type:               conditionReady,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: wnp.Generation,
			Reason:             reasonDuplicateTarget,
			Message: fmt.Sprintf(
				"%s %s/%s %s is targeted by %d WorkloadNetworkPolicies (%s); only the oldest, %s, renders a policy",
				ref.Kind, wnp.Namespace, ref.Name, wnp.Spec.Direction,
				len(wnpList.Items), strings.Join(names, ", "), oldest.Name,
			),
		},
		winner: oldest.Name == wnp.Name,
	}, true, nil
}

func oldestWorkloadNetworkPolicy(
	policies []securityv1alpha1.WorkloadNetworkPolicy,
) *securityv1alpha1.WorkloadNetworkPolicy {
	oldest := slices.MinFunc(policies, func(a, b securityv1alpha1.WorkloadNetworkPolicy) int {
		switch {
		case a.CreationTimestamp.Before(&b.CreationTimestamp):
			return -1
		case b.CreationTimestamp.Before(&a.CreationTimestamp):
			return 1
		default:
			return strings.Compare(a.Name, b.Name)
		}
	})
	return &oldest
}

func (r *WorkloadNetworkPolicyReconciler) removeRenderedPolicy(
	ctx context.Context,
	wnp *securityv1alpha1.WorkloadNetworkPolicy,
) error {
	var rendered client.Object
	if wnp.Spec.IsKubernetesBackend() {
		rendered = &networkingv1.NetworkPolicy{}
	} else {
		rendered = &istiosecurityv1.AuthorizationPolicy{}
	}

	key := wnp.NamespacedName()
	if err := r.Get(ctx, key, rendered); err != nil {
		return client.IgnoreNotFound(err)
	}
	if !metav1.IsControlledBy(rendered, wnp) {
		return nil
	}
	if err := r.Delete(ctx, rendered); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete rendered policy for duplicate target: %w", err)
	}
	return nil
}

// duplicateTargetPolicies maps a WorkloadNetworkPolicy event to every other
// policy in the namespace, so duplicate-target conflicts are detected and
// cleared without waiting for another event on those policies.
func (r *WorkloadNetworkPolicyReconciler) duplicateTargetPolicies(
	ctx context.Context,
	obj client.Object,
) []ctrl.Request {
	var wnpList securityv1alpha1.WorkloadNetworkPolicyList
	if err := r.List(ctx, &wnpList, client.InNamespace(obj.GetNamespace())); err != nil {
		log.FromContext(ctx).Error(err, "Failed to list WorkloadNetworkPolicies for policy change",
			"namespace", obj.GetNamespace(), "name", obj.GetName())
		return nil
	}

	requests := make([]ctrl.Request, 0, len(wnpList.Items))
	for i := range wnpList.Items {
		if wnpList.Items[i].Name == obj.GetName() {
			continue
		}
		requests = append(requests, ctrl.Request{NamespacedName: wnpList.Items[i].NamespacedName()})
	}
	return requests
}
