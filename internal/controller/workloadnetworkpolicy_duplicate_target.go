package controller

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
	"github.com/kubewarden/network-enforcer/internal/workload"
)

const (
	reasonDuplicateTarget            = "DuplicateTarget"
	minDuplicateTargetPolicies       = 2
	maxDuplicateTargetNamesInMessage = 16
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
	target, ok := wnpTargetKey(wnp)
	if !ok {
		return duplicateTargetConflict{}, false, nil
	}
	ref := wnp.Spec.TargetRef

	var wnpList securityv1alpha1.WorkloadNetworkPolicyList
	if err := r.List(ctx, &wnpList,
		client.InNamespace(wnp.Namespace),
		client.MatchingFields{workload.WNPTargetIndexField: target.target},
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
	omitted := 0
	if len(names) > maxDuplicateTargetNamesInMessage {
		omitted = len(names) - maxDuplicateTargetNamesInMessage
		names = names[:maxDuplicateTargetNamesInMessage]
	}
	listedNames := strings.Join(names, ", ")
	if omitted > 0 {
		listedNames = fmt.Sprintf("%s, and %d more", listedNames, omitted)
	}

	return duplicateTargetConflict{
		condition: metav1.Condition{
			Type:               conditionReady,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: wnp.Generation,
			Reason:             reasonDuplicateTarget,
			Message: fmt.Sprintf(
				"%s %s/%s %s is targeted by %d WorkloadNetworkPolicies (%s); only the oldest, %s, renders a policy",
				ref.Kind, wnp.Namespace, ref.Name, wnp.Spec.Direction,
				len(wnpList.Items), listedNames, oldest.Name,
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

func (r *WorkloadNetworkPolicyReconciler) duplicateTargetHandler() handler.EventHandler {
	enqueue := func(ctx context.Context, obj client.Object, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
		for _, request := range r.duplicateTargetPolicies(ctx, obj) {
			q.Add(request)
		}
	}

	return handler.Funcs{
		CreateFunc: func(ctx context.Context, e event.CreateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			enqueue(ctx, e.Object, q)
		},
		UpdateFunc: func(ctx context.Context, e event.UpdateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			enqueue(ctx, e.ObjectOld, q)
			enqueue(ctx, e.ObjectNew, q)
		},
		DeleteFunc: func(ctx context.Context, e event.DeleteEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			enqueue(ctx, e.Object, q)
		},
	}
}

// duplicateTargetPolicies maps a WorkloadNetworkPolicy to the other policies
// sharing its (targetRef, direction).
func (r *WorkloadNetworkPolicyReconciler) duplicateTargetPolicies(
	ctx context.Context,
	obj client.Object,
) []ctrl.Request {
	wnp, ok := obj.(*securityv1alpha1.WorkloadNetworkPolicy)
	if !ok {
		return nil
	}
	target, ok := wnpTargetKey(wnp)
	if !ok {
		return nil
	}

	var wnpList securityv1alpha1.WorkloadNetworkPolicyList
	if err := r.List(ctx, &wnpList,
		client.InNamespace(wnp.Namespace),
		client.MatchingFields{workload.WNPTargetIndexField: target.target},
	); err != nil {
		log.FromContext(ctx).Error(err, "Failed to list WorkloadNetworkPolicies for policy change",
			"namespace", wnp.Namespace, "name", wnp.Name)
		return nil
	}

	requests := make([]ctrl.Request, 0, len(wnpList.Items))
	for i := range wnpList.Items {
		if wnpList.Items[i].Name == wnp.Name {
			continue
		}
		requests = append(requests, ctrl.Request{NamespacedName: wnpList.Items[i].NamespacedName()})
	}
	return requests
}
