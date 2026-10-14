package workload

import (
	"context"
	"errors"
	"fmt"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

// WNPTargetIndexField is the field-index key resolving a WorkloadNetworkPolicy
// by (spec.targetRef.kind, spec.targetRef.name, spec.direction). The index is
// registered on the manager by controller.SetupWNPIndexer.
const WNPTargetIndexField = "spec.targetRef.kind,spec.targetRef.name,spec.direction"

var (
	// ErrTargetNotFound is returned when no WorkloadNetworkPolicy targets the workload and direction.
	ErrTargetNotFound = errors.New("no WorkloadNetworkPolicy targets the workload and direction")
	// ErrDuplicateTarget is returned when more than one WorkloadNetworkPolicy in a
	// namespace shares the same (targetRef, direction).
	ErrDuplicateTarget = errors.New("multiple WorkloadNetworkPolicies share the same targetRef and direction")
)

// WNPTargetIndexKey builds the WNPTargetIndexField value.
func WNPTargetIndexKey(kind securityv1alpha1.WorkloadKind, name string, direction networkingv1.PolicyType) string {
	return string(kind) + "/" + name + "/" + string(direction)
}

// IndexWNPByTarget extracts the WNPTargetIndexField value for the field indexer.
func IndexWNPByTarget(o client.Object) []string {
	wnp, ok := o.(*securityv1alpha1.WorkloadNetworkPolicy)
	if !ok {
		return nil
	}
	ref := wnp.Spec.TargetRef
	if ref.Kind == "" || ref.Name == "" || wnp.Spec.Direction == "" {
		return nil
	}
	return []string{WNPTargetIndexKey(ref.Kind, ref.Name, wnp.Spec.Direction)}
}

// LookupWNPByTarget returns the single WorkloadNetworkPolicy in namespace that
// targets (kind, name) in direction. It wraps ErrTargetNotFound when none exists
// and ErrDuplicateTarget when more than one does. The reader must have the
// WNPTargetIndexField index registered.
func LookupWNPByTarget(
	ctx context.Context,
	c client.Reader,
	namespace string,
	kind securityv1alpha1.WorkloadKind,
	name string,
	direction networkingv1.PolicyType,
) (*securityv1alpha1.WorkloadNetworkPolicy, error) {
	var wnpList securityv1alpha1.WorkloadNetworkPolicyList
	if err := c.List(ctx, &wnpList,
		client.InNamespace(namespace),
		client.MatchingFields{WNPTargetIndexField: WNPTargetIndexKey(kind, name, direction)},
	); err != nil {
		return nil, fmt.Errorf("listing WorkloadNetworkPolicies in namespace %s: %w", namespace, err)
	}

	switch len(wnpList.Items) {
	case 0:
		return nil, fmt.Errorf("%w: %s %s/%s %s", ErrTargetNotFound, kind, namespace, name, direction)
	case 1:
		return &wnpList.Items[0], nil
	default:
		names := make([]string, 0, len(wnpList.Items))
		for i := range wnpList.Items {
			names = append(names, wnpList.Items[i].Name)
		}
		return nil, fmt.Errorf("%w: %s %s/%s %s: %s",
			ErrDuplicateTarget, kind, namespace, name, direction, strings.Join(names, ", "))
	}
}
