package controller

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/manager"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
	"github.com/kubewarden/network-enforcer/internal/workload"
)

// SetupWNPIndexer registers the (targetRef.kind, targetRef.name, direction)
// field index on WorkloadNetworkPolicy. It must be called before mgr.Start. The
// index is queried through workload.LookupWNPByTarget.
func SetupWNPIndexer(ctx context.Context, mgr manager.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(
		ctx, &securityv1alpha1.WorkloadNetworkPolicy{}, workload.WNPTargetIndexField, workload.IndexWNPByTarget,
	); err != nil {
		return fmt.Errorf("indexing WorkloadNetworkPolicies by %s: %w", workload.WNPTargetIndexField, err)
	}
	return nil
}
