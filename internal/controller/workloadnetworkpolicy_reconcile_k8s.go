package controller

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

func (r *WorkloadNetworkPolicyReconciler) reconcileK8sPolicy(
	ctx context.Context,
	log logr.Logger,
	wnp *securityv1alpha1.WorkloadNetworkPolicy,
) error {
	np := &networkingv1.NetworkPolicy{
		Name:      wnp.Name,
		Namespace: wnp.Namespace,
	}
	err := r.Get(ctx, wnp.NamespacedName(), np)
	switch {
	case err != nil && !apierrors.IsNotFound(err):
		return fmt.Errorf("failed to get NetworkPolicy: %w", err)
	case err == nil && !metav1.IsControlledBy(np, wnp):
		return &policyOwnershipConflictError{kind: "NetworkPolicy", key: wnp.NamespacedName()}
	case apierrors.IsNotFound(err) &&
		wnp.Spec.Mode == securityv1alpha1.WorkloadNetworkPolicyModeMonitor:
		// Nothing to do in monitor mode if the policy doesn't exist
		return nil
	default:
	}

	if wnp.Spec.Mode == securityv1alpha1.WorkloadNetworkPolicyModeMonitor {
		log.Info("Deleting NetworkPolicy", "name", np.Name, "namespace", np.Namespace)
		return r.Delete(ctx, np)
	}
	return r.reconcileProtect(ctx, log, wnp, np)
}

func (r *WorkloadNetworkPolicyReconciler) reconcileProtect(
	ctx context.Context,
	log logr.Logger,
	wnp *securityv1alpha1.WorkloadNetworkPolicy,
	np *networkingv1.NetworkPolicy,
) error {
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, np, func() error {
		wnp.Spec.Kubernetes.DeepCopyInto(&np.Spec)
		setManagedByLabel(np)

		return controllerutil.SetControllerReference(wnp, np, r.Scheme)
	}); err != nil {
		return fmt.Errorf("failed to reconcile NetworkPolicy: %w", err)
	}

	log.Info("Reconciled NetworkPolicy", "name", np.Name, "namespace", np.Namespace)
	return nil
}
