package controller

import (
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	appsv1 "k8s.io/api/apps/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apiMeta "k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

// WorkloadNetworkPolicyReconciler reconciles WorkloadNetworkPolicy resources.
type WorkloadNetworkPolicyReconciler struct {
	client.Client

	Scheme *runtime.Scheme

	selectorOverlaps prometheus.Counter
}

// +kubebuilder:rbac:groups=networkenforcer.kubewarden.io,resources=workloadnetworkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=deployments;statefulsets;daemonsets,verbs=get;list;watch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.istio.io,resources=authorizationpolicies,verbs=get;list;watch;create;update;patch;delete

// Reconcile handles WorkloadNetworkPolicy create / update / delete.
func (r *WorkloadNetworkPolicyReconciler) Reconcile(
	ctx context.Context,
	req ctrl.Request,
) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	var wnp securityv1alpha1.WorkloadNetworkPolicy
	if err := r.Get(ctx, req.NamespacedName, &wnp); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	condition, err := r.checkSelectorScope(ctx, &wnp)
	if err != nil {
		return ctrl.Result{}, err
	}

	if condition.Reason != reasonSelectorDoesNotMatchTarget {
		if wnp.Spec.IsKubernetesBackend() {
			err = r.reconcileK8sPolicy(ctx, log, &wnp)
		} else {
			err = r.reconcileIstioPolicy(ctx, log, &wnp)
		}
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, r.updateReadyCondition(ctx, &wnp, condition)
}

// SetupWithManager sets up the controller with the Manager.
func (r *WorkloadNetworkPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.selectorOverlaps = newSelectorOverlapsCounter()
	if err := metrics.Registry.Register(r.selectorOverlaps); err != nil {
		return fmt.Errorf("failed to register selector overlap metric: %w", err)
	}

	workloadHandler := handler.EnqueueRequestsFromMapFunc(r.policiesForWorkload)
	workloadChanges := builder.WithPredicates(predicate.GenerationChangedPredicate{})
	builder := ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.WorkloadNetworkPolicy{}).
		Owns(&networkingv1.NetworkPolicy{}).
		Watches(&appsv1.Deployment{}, workloadHandler, workloadChanges).
		Watches(&appsv1.StatefulSet{}, workloadHandler, workloadChanges).
		Watches(&appsv1.DaemonSet{}, workloadHandler, workloadChanges)

	// we need to disable the watch on the resource if Istio is not installed in the cluster
	_, err := mgr.GetRESTMapper().RESTMapping(schema.GroupKind{
		Group: "security.istio.io",
		Kind:  "AuthorizationPolicy",
	}, "v1")
	switch {
	case err == nil:
		builder = builder.Owns(&istiosecurityv1.AuthorizationPolicy{})
	case apiMeta.IsNoMatchError(err):
		log.Log.WithName("workloadnetworkpolicy").Info(
			"Istio AuthorizationPolicy CRD not found, disabling AuthorizationPolicy watch",
		)
	default:
		return fmt.Errorf("unable to discover Istio AuthorizationPolicy CRD: %w", err)
	}

	return builder.Named("workloadnetworkpolicy").Complete(r)
}
