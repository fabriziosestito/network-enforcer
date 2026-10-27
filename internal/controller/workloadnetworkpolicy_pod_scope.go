package controller

import (
	"context"
	"fmt"
	"maps"
	"reflect"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

func (r *WorkloadNetworkPolicyReconciler) podSelectorOverlaps(
	ctx context.Context,
	wnp *securityv1alpha1.WorkloadNetworkPolicy,
	selector labels.Selector,
	templates []workloadTemplate,
) ([]string, error) {
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(wnp.Namespace), client.MatchingLabelsSelector{
		Selector: selector,
	}); err != nil {
		return nil, fmt.Errorf("failed to list Pods for selector scope: %w", err)
	}
	var overlaps []string
	for _, pod := range pods.Items {
		owner, err := r.podWorkloadOwner(ctx, &pod)
		if err != nil {
			return nil, err
		}
		if podOwnerMatchesTarget(owner, wnp.Spec.TargetRef, templates) {
			continue
		}
		description := fmt.Sprintf("Pod %s/%s", pod.Namespace, pod.Name)
		if owner != nil {
			description += fmt.Sprintf(" (owner: %s %s/%s)", owner.Kind, pod.Namespace, owner.Name)
		}
		overlaps = append(overlaps, description)
	}
	return overlaps, nil
}

func (r *WorkloadNetworkPolicyReconciler) podWorkloadOwner(
	ctx context.Context,
	pod *corev1.Pod,
) (*metav1.OwnerReference, error) {
	owner := metav1.GetControllerOf(pod)
	if owner == nil || owner.APIVersion != appsv1.SchemeGroupVersion.String() || owner.Kind != "ReplicaSet" {
		return owner, nil
	}
	var rs appsv1.ReplicaSet
	key := client.ObjectKey{Namespace: pod.Namespace, Name: owner.Name}
	if err := r.Get(ctx, key, &rs); err != nil {
		if apierrors.IsNotFound(err) {
			// A dangling reference cannot establish membership in the target Deployment.
			return owner, nil
		}
		return nil, fmt.Errorf("failed to get ReplicaSet %s for Pod %s/%s: %w", key, pod.Namespace, pod.Name, err)
	}
	if rs.UID != owner.UID {
		return owner, nil
	}
	if controller := metav1.GetControllerOf(&rs); controller != nil &&
		controller.APIVersion == appsv1.SchemeGroupVersion.String() && controller.Kind == "Deployment" {
		return controller, nil
	}
	return owner, nil
}

func podOwnerMatchesTarget(
	owner *metav1.OwnerReference,
	target securityv1alpha1.WorkloadTargetRef,
	templates []workloadTemplate,
) bool {
	if owner == nil || owner.APIVersion != appsv1.SchemeGroupVersion.String() ||
		owner.Kind != string(target.Kind) || owner.Name != target.Name {
		return false
	}
	for _, template := range templates {
		if template.target == target {
			return owner.UID == template.uid
		}
	}
	// Leftover Pods of a missing target are reported as TargetNotFound rather than as overlaps.
	return true
}

func selectorScopeMetadataChanges() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			return !maps.Equal(e.ObjectOld.GetLabels(), e.ObjectNew.GetLabels()) ||
				!reflect.DeepEqual(e.ObjectOld.GetOwnerReferences(), e.ObjectNew.GetOwnerReferences())
		},
	}
}
