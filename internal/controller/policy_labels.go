package controller

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

// setManagedByLabel sets the app.kubernetes.io/managed-by label on obj,
// preserving any other labels already present. It is applied to every low
// level network policy (NetworkPolicy, Istio AuthorizationPolicy, ...)
// rendered from a WorkloadNetworkPolicy, so that they can be found with a
// label selector.
func setManagedByLabel(obj metav1.Object) {
	labels := obj.GetLabels()
	if labels == nil {
		labels = map[string]string{}
	}
	labels[securityv1alpha1.ManagedByLabelKey] = securityv1alpha1.ManagedByLabelValue
	obj.SetLabels(labels)
}
