/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
	"github.com/kubewarden/network-enforcer/internal/workload"
)

// +kubebuilder:webhook:path=/validate-networkenforcer-kubewarden-io-v1alpha1-workloadnetworkpolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=networkenforcer.kubewarden.io,resources=workloadnetworkpolicies,verbs=create;update,versions=v1alpha1,name=validate-workloadnetworkpolicies.kubewarden.io,admissionReviewVersions=v1

type PolicyValidator struct {
	Client client.Client
}

var _ admission.Validator[*securityv1alpha1.WorkloadNetworkPolicy] = &PolicyValidator{}

func (v *PolicyValidator) ValidateCreate(
	ctx context.Context,
	obj *securityv1alpha1.WorkloadNetworkPolicy,
) (admission.Warnings, error) {
	return nil, v.validateUniqueTarget(ctx, obj)
}

// ValidateUpdate only updates that move the object to a
// different (targetRef, direction) are checked.
func (v *PolicyValidator) ValidateUpdate(
	ctx context.Context,
	oldObj, newObj *securityv1alpha1.WorkloadNetworkPolicy,
) (admission.Warnings, error) {
	if !newObj.DeletionTimestamp.IsZero() || targetKey(oldObj) == targetKey(newObj) {
		return nil, nil
	}
	return nil, v.validateUniqueTarget(ctx, newObj)
}

func (v *PolicyValidator) ValidateDelete(
	_ context.Context,
	_ *securityv1alpha1.WorkloadNetworkPolicy,
) (admission.Warnings, error) {
	return nil, nil
}

func (v *PolicyValidator) validateUniqueTarget(
	ctx context.Context,
	wnp *securityv1alpha1.WorkloadNetworkPolicy,
) error {
	key := targetKey(wnp)
	if key == "" {
		// Schema validation rejects an incomplete targetRef or direction.
		return nil
	}

	var wnpList securityv1alpha1.WorkloadNetworkPolicyList
	if err := v.Client.List(ctx, &wnpList,
		client.InNamespace(wnp.Namespace),
		client.MatchingFields{workload.WNPTargetIndexField: key},
	); err != nil {
		return apierrors.NewInternalError(
			fmt.Errorf("listing WorkloadNetworkPolicies in namespace %s: %w", wnp.Namespace, err))
	}

	var conflicts []string
	for _, existing := range wnpList.Items {
		// Names are unique per namespace, so a same-name entry is either this
		// object or a stale cache entry for a deleted predecessor.
		if existing.UID == wnp.UID || existing.Name == wnp.Name || !existing.DeletionTimestamp.IsZero() {
			continue
		}
		conflicts = append(conflicts, existing.Namespace+"/"+existing.Name)
	}
	if len(conflicts) == 0 {
		return nil
	}

	ref := wnp.Spec.TargetRef
	log.FromContext(ctx).Info("Rejected WorkloadNetworkPolicy with a taken targetRef and direction",
		"namespace", wnp.Namespace, "name", wnp.Name, "conflicts", conflicts)
	return apierrors.NewInvalid(
		securityv1alpha1.GroupVersion.WithKind(
			securityv1alpha1.WorkloadNetworkPolicyKind,
		).GroupKind(),
		wnp.Name,
		field.ErrorList{field.Invalid(
			field.NewPath("spec", "targetRef"),
			string(ref.Kind)+"/"+ref.Name,
			fmt.Sprintf("direction %s is already taken by WorkloadNetworkPolicy %s; "+
				"at most one WorkloadNetworkPolicy may target a workload per direction",
				wnp.Spec.Direction, strings.Join(conflicts, ", ")),
		)},
	)
}

// targetKey returns the workload.WNPTargetIndexField value of wnp, or "" when
// the object carries no complete (targetRef, direction).
func targetKey(wnp *securityv1alpha1.WorkloadNetworkPolicy) string {
	if keys := workload.IndexWNPByTarget(wnp); len(keys) == 1 {
		return keys[0]
	}
	return ""
}
