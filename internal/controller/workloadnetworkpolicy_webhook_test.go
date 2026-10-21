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
	"errors"
	"strings"
	"testing"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
	"github.com/kubewarden/network-enforcer/internal/workload"
)

func newWNP(
	namespace, name, target string,
	direction networkingv1.PolicyType,
) *securityv1alpha1.WorkloadNetworkPolicy {
	return &securityv1alpha1.WorkloadNetworkPolicy{
		Namespace: namespace,
		Name:      name,
		Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
			WorkloadTargetingSpec: securityv1alpha1.WorkloadTargetingSpec{
				TargetRef: securityv1alpha1.WorkloadTargetRef{
					Kind: securityv1alpha1.WorkloadKindDeployment,
					Name: target,
				},
				Direction: direction,
			},
			PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
				Backend: securityv1alpha1.PolicyBackendKubernetes,
				Kubernetes: &networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": target}},
					PolicyTypes: []networkingv1.PolicyType{direction},
				},
			},
		},
	}
}

func newValidator(
	t *testing.T,
	funcs interceptor.Funcs,
	objs ...client.Object,
) *PolicyValidator {
	t.Helper()

	s := runtime.NewScheme()
	if err := securityv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("add WorkloadNetworkPolicy scheme: %v", err)
	}

	reader := fake.NewClientBuilder().
		WithScheme(s).
		WithIndex(&securityv1alpha1.WorkloadNetworkPolicy{},
			workload.WNPTargetIndexField, workload.IndexWNPByTarget).
		WithObjects(objs...).
		WithInterceptorFuncs(funcs).
		Build()
	return &PolicyValidator{Client: reader}
}

func withUID(
	wnp *securityv1alpha1.WorkloadNetworkPolicy,
	uid types.UID,
) *securityv1alpha1.WorkloadNetworkPolicy {
	wnp.UID = uid
	return wnp
}

func assertConflict(t *testing.T, err error, names ...string) {
	t.Helper()
	if !apierrors.IsInvalid(err) {
		t.Fatalf("expected Invalid error, got %v", err)
	}
	for _, want := range append([]string{
		"is already taken by WorkloadNetworkPolicy",
		"spec.targetRef",
	}, names...) {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestValidateCreate(t *testing.T) {
	const namespace = "default"

	tests := []struct {
		name         string
		existing     []*securityv1alpha1.WorkloadNetworkPolicy
		candidate    *securityv1alpha1.WorkloadNetworkPolicy
		listError    bool
		wantErr      bool
		wantInternal bool
		wantNames    []string
	}{
		{
			name: "rejects duplicate and names existing object",
			existing: []*securityv1alpha1.WorkloadNetworkPolicy{
				withUID(newWNP(namespace, "existing", "web", networkingv1.PolicyTypeIngress), "uid-existing"),
			},
			candidate: withUID(newWNP(namespace, "duplicate", "web", networkingv1.PolicyTypeIngress), "uid-duplicate"),
			wantErr:   true,
			wantNames: []string{"default/existing"},
		},
		{
			name: "names all conflicting objects",
			existing: []*securityv1alpha1.WorkloadNetworkPolicy{
				withUID(newWNP(namespace, "a", "web", networkingv1.PolicyTypeIngress), "uid-a"),
				withUID(newWNP(namespace, "b", "web", networkingv1.PolicyTypeIngress), "uid-b"),
			},
			candidate: withUID(newWNP(namespace, "c", "web", networkingv1.PolicyTypeIngress), "uid-c"),
			wantErr:   true,
			wantNames: []string{"default/a", "default/b"},
		},
		{
			name: "allows same target and direction in another namespace",
			existing: []*securityv1alpha1.WorkloadNetworkPolicy{
				withUID(newWNP(namespace, "existing", "web", networkingv1.PolicyTypeIngress), "uid-existing"),
			},
			candidate: withUID(newWNP("other", "candidate", "web", networkingv1.PolicyTypeIngress), "uid-candidate"),
		},
		{
			name: "allows a different direction on the same target",
			existing: []*securityv1alpha1.WorkloadNetworkPolicy{
				withUID(newWNP(namespace, "ingress", "web", networkingv1.PolicyTypeIngress), "uid-ingress"),
			},
			candidate: withUID(newWNP(namespace, "egress", "web", networkingv1.PolicyTypeEgress), "uid-egress"),
		},
		{
			name: "excludes the object under review by UID",
			existing: []*securityv1alpha1.WorkloadNetworkPolicy{
				func() *securityv1alpha1.WorkloadNetworkPolicy {
					cached := newWNP(namespace, "cached-under-another-name", "web", networkingv1.PolicyTypeIngress)
					return withUID(cached, "uid-self")
				}(),
			},
			candidate: withUID(newWNP(namespace, "self", "web", networkingv1.PolicyTypeIngress), "uid-self"),
		},
		{
			name: "ignores a terminating policy",
			existing: []*securityv1alpha1.WorkloadNetworkPolicy{
				func() *securityv1alpha1.WorkloadNetworkPolicy {
					terminating := withUID(newWNP(namespace, "old", "web", networkingv1.PolicyTypeIngress), "uid-old")
					terminating.Finalizers = []string{"example.com/hold"}
					deletingAt := metav1.NewTime(time.Now())
					terminating.DeletionTimestamp = &deletingAt
					return terminating
				}(),
			},
			candidate: withUID(newWNP(namespace, "new", "web", networkingv1.PolicyTypeIngress), "uid-new"),
		},
		{
			name: "fails closed when lookup fails",
			candidate: withUID(
				newWNP(namespace, "candidate", "web", networkingv1.PolicyTypeIngress),
				"uid-candidate",
			),
			listError:    true,
			wantErr:      true,
			wantInternal: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			funcs := interceptor.Funcs{}
			if tt.listError {
				funcs.List = func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
					return errors.New("cache unavailable")
				}
			}
			objs := make([]client.Object, 0, len(tt.existing))
			for _, existing := range tt.existing {
				objs = append(objs, existing)
			}
			validator := newValidator(t, funcs, objs...)

			_, err := validator.ValidateCreate(context.Background(), tt.candidate)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateCreate() error = %v, want error %t", err, tt.wantErr)
			}
			if tt.wantInternal && !apierrors.IsInternalError(err) {
				t.Errorf("expected InternalError, got %v", err)
			}
			if tt.wantErr && !tt.wantInternal {
				assertConflict(t, err, tt.wantNames...)
			}
		})
	}
}

func TestValidateUpdate(t *testing.T) {
	const namespace = "default"

	tests := []struct {
		name     string
		existing *securityv1alpha1.WorkloadNetworkPolicy
		old      *securityv1alpha1.WorkloadNetworkPolicy
		updated  *securityv1alpha1.WorkloadNetworkPolicy
		wantErr  bool
	}{
		{
			name:     "rejects update moving onto a taken target and direction",
			existing: withUID(newWNP(namespace, "existing", "web", networkingv1.PolicyTypeIngress), "uid-existing"),
			old:      withUID(newWNP(namespace, "moving", "api", networkingv1.PolicyTypeIngress), "uid-moving"),
			updated: func() *securityv1alpha1.WorkloadNetworkPolicy {
				updated := newWNP(namespace, "moving", "web", networkingv1.PolicyTypeIngress)
				return withUID(updated, "uid-moving")
			}(),
			wantErr: true,
		},
		{
			name:     "admits update preserving an already duplicated target",
			existing: withUID(newWNP(namespace, "a", "web", networkingv1.PolicyTypeIngress), "uid-a"),
			old:      withUID(newWNP(namespace, "b", "web", networkingv1.PolicyTypeIngress), "uid-b"),
			updated: func() *securityv1alpha1.WorkloadNetworkPolicy {
				updated := newWNP(namespace, "b", "web", networkingv1.PolicyTypeIngress)
				updated.Annotations = map[string]string{"example.com/touched": "true"}
				return withUID(updated, "uid-b")
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := newValidator(t, interceptor.Funcs{}, tt.existing)
			_, err := validator.ValidateUpdate(context.Background(), tt.old, tt.updated)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateUpdate() error = %v, want error %t", err, tt.wantErr)
			}
			if tt.wantErr {
				assertConflict(t, err, "default/existing")
			}
		})
	}
}

func TestValidateDelete(t *testing.T) {
	validator := newValidator(t, interceptor.Funcs{})
	if _, err := validator.ValidateDelete(context.Background(),
		newWNP("default", "policy", "web", networkingv1.PolicyTypeIngress)); err != nil {
		t.Fatalf("ValidateDelete() error = %v, want nil", err)
	}
}
