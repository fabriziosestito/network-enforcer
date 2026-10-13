package workload

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

const testNamespace = "default"

func ownedPod(name string, owner *metav1.OwnerReference, labels map[string]string) *corev1.Pod {
	pod := &corev1.Pod{
		Name:      name,
		Namespace: testNamespace,
		Labels:    labels,
		UID:       types.UID(name + "-uid"),
	}
	if owner != nil {
		pod.OwnerReferences = []metav1.OwnerReference{*owner}
	}
	return pod
}

func controllerRef(apiVersion, kind, name string) *metav1.OwnerReference {
	return &metav1.OwnerReference{
		APIVersion: apiVersion,
		Kind:       kind,
		Name:       name,
		UID:        types.UID(name + "-uid"),
		Controller: new(true),
	}
}

// Cases adapted from runtime-enforcer getPodInfo tests:
// https://github.com/kubewarden/runtime-enforcer/pull/219/changes#diff-43908338b58fbcda0d302e74469efb9886c7f6846076de871715ef480b0b76efL13
func TestExtractWorkloadKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		pod  *corev1.Pod
		want securityv1alpha1.WorkloadRef
	}{
		{
			name: "standalone pod without controller",
			pod:  ownedPod("mypod", nil, nil),
			want: securityv1alpha1.WorkloadRef{
				Namespace: testNamespace,
				OwnerKind: securityv1alpha1.WorkloadKindPod,
				OwnerName: "mypod",
			},
		},
		{
			name: "replicaset without pod-template-hash stays replicaset",
			pod: ownedPod(
				"network-enforcer-controller-manager-6f4b9855c6-5zwq7",
				controllerRef(
					"apps/v1",
					string(securityv1alpha1.WorkloadKindReplicaSet),
					"network-enforcer-controller-manager-6f4b9855c6",
				),
				map[string]string{},
			),
			want: securityv1alpha1.WorkloadRef{
				Namespace: testNamespace,
				OwnerKind: securityv1alpha1.WorkloadKindReplicaSet,
				OwnerName: "network-enforcer-controller-manager-6f4b9855c6",
			},
		},
		{
			name: "replicaset with pod-template-hash becomes deployment",
			pod: ownedPod(
				"network-enforcer-controller-manager-6f4b9855c6-5zwq7",
				controllerRef(
					"apps/v1",
					string(securityv1alpha1.WorkloadKindReplicaSet),
					"network-enforcer-controller-manager-6f4b9855c6",
				),
				map[string]string{
					appsv1.DefaultDeploymentUniqueLabelKey: "6f4b9855c6",
				},
			),
			want: securityv1alpha1.WorkloadRef{
				Namespace: testNamespace,
				OwnerKind: securityv1alpha1.WorkloadKindDeployment,
				OwnerName: "network-enforcer-controller-manager",
			},
		},
		{
			name: "statefulset",
			pod: ownedPod(
				"db-0",
				controllerRef("apps/v1", string(securityv1alpha1.WorkloadKindStatefulSet), "db"),
				nil,
			),
			want: securityv1alpha1.WorkloadRef{
				Namespace: testNamespace,
				OwnerKind: securityv1alpha1.WorkloadKindStatefulSet,
				OwnerName: "db",
			},
		},
		{
			name: "daemonset",
			pod: ownedPod(
				"agent-node1",
				controllerRef("apps/v1", string(securityv1alpha1.WorkloadKindDaemonSet), "agent"),
				nil,
			),
			want: securityv1alpha1.WorkloadRef{
				Namespace: testNamespace,
				OwnerKind: securityv1alpha1.WorkloadKindDaemonSet,
				OwnerName: "agent",
			},
		},
		{
			name: "job controller remains job",
			pod: ownedPod(
				"ubuntu-job-pq2qc",
				controllerRef("batch/v1", "Job", "ubuntu-job"),
				nil,
			),
			want: securityv1alpha1.WorkloadRef{
				Namespace: testNamespace,
				OwnerKind: securityv1alpha1.WorkloadKindJob,
				OwnerName: "ubuntu-job",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, GetNameAndKind(tt.pod))
		})
	}
}

func TestWorkloadKeyFromPod(t *testing.T) {
	t.Parallel()

	pod := ownedPod(
		"frontend-abc123-xyz",
		controllerRef("apps/v1", string(securityv1alpha1.WorkloadKindReplicaSet), "frontend-abc123"),
		map[string]string{appsv1.DefaultDeploymentUniqueLabelKey: "abc123"},
	)
	deployment := &appsv1.Deployment{
		Name: "frontend", Namespace: testNamespace,
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "frontend"}},
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, appsv1.AddToScheme(scheme))

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pod, deployment).
		Build()

	got, err := Get(context.Background(), cl, types.NamespacedName{Namespace: testNamespace, Name: pod.Name})
	require.NoError(t, err)
	require.Equal(t, securityv1alpha1.WorkloadRef{
		Namespace: testNamespace,
		OwnerKind: securityv1alpha1.WorkloadKindDeployment,
		OwnerName: "frontend",
		Identity:  "", // identity is not populated by this method
		Selector:  metav1.LabelSelector{MatchLabels: map[string]string{"app": "frontend"}},
	}, got)

	_, err = Get(context.Background(), cl, types.NamespacedName{Namespace: testNamespace, Name: "missing"})
	require.True(t, apierrors.IsNotFound(err))
}

func TestResolveDenyingPolicy(t *testing.T) {
	t.Parallel()

	selector := metav1.LabelSelector{MatchLabels: map[string]string{"app": "frontend"}}
	wk := &securityv1alpha1.WorkloadRef{
		Namespace: testNamespace,
		OwnerKind: securityv1alpha1.WorkloadKindDeployment,
		OwnerName: "frontend",
		Selector:  selector,
	}
	newPolicy := func(name string, direction networkingv1.PolicyType) *securityv1alpha1.WorkloadNetworkPolicy {
		return &securityv1alpha1.WorkloadNetworkPolicy{
			Name: name, Namespace: testNamespace,
			Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
				WorkloadTargetingSpec: securityv1alpha1.WorkloadTargetingSpec{
					TargetRef: securityv1alpha1.WorkloadTargetRef{Kind: wk.OwnerKind, Name: wk.OwnerName},
					Direction: direction,
				},
				PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
					Backend: securityv1alpha1.PolicyBackendKubernetes,
					Kubernetes: &networkingv1.NetworkPolicySpec{
						PodSelector: selector,
						PolicyTypes: []networkingv1.PolicyType{direction},
					},
				},
			},
		}
	}
	ingress := newPolicy("incoming", networkingv1.PolicyTypeIngress)
	egress := newPolicy("outgoing", networkingv1.PolicyTypeEgress)
	otherNamespace := ingress.DeepCopy()
	otherNamespace.Namespace = "other"
	otherTarget := newPolicy("other-workload", networkingv1.PolicyTypeIngress)
	otherTarget.Spec.TargetRef.Name = "other"
	invalidEgress := newPolicy("invalid-egress", networkingv1.PolicyTypeEgress)
	invalidEgress.Spec.Kubernetes = nil

	cases := []struct {
		name      string
		direction networkingv1.PolicyType
		objs      []client.Object
		wantName  string
		wantErr   error
	}{
		{
			name:      "ingress ignores egress with identical selector",
			direction: networkingv1.PolicyTypeIngress,
			objs:      []client.Object{ingress, egress},
			wantName:  ingress.Name,
		},
		{
			name:      "egress ignores ingress with identical selector",
			direction: networkingv1.PolicyTypeEgress,
			objs:      []client.Object{ingress, egress},
			wantName:  egress.Name,
		},
		{
			name:      "ingress cannot match egress-only policy",
			direction: networkingv1.PolicyTypeIngress,
			objs:      []client.Object{egress},
			wantErr:   ErrTargetNotFound,
		},
		{
			name:      "egress cannot match ingress-only policy",
			direction: networkingv1.PolicyTypeEgress,
			objs:      []client.Object{ingress},
			wantErr:   ErrTargetNotFound,
		},
		{
			name:      "policy without direction is ignored",
			direction: networkingv1.PolicyTypeIngress,
			objs:      []client.Object{newPolicy("no-direction", "")},
			wantErr:   ErrTargetNotFound,
		},
		{
			name:      "same-direction duplicate is an error",
			direction: networkingv1.PolicyTypeIngress,
			objs:      []client.Object{ingress, newPolicy("duplicate", networkingv1.PolicyTypeIngress), egress},
			wantErr:   ErrDuplicateTarget,
		},
		{
			name:      "other namespace and other target are ignored",
			direction: networkingv1.PolicyTypeIngress,
			objs:      []client.Object{ingress, otherNamespace, otherTarget},
			wantName:  ingress.Name,
		},
		{
			name:      "opposite direction with an invalid spec is ignored",
			direction: networkingv1.PolicyTypeIngress,
			objs:      []client.Object{ingress, invalidEgress},
			wantName:  ingress.Name,
		},
		{
			name:      "no WNP targets the workload",
			direction: networkingv1.PolicyTypeIngress,
			objs:      []client.Object{otherTarget},
			wantErr:   ErrTargetNotFound,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			scheme := runtime.NewScheme()
			require.NoError(t, securityv1alpha1.AddToScheme(scheme))
			builder := fake.NewClientBuilder().
				WithScheme(scheme).
				WithIndex(&securityv1alpha1.WorkloadNetworkPolicy{}, WNPTargetIndexField, IndexWNPByTarget)
			for _, obj := range tc.objs {
				builder.WithRuntimeObjects(obj.DeepCopyObject())
			}
			cl := builder.Build()

			got, err := ResolveDenyingPolicy(t.Context(), cl, wk, tc.direction)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Empty(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, types.NamespacedName{Namespace: testNamespace, Name: tc.wantName}, got)
		})
	}
}
