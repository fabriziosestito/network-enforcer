package e2e_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

const (
	wnpValidatingWebhookConfigurationName = "network-enforcer-validating-webhook-configuration"
	wnpWebhookName                        = "validate-workloadnetworkpolicies.kubewarden.io"
	wnpDuplicateTarget                    = "webhook-e2e-target"
	wnpDuplicateExistingName              = "existing"
	wnpDuplicateName                      = "duplicate"
)

func TestWorkloadNetworkPolicyDuplicateTargetWebhook(t *testing.T) {
	feature := features.New("WorkloadNetworkPolicy admission webhook rejects a duplicate targetRef and direction").
		Setup(setupTestNamespace).
		Assess("Create the first WorkloadNetworkPolicy",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				wnp := newDuplicateTestWNP(getNamespace(ctx), wnpDuplicateExistingName)
				require.NoError(t, getSecurityV1Alpha1Client(ctx).Create(ctx, wnp))
				return ctx
			}).
		Assess("Reject a duplicate naming the existing WorkloadNetworkPolicy", assessDuplicateWNPRejected).
		Assess("Admit an update to the existing WorkloadNetworkPolicy",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := getSecurityV1Alpha1Client(ctx)
				var wnp securityv1alpha1.WorkloadNetworkPolicy
				require.NoError(t, r.Get(ctx, wnpDuplicateExistingName, getNamespace(ctx), &wnp))
				wnp.Spec.Mode = securityv1alpha1.WorkloadNetworkPolicyModeProtect
				require.NoError(t, r.Update(ctx, &wnp))
				return ctx
			}).
		Teardown(teardownTestNamespace).
		Feature()

	testEnv.Test(t, feature)
}

// assessDuplicateWNPRejected retries until the webhook's cache has observed the
// first object. The webhook is advisory, so a duplicate admitted during that
// window is deleted before the next attempt.
func assessDuplicateWNPRejected(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	r := getSecurityV1Alpha1Client(ctx)
	namespace := getNamespace(ctx)

	var rejection error
	require.Eventually(t, func() bool {
		err := r.Create(ctx, newDuplicateTestWNP(namespace, wnpDuplicateName))
		if err == nil {
			deleteErr := r.Delete(ctx, newDuplicateTestWNP(namespace, wnpDuplicateName))
			if deleteErr != nil && !apierrors.IsNotFound(deleteErr) {
				t.Logf("failed to delete admitted duplicate: %v", deleteErr)
			}
			return false
		}
		rejection = err
		return apierrors.IsInvalid(err)
	}, defaultOperationTimeout, time.Second, "duplicate WorkloadNetworkPolicy was never rejected")

	msg := rejection.Error()
	require.Contains(t, msg, wnpWebhookName)
	require.Contains(t, msg, "is already taken by WorkloadNetworkPolicy "+namespace+"/"+wnpDuplicateExistingName,
		"rejection must name the existing object")
	require.Contains(t, msg, "Deployment/"+wnpDuplicateTarget, "rejection must name the target")

	var dup securityv1alpha1.WorkloadNetworkPolicy
	err := r.Get(ctx, wnpDuplicateName, namespace, &dup)
	require.True(t, apierrors.IsNotFound(err), "duplicate must not exist, got %v", err)
	return ctx
}

func newDuplicateTestWNP(namespace, name string) *securityv1alpha1.WorkloadNetworkPolicy {
	return &securityv1alpha1.WorkloadNetworkPolicy{
		Namespace: namespace,
		Name:      name,
		Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
			Mode: securityv1alpha1.WorkloadNetworkPolicyModeMonitor,
			WorkloadTargetingSpec: securityv1alpha1.WorkloadTargetingSpec{
				TargetRef: securityv1alpha1.WorkloadTargetRef{
					Kind: securityv1alpha1.WorkloadKindDeployment,
					Name: wnpDuplicateTarget,
				},
				Direction: networkingv1.PolicyTypeIngress,
			},
			PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
				Backend: securityv1alpha1.PolicyBackendKubernetes,
				Kubernetes: &networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": wnpDuplicateTarget}},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				},
			},
		},
	}
}
