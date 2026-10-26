package e2e_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

const (
	stagedProtectPolicyName = "staged-protect"
	stagedCanaryPolicyName  = "staged-canary"
	stagedCanaryDeployment  = "http-canary"
)

// RFC 0005 (#509) keeps rendering the overlapping data-plane object, so the
// monitor sibling is enforced for the duration of the overlap. This feature
// covers the overlap condition and subject-based attribution, not non-enforcement.
func TestWorkloadNetworkPolicyStagedRollout(t *testing.T) {
	feature := features.New(
		"Violations of a monitor sibling selected by an overlapping protect policy are attributed to the sibling").
		Setup(setupTestNamespace).
		Setup(labelNamespaceAmbient).
		Setup(setupSimpleAppWorkload).
		Assess("Create a canary workload selected by the target policy", assessCreateStagedCanary).
		Assess("Create the protect and monitor policies", assessCreateStagedPolicies).
		Assess("Report the overlap on the protect policy", assessStagedOverlapCondition).
		Assess("Keep the canary policy in monitor mode", assessStagedCanaryMonitorState).
		Assess("Attribute enforced canary traffic to the canary policy", assessStagedAttribution).
		Assess("Keep the canary violation off the protect policy", assessStagedProtectHasNoCanaryViolation).
		Teardown(teardownSimpleAppWorkload).
		Teardown(teardownTestNamespace).
		Feature()

	testEnv.Test(t, feature)
}

func assessCreateStagedCanary(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	createCorrelationDeployment(ctx, t, stagedCanaryDeployment,
		map[string]string{correlationWorkloadLabel: stagedCanaryDeployment},
		map[string]string{
			correlationWorkloadLabel: stagedCanaryDeployment,
			correlationAppLabel:      simpleAppServerDeploymentName,
			correlationTierLabel:     correlationCanaryTier,
		},
		correlationListenerCommand())
	return ctx
}

func assessCreateStagedPolicies(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	createCorrelationWNP(ctx, t, correlationWNPSpec{
		name:        stagedProtectPolicyName,
		targetName:  simpleAppServerDeploymentName,
		direction:   networkingv1.PolicyTypeIngress,
		mode:        securityv1alpha1.WorkloadNetworkPolicyModeProtect,
		selector:    map[string]string{correlationAppLabel: simpleAppServerDeploymentName},
		allowedPort: simpleAppTCPServicePort,
	})
	createCorrelationWNP(ctx, t, correlationWNPSpec{
		name:       stagedCanaryPolicyName,
		targetName: stagedCanaryDeployment,
		direction:  networkingv1.PolicyTypeIngress,
		mode:       securityv1alpha1.WorkloadNetworkPolicyModeMonitor,
		selector: map[string]string{
			correlationAppLabel:  simpleAppServerDeploymentName,
			correlationTierLabel: correlationCanaryTier,
		},
		allowedPort: simpleAppTCPServicePort,
	})
	return ctx
}

func assessStagedOverlapCondition(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	requireWNPCondition(ctx, t, stagedProtectPolicyName, metav1.ConditionFalse, reasonSelectorOverlaps,
		fmt.Sprintf("Deployment %s/%s", getNamespace(ctx), stagedCanaryDeployment))
	return ctx
}

func assessStagedCanaryMonitorState(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	requireWNPCondition(ctx, t, stagedCanaryPolicyName, metav1.ConditionTrue, reasonSelectorScopeValid, "")
	requireMonitorPolicyState(ctx, t, stagedCanaryPolicyName)
	return ctx
}

func assessStagedAttribution(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	canaryIPs := readyPodIPs(ctx, t, map[string]string{
		correlationAppLabel:  simpleAppServerDeploymentName,
		correlationTierLabel: correlationCanaryTier,
	})
	require.Len(t, canaryIPs, 1, "expected exactly one canary pod")
	sendTrafficUntilViolation(
		ctx, t,
		func() { sendClientTrafficToPod(ctx, canaryIPs[0], simpleAppViolatingServicePort) },
		stagedCanaryPolicyName,
		func(violation securityv1alpha1.ViolationRecord) bool {
			return violation.Action == securityv1alpha1.WorkloadNetworkPolicyModeProtect &&
				violation.Protocol == corev1.ProtocolTCP &&
				violation.Dest.OwnerName == stagedCanaryDeployment &&
				violation.DenyingPolicyNamespace == getNamespace(ctx) &&
				violation.DenyingPolicyName == stagedCanaryPolicyName
		},
		"enforced violation of the canary workload",
	)
	return ctx
}

func assessStagedProtectHasNoCanaryViolation(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	requireNoViolationMatching(ctx, t, stagedProtectPolicyName,
		func(violation securityv1alpha1.ViolationRecord) bool {
			return violation.Dest.OwnerName == stagedCanaryDeployment
		},
		"the protect policy must not own violations of the monitor sibling workload",
	)
	return ctx
}
