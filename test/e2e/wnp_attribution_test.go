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
	directionIngressPolicyName = "attribution-ingress"
	directionEgressPolicyName  = "attribution-egress"
	missingTargetPolicyName    = "missing-target"
	missingTargetDeployment    = "does-not-exist"
)

func TestWorkloadNetworkPolicyDirectionAttribution(t *testing.T) {
	if !loadSuiteConfig().IsKubernetesProvider() {
		t.Skip("Skipping direction attribution test: the Istio backend only supports the Ingress direction")
	}

	feature := features.New("Both directions of one Deployment are attributed distinctly").
		Setup(setupTestNamespace).
		Setup(setupSimpleAppWorkload).
		Assess("Create ingress and egress policies sharing the target selector", assessCreateDirectionPolicies).
		Assess("Both policies report a valid selector scope", assessDirectionPoliciesReady).
		Assess("Attribute the ingress violation to the ingress policy", assessIngressAttribution).
		Assess("Attribute the egress violation to the egress policy", assessEgressAttribution).
		Teardown(teardownSimpleAppWorkload).
		Teardown(teardownTestNamespace).
		Feature()

	testEnv.Test(t, feature)
}

func TestWorkloadNetworkPolicyUnattributedViolation(t *testing.T) {
	feature := features.New("A violation whose target has no policy is counted as unattributed").
		Setup(setupTestNamespace).
		Setup(labelNamespaceAmbient).
		Setup(setupSimpleAppWorkload).
		Assess("Allow traffic to the violating port before any policy exists", assessViolatingPortAllowed).
		Assess("Deny the traffic with a policy for a missing target", assessUnattributedViolation).
		Assess("Keep the violation off the policy for the missing target", assessMissingTargetPolicyHasNoViolation).
		Teardown(teardownSimpleAppWorkload).
		Teardown(teardownTestNamespace).
		Feature()

	testEnv.Test(t, feature)
}

func assessCreateDirectionPolicies(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	createCorrelationWNP(ctx, t, correlationWNPSpec{
		name:        directionIngressPolicyName,
		targetName:  simpleAppServerDeploymentName,
		direction:   networkingv1.PolicyTypeIngress,
		mode:        securityv1alpha1.WorkloadNetworkPolicyModeProtect,
		selector:    map[string]string{correlationAppLabel: simpleAppServerDeploymentName},
		allowedPort: simpleAppTCPServicePort,
	})
	createCorrelationWNP(ctx, t, correlationWNPSpec{
		name:        directionEgressPolicyName,
		targetName:  simpleAppServerDeploymentName,
		direction:   networkingv1.PolicyTypeEgress,
		mode:        securityv1alpha1.WorkloadNetworkPolicyModeProtect,
		selector:    map[string]string{correlationAppLabel: simpleAppServerDeploymentName},
		allowedPort: 0,
	})
	return ctx
}

func assessDirectionPoliciesReady(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	requireWNPCondition(ctx, t, directionIngressPolicyName, metav1.ConditionTrue, reasonSelectorScopeValid, "")
	requireWNPCondition(ctx, t, directionEgressPolicyName, metav1.ConditionTrue, reasonSelectorScopeValid, "")

	ingress := getNetworkPolicy(ctx, t, directionIngressPolicyName)
	egress := getNetworkPolicy(ctx, t, directionEgressPolicyName)
	require.Equal(t, ingress.Spec.PodSelector, egress.Spec.PodSelector,
		"both policies must render the same selector")
	return ctx
}

func assessIngressAttribution(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	assertIngressViolationAttributed(ctx, t, directionIngressPolicyName)
	assertNoIngressViolation(ctx, t, directionEgressPolicyName)
	return ctx
}

func assessEgressAttribution(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	assertEgressViolationAttributed(ctx, t, directionEgressPolicyName)
	assertNoEgressViolation(ctx, t, directionIngressPolicyName)
	return ctx
}

func assessViolatingPortAllowed(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	return assertPacketSentFromClient(ctx, t, corev1.ProtocolTCP, simpleAppViolatingServicePort)
}

func assessUnattributedViolation(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	grantMetricsAccess(ctx, t)
	provider := expectedMetricProvider(ctx)
	baseline, identity := stableUnattributedTotal(ctx, t, provider, unattributedReasonNoTarget)

	createCorrelationWNP(ctx, t, correlationWNPSpec{
		name:        missingTargetPolicyName,
		targetName:  missingTargetDeployment,
		direction:   networkingv1.PolicyTypeIngress,
		mode:        securityv1alpha1.WorkloadNetworkPolicyModeProtect,
		selector:    map[string]string{correlationAppLabel: simpleAppServerDeploymentName},
		allowedPort: simpleAppTCPServicePort,
	})
	requireWNPCondition(ctx, t, missingTargetPolicyName, metav1.ConditionFalse, reasonSelectorOverlaps,
		fmt.Sprintf("Deployment %s/%s", getNamespace(ctx), simpleAppServerDeploymentName))
	requireProtectPolicyRendered(ctx, t, missingTargetPolicyName)

	assertPacketBlockedFromClient(ctx, t, corev1.ProtocolTCP, simpleAppViolatingServicePort)
	requireUnattributedTotalIncreased(
		ctx, t, provider, unattributedReasonNoTarget, baseline, identity,
		func() { sendClientTrafficToPort(ctx, simpleAppViolatingServicePort) },
	)
	return ctx
}

func assessMissingTargetPolicyHasNoViolation(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	requireNoViolationMatching(ctx, t, missingTargetPolicyName,
		func(securityv1alpha1.ViolationRecord) bool { return true },
		"the policy targeting a missing workload must not own any violation")
	return ctx
}
