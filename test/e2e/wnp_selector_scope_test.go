package e2e_test

import (
	"context"
	"fmt"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

const (
	overlapTargetDeployment = "overlap-target"
	overlapCanaryDeployment = "overlap-canary"
	overlapTargetApp        = "web"
	overlapCanaryApp        = "web-canary"
	overlapPolicyName       = "overlap-policy"
)

func TestWorkloadNetworkPolicySelectorOverlap(t *testing.T) {
	feature := features.New("WorkloadNetworkPolicy reports a sibling workload selected by its policy").
		Setup(setupTestNamespace).
		Setup(labelNamespaceAmbient).
		Assess("Create workloads with overlapping pod labels", assessOverlappingWorkloads).
		Assess("Report the overlap on the Ready condition", assessOverlapCondition).
		Assess("Keep the data-plane object rendered", assessOverlapRendered).
		Assess("Clear the condition after relabelling the sibling", assessOverlapCleared).
		Teardown(teardownTestNamespace).
		Feature()

	testEnv.Test(t, feature)
}

func assessOverlappingWorkloads(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	createCorrelationDeployment(ctx, t, overlapTargetDeployment,
		map[string]string{correlationWorkloadLabel: overlapTargetDeployment},
		map[string]string{
			correlationWorkloadLabel: overlapTargetDeployment,
			correlationAppLabel:      overlapTargetApp,
		},
		[]string{"sleep", correlationSleepDuration})
	createCorrelationDeployment(ctx, t, overlapCanaryDeployment,
		map[string]string{correlationWorkloadLabel: overlapCanaryDeployment},
		map[string]string{
			correlationWorkloadLabel: overlapCanaryDeployment,
			correlationAppLabel:      overlapTargetApp,
		},
		[]string{"sleep", correlationSleepDuration})

	createCorrelationWNP(ctx, t, correlationWNPSpec{
		name:        overlapPolicyName,
		targetName:  overlapTargetDeployment,
		direction:   networkingv1.PolicyTypeIngress,
		mode:        securityv1alpha1.WorkloadNetworkPolicyModeProtect,
		selector:    map[string]string{correlationAppLabel: overlapTargetApp},
		allowedPort: 0,
	})
	return ctx
}

func assessOverlapCondition(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	requireWNPCondition(ctx, t, overlapPolicyName, metav1.ConditionFalse, reasonSelectorOverlaps,
		fmt.Sprintf("Deployment %s/%s", getNamespace(ctx), overlapCanaryDeployment))
	return ctx
}

func assessOverlapRendered(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	requireProtectPolicyRendered(ctx, t, overlapPolicyName)
	return ctx
}

func assessOverlapCleared(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	setDeploymentTemplateLabel(ctx, t, overlapCanaryDeployment, correlationAppLabel, overlapCanaryApp)
	requireWNPCondition(ctx, t, overlapPolicyName, metav1.ConditionTrue, reasonSelectorScopeValid, "")
	requireProtectPolicyRendered(ctx, t, overlapPolicyName)
	return ctx
}
