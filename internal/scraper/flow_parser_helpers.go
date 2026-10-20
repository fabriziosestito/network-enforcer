package scraper

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	networkingv1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
	"github.com/kubewarden/network-enforcer/internal/types"
	"github.com/kubewarden/network-enforcer/internal/violation"
	"github.com/kubewarden/network-enforcer/internal/workload"
)

var (
	errUnsupportedProtocol   = errors.New("unsupported protocol")
	errEndpointHasNoWorkload = errors.New("endpoint has no associated workload")
	errSkipWorkload          = errors.New("endpoint has no supported workload")
	errPortOutOfRange        = errors.New("port is out of range")
)

const (
	minValidPort = 1
	maxValidPort = 65535
)

type flowPort interface {
	~int64 | ~uint32
}

// portToInt32 narrows a port reported by a CNI flow API to int32, the range check avoids a gosec suppression.
// A port of 0 is accepted because it is the value the flow APIs report when the port is unavailable.
func portToInt32[T flowPort](port T) (int32, error) {
	if port < 0 || port > maxValidPort {
		return 0, fmt.Errorf("%w: %d", errPortOutOfRange, port)
	}
	return int32(port), nil
}

// parsePort parses a port coming from a string attribute and validates it against the 1 - 65535 range.
func parsePort(port string) (int32, error) {
	parsed, err := strconv.ParseInt(port, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("cannot parse port %q: %w", port, err)
	}
	if parsed < minValidPort || parsed > maxValidPort {
		return 0, fmt.Errorf("%w: %d", errPortOutOfRange, parsed)
	}
	return portToInt32(parsed)
}

type processFlowOutcome int

const (
	processFlowOutcomeSkip processFlowOutcome = iota
	processFlowOutcomeEnqueue
	processFlowOutcomeViolation
	processFlowOutcomeError
)

type processFlowResult struct {
	outcome     processFlowOutcome
	event       types.LearningEvent
	observation violation.Observation
	err         error
}

func processFlowSkip() processFlowResult {
	return processFlowResult{outcome: processFlowOutcomeSkip}
}

func processFlowEnqueue(event types.LearningEvent) processFlowResult {
	return processFlowResult{outcome: processFlowOutcomeEnqueue, event: event}
}

func processFlowRecordViolation(observation violation.Observation) processFlowResult {
	return processFlowResult{outcome: processFlowOutcomeViolation, observation: observation}
}

func processFlowError(err error) processFlowResult {
	return processFlowResult{outcome: processFlowOutcomeError, err: err}
}

func resolveOutcome(role string, err error) processFlowResult {
	if errors.Is(err, errSkipWorkload) {
		return processFlowSkip()
	}
	return processFlowError(fmt.Errorf("cannot resolve %s workload: %w", role, err))
}

// resolveViolationDenyingPolicy fills in the WorkloadNetworkPolicy targeting the
// violation subject when the provider did not report a policy. It is
// best-effort: when no WNP targets the subject, several do, or the lookup fails,
// the policy stays empty and the observation is kept, so it is still logged and
// buffered. The controller then attributes it or counts it as unattributed with
// the reason.
func resolveViolationDenyingPolicy(
	ctx context.Context,
	c client.Reader,
	observation *violation.Observation,
) {
	if observation.DenyingPolicyName != "" {
		// Calico could have already resolved the policy name
		// so we do that only if necessary
		return
	}
	// this is the correct workload if the direction is egress
	ref := &observation.Source
	if observation.Direction == networkingv1.PolicyTypeIngress {
		ref = &observation.Dest
	}

	policy, err := workload.ResolveDenyingPolicy(ctx, c, ref, observation.Direction)
	if err != nil {
		return
	}

	observation.DenyingPolicyName = policy.Name
	observation.DenyingPolicyNamespace = policy.Namespace
}

func resolveParsedFlow(
	ctx context.Context,
	resolveWorkload func(context.Context, *securityv1alpha1.WorkloadRef) error,
	c client.Reader,
	parsed processFlowResult,
) processFlowResult {
	switch parsed.outcome {
	case processFlowOutcomeEnqueue:
		if err := resolveWorkload(ctx, parsed.event.Source); err != nil {
			return resolveOutcome("source", err)
		}
		if err := resolveWorkload(ctx, parsed.event.Dest); err != nil {
			return resolveOutcome("destination", err)
		}
	case processFlowOutcomeViolation:
		// The subject (the workload the policy selects) must resolve. The peer is
		// resolved best-effort: an off-cluster or unresolvable peer keeps its raw
		// value so the violation is still recorded.
		subject, subjectRole, peer := &parsed.observation.Source, "source", &parsed.observation.Dest
		if parsed.observation.Direction == networkingv1.PolicyTypeIngress {
			subject, subjectRole, peer = &parsed.observation.Dest, "destination", &parsed.observation.Source
		}
		if err := resolveWorkload(ctx, subject); err != nil {
			return resolveOutcome(subjectRole, err)
		}
		_ = resolveWorkload(ctx, peer)
		resolveViolationDenyingPolicy(ctx, c, &parsed.observation)
	case processFlowOutcomeError, processFlowOutcomeSkip:
	}

	return parsed
}

func completeSelector(ctx context.Context, c client.Client, ref *securityv1alpha1.WorkloadRef) error {
	if err := workload.LookupPodSelectorForWorkload(ctx, c, ref); err != nil {
		return fmt.Errorf("failed to lookup pod selector for workload %q: %w", ref.OwnerName, err)
	}
	return nil
}
