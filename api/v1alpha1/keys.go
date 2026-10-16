package v1alpha1

const (
	// ProposalPromoteLabelKey is set on a WorkloadNetworkPolicyProposal when it
	// is promoted to a WorkloadNetworkPolicy.
	// Valid values are WorkloadNetworkPolicyMode strings ("monitor", "protect").
	ProposalPromoteLabelKey = "networkenforcer.kubewarden.io/promote"

	// PolicyPromotedFromLabelKey is set on a WorkloadNetworkPolicy when it is
	// created by promoting a WorkloadNetworkPolicyProposal.
	PolicyPromotedFromLabelKey = "networkenforcer.kubewarden.io/promoted-from"

	// ViolationAcknowledgePrefix is the prefix of annotation key used to acknowledge a violation.
	// An annotation of the form networkenforcer.kubewarden.io/acknowledge-<id>: "<reason>" moves the
	// violation record with that ID into AcknowledgedViolations.
	ViolationAcknowledgePrefix = "networkenforcer.kubewarden.io/acknowledge-"

	// ManagedByLabelKey is the Kubernetes recommended label
	// (https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/)
	// identifying the tool used to manage an object. It is set on every
	// low level network policy (NetworkPolicy, Istio AuthorizationPolicy, ...)
	// rendered from a WorkloadNetworkPolicy.
	ManagedByLabelKey = "app.kubernetes.io/managed-by"

	// ManagedByLabelValue is the value of ManagedByLabelKey for objects
	// managed by network-enforcer.
	ManagedByLabelValue = "network-enforcer"
)
