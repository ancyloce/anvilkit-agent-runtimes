package main

import (
	"encoding/json"
	"strings"

	"github.com/ancyloce/anvilkit-agent-runtimes/runtime"
)

// The Manager's model does not act; it proposes. What arrives from the governed
// gateway is a bounded plan document, and everything in this file exists to
// decide whether that plan is something this release is permitted to carry out.
//
// The order matters: the plan is bounded before it is read, read before it is
// interpreted, and interpreted only into the governed decision vocabulary. A
// proposal that fails any of those becomes a typed refusal rather than a
// narrower version of itself, because silently narrowing a proposal is how a
// model's intent ends up half-executed.

const (
	// planOutputKey is where the governed output carries the plan. It is one
	// key by contract: a runtime that scanned the whole output for something
	// plan-shaped would be interpreting fields nobody agreed were a plan.
	planOutputKey = "plan"
	// planKind is the only document this Manager reads as a plan.
	planKind = "AgentPlan"
	// maximumPlanSteps bounds a plan. One turn resolves one decision; the rest
	// of a plan is intent the control plane will dispatch later turns for, and
	// a plan longer than this is not bounded reasoning.
	maximumPlanSteps = 4
	// permittedDelegate is the single Specialist a P0 Page Change Manager may
	// ask for. Agent Service holds the authoritative pinned allowed-delegate
	// set and checks the decision against it; this is the same limit stated on
	// the side that produces the proposal, so a model asking for a second
	// specialist is refused before a delegation is ever proposed.
	permittedDelegate = "definition.platform.page-candidate-specialist"
)

// plan is the bounded document a Manager turn reads from governed output.
type plan struct {
	Kind  string     `json:"kind"`
	Steps []planStep `json:"steps"`
}

// planStep is one proposed action. The fields are exactly what the governed
// decision vocabulary can carry: there is no field for a budget, a credential,
// an endpoint, or a capability, so a model cannot propose one in a well-formed
// plan — and a plan that carries one anyway is refused by readPlan rather than
// quietly ignored, because an ignored field is an intent nobody answered.
type planStep struct {
	Action    string          `json:"action"`
	Delegate  string          `json:"delegate,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	Tool      string          `json:"tool,omitempty"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
	Note      string          `json:"note,omitempty"`
	Question  string          `json:"question,omitempty"`
	Summary   string          `json:"summary,omitempty"`
	Reason    string          `json:"reason,omitempty"`
}

// The governed actions a plan step may name.
const (
	actionContinue  = "continue"
	actionNeedInput = "need_input"
	actionDelegate  = "delegate"
	actionFinal     = "final"
	actionRefuse    = "refuse"
	actionToolCall  = "tool_call"
)

// readPlan reads and bounds one proposal.
//
// Decoding is strict. A plan carrying members this type does not declare is a
// plan proposing something the vocabulary has no place for — the authority
// expansions worth worrying about all look like an extra field — so an unknown
// member is a refusal and not a field to skip.
func readPlan(completion runtime.Completion) (plan, error) {
	raw, present := completion.Value(planOutputKey)
	if !present {
		return plan{}, &runtime.ModelOutputError{Key: planOutputKey}
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var proposed plan
	if err := decoder.Decode(&proposed); err != nil {
		return plan{}, runtime.RefuseProposal(runtime.ProposalExpandsAuthority)
	}
	if proposed.Kind != planKind {
		return plan{}, &runtime.ModelOutputError{Key: planOutputKey}
	}
	if len(proposed.Steps) == 0 {
		return plan{}, runtime.RefuseProposal(runtime.ProposalIncomplete)
	}
	if len(proposed.Steps) > maximumPlanSteps {
		return plan{}, runtime.RefuseProposal(runtime.ProposalUnboundedPlan)
	}
	// A plan may propose at most one delegation, and only as its first step. A
	// model that queued two delegations would be asking for fan-out the release
	// does not have, and one that buried a delegation behind other steps would
	// be asking for a delegation this turn was never going to reach.
	for position, step := range proposed.Steps {
		if step.Action != actionDelegate {
			continue
		}
		if position != 0 {
			return plan{}, runtime.RefuseProposal(runtime.ProposalUnboundedPlan)
		}
		if len(proposed.Steps) > 1 && hasFurtherDelegation(proposed.Steps[1:]) {
			return plan{}, runtime.RefuseProposal(runtime.ProposalDelegationExhausted)
		}
	}
	return proposed, nil
}

// hasFurtherDelegation reports whether any of the remaining steps delegates.
func hasFurtherDelegation(steps []planStep) bool {
	for _, step := range steps {
		if step.Action == actionDelegate {
			return true
		}
	}
	return false
}
