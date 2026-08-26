package main

import (
	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-runtimes/runtime"
)

// specialistTurn resolves one Page Candidate Specialist turn.
//
// The Specialist produces a bounded page candidate and returns it as a final
// decision with its artifact outputs. It cannot delegate — a Specialist that
// could delegate would be a Manager — and it cannot finalize, approve, or
// commit anything it produced: the candidate is a proposal Agent Service
// validates.
type specialistTurn struct{}

func (t *specialistTurn) Decide(
	task schema.AgentTask,
	boundary *runtime.Boundary,
) (schema.AgentRuntimeResultTurnDecision, runtime.Usage, []runtime.Diagnostic, error) {
	if _, forbidden := task.Parameters["delegate"]; forbidden {
		// A Specialist is a bounded reasoning unit. Delegation is the Manager's
		// and only through Agent Service.
		return schema.AgentRuntimeResultTurnDecision{}, runtime.Usage{}, nil,
			boundary.Peer("delegation is not a Specialist decision")
	}

	decision := schema.AgentRuntimeResultTurnDecision{
		Decision: schema.AgentRuntimeResultTurnDecisionDecisionFinal,
		Payload: schema.SharedPrimitivesBoundedStringMap{
			"produced": "page-candidate",
		},
		// The candidate travels as an artifact reference the control plane
		// records. The Specialist does not store it and cannot finalize it.
		ArtifactOutputs: []schema.SharedPrimitivesArtifactReference{},
	}
	return decision, runtime.Usage{}, nil, nil
}
