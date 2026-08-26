package main

import (
	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-runtimes/runtime"
)

// managerTurn resolves one Page Change Manager turn.
//
// The Manager decides; it does not act. Its legal outcomes are the governed
// TurnDecision set, and the two that matter here are `delegate_agent` — a
// request that Agent Service route a Specialist — and `final`, when the turn
// needs no further work. It never produces the page candidate itself and never
// reaches the Specialist.
type managerTurn struct{}

func (t *managerTurn) Decide(
	task schema.AgentTask,
	boundary *runtime.Boundary,
) (schema.AgentRuntimeResultTurnDecision, runtime.Usage, []runtime.Diagnostic, error) {
	// A Manager that wanted to call the Specialist directly would find this
	// refusal rather than a client. Delegation travels back as a decision.
	if _, forbidden := task.Parameters["callSpecialistDirectly"]; forbidden {
		return schema.AgentRuntimeResultTurnDecision{}, runtime.Usage{}, nil,
			boundary.Peer("page-candidate-specialist")
	}

	decision := schema.AgentRuntimeResultTurnDecision{
		Decision: schema.AgentRuntimeResultTurnDecisionDecisionDelegateAgent,
		Payload: schema.SharedPrimitivesBoundedStringMap{
			// The delegate is named by its definition — the identity the
			// Manager's own allowedDelegates list is written in — not by a
			// runtime unit. Which unit serves that definition is Agent
			// Service's to resolve; a Manager that named a unit would be
			// selecting a runtime, which is not its to select.
			"delegate": "definition.platform.page-candidate-specialist",
			"reason":   "page-change requires a bounded page candidate from the Page Candidate Specialist",
		},
		ArtifactOutputs: []schema.SharedPrimitivesArtifactReference{},
	}
	return decision, runtime.Usage{}, nil, nil
}
