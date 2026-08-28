package main

import (
	"context"
	"encoding/json"
	"strconv"
	"unicode/utf8"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-runtimes/runtime"
)

// managerTurn resolves one Page Change Manager turn.
//
// The Manager decides; it does not act. It has two shapes of turn and no
// others. Before a Specialist has run it compiles the task-scoped context it
// was given, asks the governed Model Gateway for a bounded plan, and returns
// the one governed decision that plan resolves to — for a page change, a
// request that Agent Service route the Page Candidate Specialist. After a
// Specialist has run, the task carries that outcome, and the Manager validates
// it and terminates the turn without asking the model anything: there is
// nothing left to decide, and a model call on a settled outcome would be
// spending budget to re-derive a fact the control plane already holds.
//
// That split is also what bounds delegation to one. The second turn never
// reaches a plan, so there is no path on which a model's proposal can produce a
// second delegation, and the first turn refuses a plan that asks for one.
type managerTurn struct{}

const (
	// The supplied context keys a Manager reads. Agent Service writes the
	// outcome of a delegation into the task it dispatches for the next turn;
	// the Manager does not remember it, because a runtime that remembered
	// anything between attempts would be holding state the control plane
	// cannot fence.
	keyDelegationState      = "delegation.state"
	keyDelegationDelegate   = "delegation.delegate"
	keyDelegationReasonCode = "delegation.reasonCode"
	keyDelegationCandidate  = "delegation.candidate"

	delegationCompleted = "completed"
	delegationFailed    = "failed"
	delegationRefused   = "refused"
	delegationPending   = "pending"
)

func (t *managerTurn) Decide(
	ctx context.Context,
	task schema.AgentTask,
	session *runtime.Session,
) (schema.AgentRuntimeResultTurnDecision, error) {
	brief := runtime.ReadBrief(task)

	// A Manager that wanted to call the Specialist directly would find this
	// refusal rather than a client. Delegation travels back as a decision.
	if _, forbidden := brief.Value("callSpecialistDirectly"); forbidden {
		return schema.AgentRuntimeResultTurnDecision{}, session.Boundary().Peer(permittedDelegate)
	}

	if state, present := brief.Value(keyDelegationState); present {
		return t.conclude(brief, session, state)
	}
	return t.propose(ctx, task, brief, session)
}

// propose asks the governed model for a bounded plan and returns the governed
// decision it resolves to.
func (t *managerTurn) propose(
	ctx context.Context,
	task schema.AgentTask,
	brief *runtime.Brief,
	session *runtime.Session,
) (schema.AgentRuntimeResultTurnDecision, error) {
	prompt, err := brief.GovernedPrompt("model.plan")
	if err != nil {
		return schema.AgentRuntimeResultTurnDecision{}, err
	}
	completion, err := session.Model(ctx, task, prompt)
	if err != nil {
		return schema.AgentRuntimeResultTurnDecision{}, err
	}
	proposed, err := readPlan(completion)
	if err != nil {
		return schema.AgentRuntimeResultTurnDecision{}, err
	}
	return t.resolve(proposed.Steps[0])
}

// resolve maps one validated plan step onto the governed decision vocabulary.
//
// Nothing here widens what the step said. A step naming a tool becomes a tool
// *proposal*, which Tool Guard then holds to the definition's pinned profile; a
// step naming a delegate becomes a delegation *request*, which Agent Service
// routes or refuses. The Manager never executes either.
func (t *managerTurn) resolve(step planStep) (schema.AgentRuntimeResultTurnDecision, error) {
	switch step.Action {
	case actionDelegate:
		if step.Delegate != permittedDelegate {
			// The delegate is named by its definition — the identity the
			// Manager's own pinned allowed-delegate set is written in — and P0
			// permits exactly one. A model naming any other, including a
			// runtime unit rather than a definition, is asking this release for
			// authority it does not have.
			return schema.AgentRuntimeResultTurnDecision{}, runtime.RefuseProposal(runtime.ProposalDelegateNotPermitted)
		}
		input := "{}"
		if len(step.Input) > 0 {
			if !json.Valid(step.Input) {
				return schema.AgentRuntimeResultTurnDecision{}, runtime.RefuseProposal(runtime.ProposalIncomplete)
			}
			input = string(step.Input)
		}
		// The delegation input travels in the bounded decision payload, whose
		// values are capped at 1024 characters. A specialist brief longer than
		// that is split into the indexed continuation Agent Service reassembles
		// (`input`, or `input.0`, `input.1`, …), the same convention the
		// supplied context and model output use. Splitting here keeps the
		// signed result decodable rather than producing a payload value no
		// canonical consumer can read.
		payload := map[string]string{
			"delegate": permittedDelegate,
			"reason":   "a page change requires a bounded page candidate from the Page Candidate Specialist",
		}
		for key, value := range chunkedPayloadValue("input", input) {
			payload[key] = value
		}
		return decision(schema.AgentRuntimeResultTurnDecisionDecisionDelegateAgent, payload, nil)
	case actionToolCall:
		if step.Tool == "" || len(step.Arguments) == 0 || !json.Valid(step.Arguments) {
			return schema.AgentRuntimeResultTurnDecision{}, runtime.RefuseProposal(runtime.ProposalIncomplete)
		}
		return decision(schema.AgentRuntimeResultTurnDecisionDecisionToolCall, map[string]string{
			"tool":      step.Tool,
			"arguments": string(step.Arguments),
		}, nil)
	case actionNeedInput:
		if step.Question == "" {
			return schema.AgentRuntimeResultTurnDecision{}, runtime.RefuseProposal(runtime.ProposalIncomplete)
		}
		return decision(schema.AgentRuntimeResultTurnDecisionDecisionNeedInput, map[string]string{
			"question": step.Question,
		}, nil)
	case actionContinue:
		return decision(schema.AgentRuntimeResultTurnDecisionDecisionContinue, map[string]string{
			"note": step.Note,
		}, nil)
	case actionRefuse:
		if step.Reason == "" {
			return schema.AgentRuntimeResultTurnDecision{}, runtime.RefuseProposal(runtime.ProposalIncomplete)
		}
		return decision(schema.AgentRuntimeResultTurnDecisionDecisionRefuse, map[string]string{
			"reason": step.Reason,
		}, nil)
	case actionFinal:
		// A Manager cannot finish a page change out of its own reasoning: a
		// final decision names a candidate artifact, and the Manager produces
		// none. Reaching final without a Specialist outcome means the model
		// proposed a conclusion nothing produced.
		return schema.AgentRuntimeResultTurnDecision{}, runtime.RefuseProposal(runtime.ProposalIncomplete)
	default:
		return schema.AgentRuntimeResultTurnDecision{}, runtime.RefuseProposal(runtime.ProposalOutsideVocabulary)
	}
}

// conclude validates a Specialist outcome and terminates the turn.
//
// The Manager validates what it is told about the delegation against what the
// control plane pinned into the task: the delegate it actually asked for, and a
// candidate artifact that is one of the task's own pinned inputs. A Manager that
// accepted an artifact reference the task did not carry would be finalizing a
// document nobody dispatched to it.
func (t *managerTurn) conclude(
	brief *runtime.Brief,
	session *runtime.Session,
	state string,
) (schema.AgentRuntimeResultTurnDecision, error) {
	switch state {
	case delegationPending:
		return decision(schema.AgentRuntimeResultTurnDecisionDecisionContinue, map[string]string{
			"note": "the delegated page candidate is still being produced",
		}, nil)
	case delegationRefused:
		reason, err := brief.Required(keyDelegationReasonCode)
		if err != nil {
			return schema.AgentRuntimeResultTurnDecision{}, err
		}
		return decision(schema.AgentRuntimeResultTurnDecisionDecisionRefuse, map[string]string{
			"reason": reason,
		}, nil)
	case delegationFailed:
		reason, err := brief.Required(keyDelegationReasonCode)
		if err != nil {
			return schema.AgentRuntimeResultTurnDecision{}, err
		}
		// The Specialist did not answer. That is a failure of this turn under
		// the Specialist's own governed reason, not a refusal: the pinned
		// policy declined nothing, and the control plane decides whether the
		// work is tried again. A refusal here would turn an unavailable model
		// path into a policy decision nobody made.
		return schema.AgentRuntimeResultTurnDecision{}, &runtime.DelegationFailedError{ReasonCode: reason}
	case delegationCompleted:
	default:
		return schema.AgentRuntimeResultTurnDecision{}, &runtime.ContextError{Key: keyDelegationState}
	}

	delegate, err := brief.Required(keyDelegationDelegate)
	if err != nil {
		return schema.AgentRuntimeResultTurnDecision{}, err
	}
	if delegate != permittedDelegate {
		// An outcome attributed to a delegate this release never asks for is
		// not this Manager's delegation, whatever produced it.
		return schema.AgentRuntimeResultTurnDecision{}, runtime.RefuseProposal(runtime.ProposalDelegateNotPermitted)
	}
	candidate, err := brief.ArtifactReference(keyDelegationCandidate)
	if err != nil {
		return schema.AgentRuntimeResultTurnDecision{}, err
	}
	pinned, present := brief.ArtifactInput(string(candidate.ArtifactId))
	if !present || pinned.Digest != candidate.Digest || pinned.SizeBytes != candidate.SizeBytes {
		return schema.AgentRuntimeResultTurnDecision{}, &runtime.ContextError{Key: keyDelegationCandidate}
	}
	session.Note("RUNTIME_DELEGATION_VALIDATED", "the delegated candidate is one of this task's pinned artifact inputs")
	return decision(schema.AgentRuntimeResultTurnDecisionDecisionFinal, map[string]string{
		"summary":  "the Page Candidate Specialist produced the page candidate for this change",
		"delegate": permittedDelegate,
	}, []schema.SharedPrimitivesArtifactReference{pinned})
}

// decision renders one governed decision. Artifact outputs are always a list,
// never nil: the contract requires the member, and an omitted array and an
// empty one are not the same document.
//
// The payload is held to the canonical bounds here, where every decision
// passes, rather than trusted to fit. Most of what reaches it is text the
// model controls — a tool's arguments, a question, a note, a refusal reason —
// and a value the bounded map does not admit would make the unit sign a
// document the contract calls invalid. It is refused rather than cut down: a
// truncated argument is a different proposal from the one the model made.
func decision(
	kind schema.AgentRuntimeResultTurnDecisionDecision,
	payload map[string]string,
	outputs []schema.SharedPrimitivesArtifactReference,
) (schema.AgentRuntimeResultTurnDecision, error) {
	if outputs == nil {
		outputs = []schema.SharedPrimitivesArtifactReference{}
	}
	bounded := schema.SharedPrimitivesBoundedStringMap{}
	for key, value := range payload {
		if value == "" {
			continue
		}
		if utf8.RuneCountInString(value) > maximumPayloadValueRunes {
			return schema.AgentRuntimeResultTurnDecision{}, runtime.RefuseProposal(runtime.ProposalOutsideBounds)
		}
		bounded[key] = value
	}
	if len(bounded) > maximumPayloadMembers {
		return schema.AgentRuntimeResultTurnDecision{}, runtime.RefuseProposal(runtime.ProposalOutsideBounds)
	}
	return schema.AgentRuntimeResultTurnDecision{Decision: kind, Payload: bounded, ArtifactOutputs: outputs}, nil
}

// maximumPayloadMembers is the member bound the bounded decision payload
// enforces.
const maximumPayloadMembers = 32

// maximumPayloadValueRunes is the per-value bound the bounded decision payload
// enforces.
const maximumPayloadValueRunes = 1024

// chunkedPayloadValue returns the payload members that carry one value: the key
// alone when it fits one bound, or `key.0`, `key.1`, … on rune boundaries when
// it does not.
func chunkedPayloadValue(key, value string) map[string]string {
	runes := []rune(value)
	if len(runes) <= maximumPayloadValueRunes {
		return map[string]string{key: value}
	}
	chunks := map[string]string{}
	index := 0
	for start := 0; start < len(runes); start += maximumPayloadValueRunes {
		end := start + maximumPayloadValueRunes
		if end > len(runes) {
			end = len(runes)
		}
		chunks[key+"."+strconv.Itoa(index)] = string(runes[start:end])
		index++
	}
	return chunks
}
