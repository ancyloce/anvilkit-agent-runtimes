package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-runtimes/runtime"
)

// The Manager decides and does not act. Two properties carry most of the risk:
// that a model's proposal cannot become authority the release does not have,
// and that delegation happens once. Everything below is one of those two.

func decide(t *testing.T, plane *governedPlane, task schema.AgentTask) (schema.AgentRuntimeResultTurnDecision, *runtime.Session, error) {
	t.Helper()
	session := plane.session(t)
	decision, err := (&managerTurn{}).Decide(context.Background(), task, session)
	return decision, session, err
}

func proposalRefusal(t *testing.T, err error) runtime.ProposalReason {
	t.Helper()
	var refused *runtime.ProposalError
	if !errors.As(err, &refused) {
		t.Fatalf("expected a proposal refusal, got %v", err)
	}
	return refused.Reason
}

func TestAPageChangeIsDelegatedToTheOnePermittedSpecialist(t *testing.T) {
	plane := planeServing(t, planOutput(`{"kind":"AgentPlan","steps":[{"action":"delegate","delegate":"definition.platform.page-candidate-specialist","input":{"intent":"refresh the hero"}}]}`))
	decision, session, err := decide(t, plane, managerTask(nil))
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Decision != schema.AgentRuntimeResultTurnDecisionDecisionDelegateAgent {
		t.Fatalf("decision = %q", decision.Decision)
	}
	// The delegate is named by its definition — the identity the pinned
	// allowed-delegate set is written in — not by a runtime unit. A Manager that
	// named a unit would be selecting a runtime, which is not its to select.
	if decision.Payload["delegate"] != "definition.platform.page-candidate-specialist" {
		t.Fatalf("delegate = %q", decision.Payload["delegate"])
	}
	if decision.Payload["input"] != `{"intent":"refresh the hero"}` {
		t.Fatalf("input = %q", decision.Payload["input"])
	}
	// Delegation is a decision, never a call: the Manager produced no artifact
	// and reached no peer.
	if len(decision.ArtifactOutputs) != 0 {
		t.Fatalf("a Manager produced an artifact: %+v", decision.ArtifactOutputs)
	}
	if usage := session.Usage(); usage.ModelCalls != 1 || usage.ToolCalls != 0 {
		t.Fatalf("usage = %+v", usage)
	}
}

func TestModelOutputCannotExpandDelegationAuthority(t *testing.T) {
	for name, testCase := range map[string]struct {
		plan string
		want runtime.ProposalReason
	}{
		"a delegate this release may not ask for": {
			`{"kind":"AgentPlan","steps":[{"action":"delegate","delegate":"definition.platform.component-spec-specialist"}]}`,
			runtime.ProposalDelegateNotPermitted,
		},
		"a runtime unit rather than a definition": {
			`{"kind":"AgentPlan","steps":[{"action":"delegate","delegate":"runtime.platform.page-candidate-specialist"}]}`,
			runtime.ProposalDelegateNotPermitted,
		},
		"two delegations in one plan": {
			`{"kind":"AgentPlan","steps":[{"action":"delegate","delegate":"definition.platform.page-candidate-specialist"},{"action":"delegate","delegate":"definition.platform.page-candidate-specialist"}]}`,
			runtime.ProposalDelegationExhausted,
		},
		"a delegation queued behind other work": {
			`{"kind":"AgentPlan","steps":[{"action":"continue","note":"first"},{"action":"delegate","delegate":"definition.platform.page-candidate-specialist"}]}`,
			runtime.ProposalUnboundedPlan,
		},
	} {
		t.Run(name, func(t *testing.T) {
			plane := planeServing(t, planOutput(testCase.plan))
			_, _, err := decide(t, plane, managerTask(nil))
			if got := proposalRefusal(t, err); got != testCase.want {
				t.Fatalf("reason = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestModelOutputCannotExpandToolsBudgetOrCredentials(t *testing.T) {
	for name, plan := range map[string]string{
		"a budget":       `{"kind":"AgentPlan","steps":[{"action":"continue"}],"budget":{"tokens":1000000}}`,
		"a credential":   `{"kind":"AgentPlan","steps":[{"action":"continue","credential":"provider-key"}]}`,
		"an endpoint":    `{"kind":"AgentPlan","steps":[{"action":"tool_call","tool":"x","arguments":{},"endpoint":"https://elsewhere"}]}`,
		"a capability":   `{"kind":"AgentPlan","steps":[{"action":"continue","capability":"provider.invoke"}]}`,
		"more delegates": `{"kind":"AgentPlan","steps":[{"action":"continue"}],"allowedDelegates":["definition.anything"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			// Authority arrives with the task or not at all. The interesting way
			// for a model to reach past its authority is an extra member, so an
			// unknown member is a refusal rather than a field to skip: a skipped
			// field is an intent nobody answered.
			plane := planeServing(t, planOutput(plan))
			_, _, err := decide(t, plane, managerTask(nil))
			if got := proposalRefusal(t, err); got != runtime.ProposalExpandsAuthority {
				t.Fatalf("reason = %q", got)
			}
		})
	}
}

func TestAPlanOutsideItsBoundsIsRefused(t *testing.T) {
	long := `{"kind":"AgentPlan","steps":[` +
		strings.Repeat(`{"action":"continue","note":"x"},`, maximumPlanSteps) +
		`{"action":"continue","note":"x"}]}`
	for name, testCase := range map[string]struct {
		plan string
		want runtime.ProposalReason
	}{
		"no steps":              {`{"kind":"AgentPlan","steps":[]}`, runtime.ProposalIncomplete},
		"more steps than bound": {long, runtime.ProposalUnboundedPlan},
		"an unknown action":     {`{"kind":"AgentPlan","steps":[{"action":"publish"}]}`, runtime.ProposalOutsideVocabulary},
		"a final with nothing to finalize": {
			`{"kind":"AgentPlan","steps":[{"action":"final","summary":"done"}]}`,
			runtime.ProposalIncomplete,
		},
		"a refusal with no reason": {`{"kind":"AgentPlan","steps":[{"action":"refuse"}]}`, runtime.ProposalIncomplete},
		"a question with no question": {
			`{"kind":"AgentPlan","steps":[{"action":"need_input"}]}`,
			runtime.ProposalIncomplete,
		},
		"a tool call with no arguments": {
			`{"kind":"AgentPlan","steps":[{"action":"tool_call","tool":"anvilkit.tool.context-echo"}]}`,
			runtime.ProposalIncomplete,
		},
	} {
		t.Run(name, func(t *testing.T) {
			plane := planeServing(t, planOutput(testCase.plan))
			_, _, err := decide(t, plane, managerTask(nil))
			if got := proposalRefusal(t, err); got != testCase.want {
				t.Fatalf("reason = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestOutputThatIsNotAPlanIsRefusedRatherThanSalvaged(t *testing.T) {
	for name, output := range map[string]map[string]string{
		"no plan at all":   {"prose": "I think we should refresh the hero"},
		"a different kind": planOutput(`{"kind":"Something","steps":[{"action":"continue"}]}`),
		"not a document":   planOutput(`refresh the hero`),
	} {
		t.Run(name, func(t *testing.T) {
			plane := planeServing(t, output)
			_, _, err := decide(t, plane, managerTask(nil))
			var invalid *runtime.ModelOutputError
			var refused *runtime.ProposalError
			if !errors.As(err, &invalid) && !errors.As(err, &refused) {
				t.Fatalf("unusable output was not refused: %v", err)
			}
		})
	}
}

func TestAToolCallIsProposedAndNeverExecuted(t *testing.T) {
	plane := planeServing(t, planOutput(`{"kind":"AgentPlan","steps":[{"action":"tool_call","tool":"anvilkit.tool.context-echo","arguments":{"query":"hero"}}]}`))
	decision, session, err := decide(t, plane, managerTask(nil))
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	// A tool step becomes a proposal Tool Guard then holds to the definition's
	// pinned profile. The Manager executes nothing, which shows as no tool call
	// against the attempt.
	if decision.Decision != schema.AgentRuntimeResultTurnDecisionDecisionToolCall {
		t.Fatalf("decision = %q", decision.Decision)
	}
	if decision.Payload["tool"] != "anvilkit.tool.context-echo" {
		t.Fatalf("tool = %q", decision.Payload["tool"])
	}
	if usage := session.Usage(); usage.ToolCalls != 0 {
		t.Fatalf("the Manager executed a tool: %+v", usage)
	}
}

// candidateReference is the artifact a completed delegation produced.
func candidateReference() schema.SharedPrimitivesArtifactReference {
	return schema.SharedPrimitivesArtifactReference{
		ArtifactId: "artifact.candidate.0001",
		Digest:     schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("a", 64)),
		MediaType:  "application/json",
		SizeBytes:  4096,
	}
}

// concludingTask is the next turn's dispatch: the delegation outcome the
// control plane recorded, and the candidate pinned as an artifact input.
func concludingTask(state string, overrides map[string]string) schema.AgentTask {
	reference := candidateReference()
	values := map[string]string{
		"delegation.state":                state,
		"delegation.delegate":             "definition.platform.page-candidate-specialist",
		"delegation.candidate.artifactId": string(reference.ArtifactId),
		"delegation.candidate.digest":     string(reference.Digest),
		"delegation.candidate.mediaType":  reference.MediaType,
		"delegation.candidate.sizeBytes":  "4096",
	}
	for key, value := range overrides {
		values[key] = value
	}
	return managerTask(values, reference)
}

func TestASettledDelegationIsConcludedWithoutAskingTheModelAgain(t *testing.T) {
	plane := planeServing(t, planOutput(`{"kind":"AgentPlan","steps":[{"action":"delegate","delegate":"definition.platform.page-candidate-specialist"}]}`))
	decision, session, err := decide(t, plane, concludingTask("completed", nil))
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Decision != schema.AgentRuntimeResultTurnDecisionDecisionFinal {
		t.Fatalf("decision = %q", decision.Decision)
	}
	if len(decision.ArtifactOutputs) != 1 || decision.ArtifactOutputs[0].ArtifactId != "artifact.candidate.0001" {
		t.Fatalf("artifact outputs = %+v", decision.ArtifactOutputs)
	}
	// This is what bounds delegation to one. The concluding turn never reaches
	// a plan, so there is no path on which a model proposal can produce a second
	// delegation — and no budget is spent re-deriving a fact the control plane
	// already holds.
	if plane.asked != 0 {
		t.Fatalf("the model was asked %d times on a settled outcome", plane.asked)
	}
	if usage := session.Usage(); usage.ModelCalls != 0 {
		t.Fatalf("usage = %+v", usage)
	}
}

func TestAnOutcomeTheTaskDidNotPinIsNotFinalized(t *testing.T) {
	for name, testCase := range map[string]struct {
		task   schema.AgentTask
		expect string
	}{
		"a candidate the task never carried": {
			concludingTask("completed", map[string]string{
				"delegation.candidate.artifactId": "artifact.elsewhere.0001",
			}),
			"context",
		},
		"a candidate whose digest does not match the pin": {
			concludingTask("completed", map[string]string{
				"delegation.candidate.digest": "sha256:" + strings.Repeat("9", 64),
			}),
			"context",
		},
		"an outcome attributed to another delegate": {
			concludingTask("completed", map[string]string{
				"delegation.delegate": "definition.platform.component-spec-specialist",
			}),
			"proposal",
		},
		"a state outside the vocabulary": {
			concludingTask("invented", nil),
			"context",
		},
	} {
		t.Run(name, func(t *testing.T) {
			plane := planeServing(t, planOutput(`{"kind":"AgentPlan","steps":[{"action":"continue"}]}`))
			_, _, err := decide(t, plane, testCase.task)
			var missing *runtime.ContextError
			var refused *runtime.ProposalError
			switch testCase.expect {
			case "context":
				if !errors.As(err, &missing) {
					t.Fatalf("expected a context refusal, got %v", err)
				}
			default:
				if !errors.As(err, &refused) {
					t.Fatalf("expected a proposal refusal, got %v", err)
				}
			}
			if plane.asked != 0 {
				t.Fatal("a settled outcome consulted the model")
			}
		})
	}
}

func TestAFailedDelegationTerminatesTheTurnWithItsGovernedReason(t *testing.T) {
	t.Run("refused", func(t *testing.T) {
		// The Specialist declined under the pinned policy: the Manager's turn
		// refuses with that governed reason.
		task := concludingTask("refused", map[string]string{"delegation.reasonCode": "RUNTIME_REFUSED_BY_GUARDRAIL"})
		plane := planeServing(t, planOutput(`{"kind":"AgentPlan","steps":[{"action":"continue"}]}`))
		decision, _, err := decide(t, plane, task)
		if err != nil {
			t.Fatalf("decide: %v", err)
		}
		if decision.Decision != schema.AgentRuntimeResultTurnDecisionDecisionRefuse {
			t.Fatalf("decision = %q", decision.Decision)
		}
		if decision.Payload["reason"] != "RUNTIME_REFUSED_BY_GUARDRAIL" {
			t.Fatalf("reason = %q", decision.Payload["reason"])
		}
	})
	t.Run("failed", func(t *testing.T) {
		// The Specialist did not answer: that is a failure of the Manager's
		// turn under the Specialist's own reason, not a policy refusal, so the
		// control plane may try the work again.
		task := concludingTask("failed", map[string]string{"delegation.reasonCode": "RUNTIME_MODEL_UNAVAILABLE"})
		plane := planeServing(t, planOutput(`{"kind":"AgentPlan","steps":[{"action":"continue"}]}`))
		_, _, err := decide(t, plane, task)
		var failed *runtime.DelegationFailedError
		if !errors.As(err, &failed) || failed.ReasonCode != "RUNTIME_MODEL_UNAVAILABLE" {
			t.Fatalf("a failed delegation was not reported as a failed turn: %v", err)
		}
	})
}

// A proposal the bounded decision payload cannot carry is refused rather than
// signed: a value longer than one bounded member admits, or a brief that
// would need more members than the contract admits, would otherwise make the
// unit sign a document the contract calls invalid.
func TestAProposalTheBoundedPayloadCannotCarryIsRefused(t *testing.T) {
	for name, plan := range map[string]string{
		"an overlong question":    `{"kind":"AgentPlan","steps":[{"action":"need_input","question":"` + strings.Repeat("q", maximumPayloadValueRunes+1) + `"}]}`,
		"overlong tool arguments": `{"kind":"AgentPlan","steps":[{"action":"tool_call","tool":"anvilkit.tool.context-echo","arguments":{"query":"` + strings.Repeat("a", maximumPayloadValueRunes+1) + `"}}]}`,
		// Thirty-one input chunks plus the delegate and the reason are one
		// member more than the payload admits.
		"a brief needing more members than the payload admits": `{"kind":"AgentPlan","steps":[{"action":"delegate","delegate":"` + permittedDelegate + `","input":{"brief":"` + strings.Repeat("b", maximumPayloadValueRunes*(maximumPayloadMembers-2)+1) + `"}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			// A plan this long crosses the governed output as an indexed
			// continuation, exactly as a real gateway answer would.
			plane := planeServing(t, chunkedPayloadValue("plan", plan))
			_, _, err := decide(t, plane, managerTask(nil))
			if got := proposalRefusal(t, err); got != runtime.ProposalOutsideBounds {
				t.Fatalf("reason = %q, want %q", got, runtime.ProposalOutsideBounds)
			}
		})
	}
}

func TestADelegationStillRunningContinuesRatherThanConcludes(t *testing.T) {
	plane := planeServing(t, planOutput(`{"kind":"AgentPlan","steps":[{"action":"continue"}]}`))
	decision, _, err := decide(t, plane, concludingTask("pending", nil))
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Decision != schema.AgentRuntimeResultTurnDecisionDecisionContinue {
		t.Fatalf("decision = %q", decision.Decision)
	}
	if len(decision.ArtifactOutputs) != 0 {
		t.Fatalf("an unfinished delegation produced an artifact: %+v", decision.ArtifactOutputs)
	}
}

func TestAManagerCannotReachTheSpecialistItself(t *testing.T) {
	plane := planeServing(t, planOutput(`{"kind":"AgentPlan","steps":[{"action":"continue"}]}`))
	_, _, err := decide(t, plane, managerTask(map[string]string{"callSpecialistDirectly": "yes"}))
	var boundary *runtime.BoundaryError
	if !errors.As(err, &boundary) || boundary.Refusal != runtime.RefusePeerCall {
		t.Fatalf("a Manager reached a peer: %v", err)
	}
	if plane.asked != 0 {
		t.Fatal("a refused peer call still spent a model invocation")
	}
}

func TestATaskWithoutItsPinnedModelContextIsNotReasonedAbout(t *testing.T) {
	task := managerTask(nil)
	delete(task.Parameters, "model.promptDigest")
	plane := planeServing(t, planOutput(`{"kind":"AgentPlan","steps":[{"action":"continue"}]}`))
	_, _, err := decide(t, plane, task)
	var missing *runtime.ContextError
	if !errors.As(err, &missing) {
		t.Fatalf("expected a context refusal, got %v", err)
	}
	// Nothing was sent: a dispatch missing its pinned prompt would have the
	// runtime choosing one.
	if plane.asked != 0 {
		t.Fatal("an invocation without its pinned prompt was sent")
	}
}

func TestAManagerHasNoArtifactWriterAtAll(t *testing.T) {
	plane := planeServing(t, planOutput(`{"kind":"AgentPlan","steps":[{"action":"continue"}]}`))
	session := plane.session(t)
	// A Manager release does not carry the artifact path. The refusal is the
	// released boundary answering, and it is what makes "the Manager never
	// writes an artifact" a property of the release rather than of its code.
	_, err := session.SubmitCandidate(context.Background(), managerTask(nil), schema.PageCandidate{})
	var boundary *runtime.BoundaryError
	if !errors.As(err, &boundary) || boundary.Refusal != runtime.RefuseUnknownDestination {
		t.Fatalf("a Manager could write an artifact: %v", err)
	}
}
