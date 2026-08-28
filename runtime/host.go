package runtime

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
)

// Host resolves one dispatched AgentTask into one signed AgentRuntimeResult.
//
// It is the whole execution surface of an Agent Runtime Unit. Everything an
// Agent may do happens inside one Turn; everything else — admitting the task,
// deciding whether the result becomes state, running validators, executing
// tools, settling budgets — happens in Agent Service, before and after.
type Host struct {
	unit  *Unit
	turn  Turn
	now   func() time.Time
	signs Signer
	// governed bounds every call an Agent makes out of the process. It is the
	// release's own execution timeout: a governed call that outlived the turn
	// would still be running when the attempt it belongs to has been replaced.
	governed time.Duration
}

// SignedStatement is the complete envelope a result carries: the algorithm, the
// key a verifier resolves, the signature bytes themselves, and the digest of
// the statement they were taken over. A digest alone is not a signature — a
// verifier who does not already hold the bytes can do nothing with it — so
// every field here is required.
type SignedStatement struct {
	Algorithm       string
	KeyID           string
	Signature       string
	StatementDigest string
}

// Signer produces the signature envelope a result carries. The host never holds
// a signing key itself: it asks for a signature over the statement it built, so
// the key lives with whatever the deployment trusts to hold one.
//
// Implementations must be safe for concurrent use. A unit serves up to the
// concurrency its manifest declares, and every one of those turns ends in a
// signature, so Sign is called from several goroutines at once.
type Signer interface {
	Sign(statement []byte) (SignedStatement, error)
}

// NewHost binds a unit, an Agent implementation, and a signer into the loop
// that serves tasks.
func NewHost(unit *Unit, turn Turn, signer Signer, now func() time.Time) (*Host, error) {
	if unit == nil || turn == nil || signer == nil || now == nil {
		return nil, fmt.Errorf("agent runtime host: a unit, a turn, a signer, and a clock are all required")
	}
	governed := time.Duration(unit.Manifest().Execution.TimeoutMilliseconds) * time.Millisecond
	if governed <= 0 {
		governed = time.Minute
	}
	return &Host{unit: unit, turn: turn, signs: signer, now: now, governed: governed}, nil
}

// Resolve serves one dispatched task.
//
// The Agent decides, and the host — not the Agent — stamps identity, selection
// digests, usage, and provenance onto the result.
//
// The host echoes the binding and fencing identity it was dispatched under —
// physical attempt, attempt number, lease epoch, and fence token — so Agent
// Service can decide at commit time whether this result still belongs to the
// execution it is holding.
//
// The credential is the attempt's own task-scoped credential, and it is what
// every governed call the Agent makes will carry. It is passed in rather than
// held on the host because it is authority for one attempt: a host that kept
// one would be holding authority between attempts.
//
// Nothing here re-checks admission. A task reaches this function only after the
// admission boundary proved its credential, its release binding, and its
// admission window, and duplicating those checks in two places is how the two
// places eventually disagree about which one is authoritative.
func (h *Host) Resolve(ctx context.Context, task schema.AgentTask, credential string) (schema.AgentRuntimeResult, error) {
	started := h.now()

	session, err := h.session(credential)
	if err != nil {
		return schema.AgentRuntimeResult{}, fmt.Errorf("agent runtime host: open session: %w", err)
	}

	decision, turnErr := h.turn.Decide(ctx, task, session)
	diagnostics := session.Diagnostics()
	status := decidedStatus(decision.Decision)
	if turnErr != nil {
		// A turn that failed is reported as a governed outcome with a safe
		// code, not as a transport error: the control plane decides what a
		// refused turn means for the run, and it can only decide from a result
		// it received.
		outcome := classify(turnErr)
		status = schema.AgentRuntimeResultStatus{Status: outcome.status, ReasonCode: outcome.reason}
		decision = schema.AgentRuntimeResultTurnDecision{
			Decision:        schema.AgentRuntimeResultTurnDecisionDecisionRefuse,
			Payload:         schema.SharedPrimitivesBoundedStringMap{},
			ArtifactOutputs: []schema.SharedPrimitivesArtifactReference{},
		}
		diagnostics = append(diagnostics, outcome.diagnostic)
	}

	// Usage is what the session measured, never what the Agent said. The only
	// figure the Agent's own code contributes is none of them.
	usage := session.Usage()
	usage.DurationMilliseconds = int(h.now().Sub(started).Milliseconds())
	if usage.DurationMilliseconds < 0 {
		usage.DurationMilliseconds = 0
	}
	// A runtime unit does not price its own work: it reports what it spent and
	// the control plane's governed meters settle it. Zero is the honest value
	// for an attempt whose cost the gateway has not attributed back to it.
	cost, currency := usage.CostAmount, usage.CostCurrency
	if cost == "" {
		cost = "0"
	}
	if currency == "" {
		currency = defaultCostCurrency
	}

	result := schema.AgentRuntimeResult{
		Kind:                "AgentRuntimeResult",
		TaskId:              task.TaskId,
		RunId:               task.RunId,
		RootRunId:           task.RootRunId,
		ExecutionGeneration: task.ExecutionGeneration,
		// The attempt is identified by the task it served. A runtime does not
		// invent attempt identity: the scheduler owns physical attempts, and an
		// attempt id a runtime chose could collide with one the scheduler
		// already recorded.
		PhysicalAttemptId: task.PhysicalAttemptId,
		AttemptNumber:     task.AttemptNumber,
		LeaseEpoch:        task.LeaseEpoch,
		// The fence is echoed, never chosen: it is the capability the scheduler
		// issued for this attempt, and a result that carried any other value
		// would be asking to commit against a lease it was not granted.
		FenceToken: task.FenceToken,
		Selected: schema.AgentRuntimeResultSelected{
			RuntimeUnitId:            h.unit.manifest.RuntimeUnitId,
			DefinitionDigest:         h.unit.manifest.Definition.DefinitionDigest,
			RuntimeManifestDigest:    schema.SharedPrimitivesDigest(h.unit.ManifestDigest()),
			InvocationProtocolDigest: h.unit.manifest.Protocol.InvocationProtocolDigest,
			ImageDigest:              h.unit.manifest.Image.ImageDigest,
		},
		Status:       status,
		TurnDecision: decision,
		Usage: schema.AgentRuntimeResultUsage{
			ModelCalls:           usage.ModelCalls,
			ToolCalls:            usage.ToolCalls,
			InputTokens:          usage.InputTokens,
			OutputTokens:         usage.OutputTokens,
			DurationMilliseconds: usage.DurationMilliseconds,
			Cost: schema.SharedPrimitivesCost{
				Amount:   schema.SharedPrimitivesDecimalString(cost),
				Currency: currency,
			},
		},
		Diagnostics:  boundDiagnostics(diagnostics),
		TraceContext: task.TraceContext,
	}

	statement, err := canonicalStatement(result)
	if err != nil {
		return schema.AgentRuntimeResult{}, fmt.Errorf("agent runtime host: build result statement: %w", err)
	}
	envelope, err := h.signs.Sign(statement)
	if err != nil {
		return schema.AgentRuntimeResult{}, fmt.Errorf("agent runtime host: sign result: %w", err)
	}
	result.Signature = schema.AgentRuntimeResultSignature{
		Algorithm:           schema.AgentRuntimeResultSignatureAlgorithm(envelope.Algorithm),
		KeyId:               envelope.KeyID,
		StatementDigest:     schema.SharedPrimitivesDigest(envelope.StatementDigest),
		Signature:           envelope.Signature,
		ProvenanceReference: h.unit.manifest.Image.ProvenanceDigest,
	}
	return result, nil
}

// session composes the capabilities one attempt may use.
//
// What a unit can reach is decided by its release, so a capability is built
// only when the manifest named the path it needs. A Manager therefore gets no
// artifact writer at all rather than one that fails at the end of a turn, and
// the difference between "this release does not write artifacts" and "this
// write failed" stays visible in the result.
func (h *Host) session(credential string) (*Session, error) {
	boundary := h.unit.Boundary()
	if credential == "" {
		return nil, fmt.Errorf("a turn cannot be opened without the attempt's task-scoped credential")
	}
	var model *ModelGateway
	if boundary.AllowControlPlane(PathModelInvocations) == nil {
		built, err := NewModelGateway(boundary, credential, h.governed)
		if err != nil {
			return nil, err
		}
		model = built
	}
	var artifacts Artifacts
	if boundary.AllowControlPlane(PathRuntimeArtifacts) == nil {
		built, err := NewArtifacts(boundary, credential, h.governed)
		if err != nil {
			return nil, err
		}
		artifacts = built
	}
	return NewSession(boundary, model, artifacts)
}

// classify turns a turn's failure into the governed outcome a result carries:
// the stable status and reason code the control plane branches on, and a
// bounded diagnostic code and detail a reviewer reads.
//
// Every reason below is a value from the runtime-result-reason registry. A
// runtime that reported free-form failure text would make the control plane
// parse prose to decide whether an attempt should be retried, replaced, or
// abandoned — and the difference between those three is the whole reason the
// registry exists.
//
// The split that matters most is retryability. A refusal is the governed path
// working and declining; an unavailability is the governed path not answering.
// Retrying the first spends budget re-asking a question that was answered.
func classify(err error) turnOutcome {
	var boundary *BoundaryError
	if errors.As(err, &boundary) {
		return refusedOutcome("BOUNDARY_REFUSED", string(boundary.Refusal), "RUNTIME_REFUSED_BY_GUARDRAIL")
	}
	var missing *ContextError
	if errors.As(err, &missing) {
		return refusedOutcome(
			"RUNTIME_TASK_CONTEXT_INCOMPLETE",
			"the dispatched task did not supply "+missing.Key,
			"RUNTIME_REFUSED_BY_GUARDRAIL")
	}
	var output *ModelOutputError
	if errors.As(err, &output) {
		return refusedOutcome(
			"RUNTIME_MODEL_OUTPUT_INVALID",
			"the governed model output did not carry a usable "+output.Key,
			"RUNTIME_REFUSED_BY_GUARDRAIL")
	}
	var proposal *ProposalError
	if errors.As(err, &proposal) {
		return refusedOutcome("RUNTIME_PROPOSAL_REFUSED", string(proposal.Reason), "RUNTIME_REFUSED_BY_GUARDRAIL")
	}
	var refused ModelRefusedError
	if errors.As(err, &refused) {
		if refused.ReasonCode == reasonBudgetExhausted {
			// The gateway stopped the invocation because the run's pinned
			// budget could not fund it. That is not the pinned policy
			// declining the proposal: the control plane branches on the
			// budget reason to halt the run under its own exceed behaviour,
			// and a refusal label would turn an exhausted budget into a
			// policy decision nobody made.
			return failedOutcome(
				"GATEWAY_BUDGET_EXHAUSTED",
				"the governed model path could not fund this invocation from the pinned budget",
				reasonBudgetExhausted)
		}
		// The gateway answered under the pinned policy. That is a policy
		// refusal of the run's, not a guardrail this unit applied.
		return refusedOutcome(
			"GATEWAY_MODEL_REFUSED",
			"the governed model path refused this invocation",
			"RUNTIME_REFUSED_BY_POLICY")
	}
	var delegation *DelegationFailedError
	if errors.As(err, &delegation) {
		// The Specialist did not answer. The Manager's turn fails under the
		// Specialist's own governed reason rather than refusing: nothing
		// declined the work, and the control plane decides whether the work
		// is tried again.
		return failedOutcome(
			"RUNTIME_DELEGATION_FAILED",
			"the delegated specialist attempt did not produce its outcome",
			governedReason(delegation.ReasonCode))
	}
	var unavailable ModelUnavailableError
	if errors.As(err, &unavailable) {
		return failedOutcome("RUNTIME_MODEL_UNAVAILABLE", unavailable.Detail, "RUNTIME_MODEL_UNAVAILABLE")
	}
	var write ArtifactWriteError
	if errors.As(err, &write) {
		// The candidate was composed and not recorded. It is a controlled tool
		// that failed, and the work can be attempted again.
		return failedOutcome("RUNTIME_ARTIFACT_WRITE_FAILED", write.Detail, "RUNTIME_TOOL_FAILED")
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return failedOutcome(
			"RUNTIME_DEADLINE_EXCEEDED",
			"the attempt exceeded the execution bound its release declares",
			"RUNTIME_DEADLINE_EXCEEDED")
	case errors.Is(err, context.Canceled):
		return failedOutcome(
			"RUNTIME_CANCELLED",
			"the attempt was cancelled before it produced a decision",
			"RUNTIME_CANCELLED")
	}
	// The detail is deliberately generic. An unattributable failure's own text
	// is the one thing most likely to carry something that should not travel.
	return failedOutcome("TURN_FAILED", "the agent could not resolve this turn", "RUNTIME_INTERNAL_ERROR")
}

// reasonBudgetExhausted is the governed reason the model gateway answers, and
// this unit reports, when the run's pinned budget could not fund an
// invocation. It is the one gateway refusal that is a halt rather than a
// policy decision.
const reasonBudgetExhausted = "RUNTIME_BUDGET_EXHAUSTED"

// turnOutcome is what a failed turn becomes: a governed status and reason, and
// the bounded diagnostic that accompanies them.
type turnOutcome struct {
	diagnostic Diagnostic
	status     schema.AgentRuntimeResultStatusStatus
	reason     string
}

func refusedOutcome(code, detail, reason string) turnOutcome {
	return turnOutcome{
		diagnostic: Diagnostic{Code: code, Detail: detail},
		status:     schema.AgentRuntimeResultStatusStatusRefused,
		reason:     reason,
	}
}

func failedOutcome(code, detail, reason string) turnOutcome {
	return turnOutcome{
		diagnostic: Diagnostic{Code: code, Detail: detail},
		status:     schema.AgentRuntimeResultStatusStatusFailed,
		reason:     reason,
	}
}

// decidedStatus reports the governed outcome of an attempt that reached a
// decision. The decision says what the Agent chose; the status says whether the
// attempt itself succeeded, and the reason code is registry-governed so a
// control plane can branch on it without parsing prose.
func decidedStatus(decision schema.AgentRuntimeResultTurnDecisionDecision) schema.AgentRuntimeResultStatus {
	switch decision {
	case schema.AgentRuntimeResultTurnDecisionDecisionRefuse:
		// The Agent chose to refuse. That is the pinned policy answering, not a
		// guardrail stopping the Agent.
		return schema.AgentRuntimeResultStatus{
			Status:     schema.AgentRuntimeResultStatusStatusRefused,
			ReasonCode: "RUNTIME_REFUSED_BY_POLICY",
		}
	case schema.AgentRuntimeResultTurnDecisionDecisionNeedInput:
		return schema.AgentRuntimeResultStatus{
			Status:     schema.AgentRuntimeResultStatusStatusCompleted,
			ReasonCode: "RUNTIME_INPUT_REQUIRED",
		}
	default:
		return schema.AgentRuntimeResultStatus{
			Status:     schema.AgentRuntimeResultStatusStatusCompleted,
			ReasonCode: "RUNTIME_COMPLETED",
		}
	}
}

// boundDiagnostics keeps a result inside the contract's bounds. A turn that
// produced more observations than the contract admits is truncated rather than
// rejected: losing the tail of a diagnostic list is better than losing the
// decision it accompanied.
func boundDiagnostics(diagnostics []Diagnostic) []schema.AgentRuntimeResultDiagnosticsElem {
	const maximum = 16
	if len(diagnostics) > maximum {
		diagnostics = diagnostics[:maximum]
	}
	out := make([]schema.AgentRuntimeResultDiagnosticsElem, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		detail := diagnostic.Detail
		if len(detail) > 256 {
			detail = detail[:256]
		}
		out = append(out, schema.AgentRuntimeResultDiagnosticsElem{Code: diagnostic.Code, Detail: detail})
	}
	return out
}
