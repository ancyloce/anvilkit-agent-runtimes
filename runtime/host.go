package runtime

import (
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
}

// Signer produces the provenance a result carries. The host never holds a
// signing key itself: it asks for a signature over the statement it built, so
// the key lives with whatever the deployment trusts to hold one.
//
// Implementations must be safe for concurrent use. A unit serves up to the
// concurrency its manifest declares, and every one of those turns ends in a
// signature, so Sign is called from several goroutines at once.
type Signer interface {
	// Sign returns the algorithm, the signature digest, and the digest of the
	// statement that was signed.
	Sign(statement []byte) (algorithm string, signatureDigest string, statementDigest string, err error)
}

// NewHost binds a unit, an Agent implementation, and a signer into the loop
// that serves tasks.
func NewHost(unit *Unit, turn Turn, signer Signer, now func() time.Time) (*Host, error) {
	if unit == nil || turn == nil || signer == nil || now == nil {
		return nil, fmt.Errorf("agent runtime host: a unit, a turn, a signer, and a clock are all required")
	}
	return &Host{unit: unit, turn: turn, signs: signer, now: now}, nil
}

// Resolve serves one dispatched task.
//
// The Agent decides, and the host — not the Agent — stamps identity, selection
// digests, usage, and provenance onto the result.
//
// The host does not verify that the task was meant for this unit, because the
// canonical AgentTask carries no definition reference to verify against: it is
// the worker dispatch envelope, whose `capability` names a Tool capability
// rather than an Agent definition. Routing is Agent Service's guarantee, which
// design 0001 §5.2 places there — AgentRunner authenticates the runtime and
// verifies task/result digests, fencing, and protocol compatibility. Adding
// defence in depth here would need the envelope to bind a definition first.
func (h *Host) Resolve(task schema.AgentTask) (schema.AgentRuntimeResult, error) {
	started := h.now()

	decision, usage, diagnostics, err := h.turn.Decide(task, h.unit.Boundary())
	if err != nil {
		// A turn that failed is reported as a refusal with a safe code, not as
		// a transport error: the control plane decides what a refused turn
		// means for the run, and it can only decide from a result it received.
		var boundary *BoundaryError
		code := "TURN_FAILED"
		detail := "the agent could not resolve this turn"
		if asBoundary(err, &boundary) {
			code = "BOUNDARY_REFUSED"
			detail = string(boundary.Refusal)
		}
		decision = schema.AgentRuntimeResultTurnDecision{
			Decision:        schema.AgentRuntimeResultTurnDecisionDecisionRefuse,
			Payload:         schema.SharedPrimitivesBoundedStringMap{},
			ArtifactOutputs: []schema.SharedPrimitivesArtifactReference{},
		}
		diagnostics = append(diagnostics, Diagnostic{Code: code, Detail: detail})
	}

	if usage.DurationMilliseconds == 0 {
		usage.DurationMilliseconds = int(h.now().Sub(started).Milliseconds())
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
		PhysicalAttemptId: task.TaskId,
		Selected: schema.AgentRuntimeResultSelected{
			DefinitionDigest:         h.unit.manifest.Definition.DefinitionDigest,
			RuntimeManifestDigest:    schema.SharedPrimitivesDigest(h.unit.ManifestDigest()),
			InvocationProtocolDigest: h.unit.manifest.Protocol.InvocationProtocolDigest,
			ImageDigest:              h.unit.manifest.Image.ImageDigest,
		},
		TurnDecision: decision,
		Usage: schema.AgentRuntimeResultUsage{
			InputTokens:          usage.InputTokens,
			OutputTokens:         usage.OutputTokens,
			DurationMilliseconds: usage.DurationMilliseconds,
		},
		Diagnostics:  boundDiagnostics(diagnostics),
		TraceContext: task.TraceContext,
	}

	statement, err := canonicalStatement(result)
	if err != nil {
		return schema.AgentRuntimeResult{}, fmt.Errorf("agent runtime host: build result statement: %w", err)
	}
	algorithm, signature, statementDigest, err := h.signs.Sign(statement)
	if err != nil {
		return schema.AgentRuntimeResult{}, fmt.Errorf("agent runtime host: sign result: %w", err)
	}
	result.Provenance = schema.AgentRuntimeResultProvenance{
		SignatureAlgorithm: schema.AgentRuntimeResultProvenanceSignatureAlgorithm(algorithm),
		SignatureDigest:    schema.SharedPrimitivesDigest(signature),
		StatementDigest:    schema.SharedPrimitivesDigest(statementDigest),
	}
	return result, nil
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
