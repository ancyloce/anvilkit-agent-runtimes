package runtime

import (
	"context"
	"fmt"
	"sync"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
)

// Session is everything one Agent may reach during one physical attempt.
//
// It exists so that the two things an Agent needs — a governed model decision
// and a controlled artifact write — arrive as capabilities the host built from
// the release and the task's own credential, rather than as clients the Agent
// constructs. An Agent that could construct its own client could choose its own
// destination and its own credential, and both of those are the control plane's.
//
// It is also where usage is observed. Every governed call goes through this
// object, so what an attempt consumed is measured rather than reported: an Agent
// cannot under-declare the tokens it spent, because it never declares them.
type Session struct {
	boundary  *Boundary
	model     *ModelGateway
	artifacts Artifacts

	lock        sync.Mutex
	modelCalls  int
	toolCalls   int
	inputTokens int
	outTokens   int
	cost        decimalAccumulator
	currency    string
	invocations []string
	notes       []Diagnostic
}

// NewSession composes one attempt's capabilities.
//
// A nil model or artifact capability is a released fact, not a missing
// dependency: a Manager is released without the artifact path because it
// produces no artifacts, and asking for one has to fail as a refusal rather
// than a panic.
func NewSession(boundary *Boundary, model *ModelGateway, artifacts Artifacts) (*Session, error) {
	if boundary == nil {
		return nil, fmt.Errorf("agent runtime session: a boundary is required")
	}
	return &Session{boundary: boundary, model: model, artifacts: artifacts}, nil
}

// Boundary is the closed destination set this unit may reach. It is exposed so
// an Agent that wants something outside it meets a refusal it can return rather
// than an absence it has to interpret.
func (s *Session) Boundary() *Boundary { return s.boundary }

// Model sends one bounded prompt through the governed Model Gateway and records
// what it cost.
//
// A unit released without the governed model path refuses here. That is the
// released boundary answering, not a configuration error: a runtime whose
// manifest never named the model path was not released to reason.
func (s *Session) Model(ctx context.Context, task schema.AgentTask, prompt Prompt) (Completion, error) {
	if s.model == nil {
		return Completion{}, &BoundaryError{Refusal: RefuseUnknownDestination}
	}
	completion, err := s.model.Invoke(ctx, task, prompt)
	// Usage is recorded before the outcome is judged. A refused invocation, and
	// one whose output could not be believed, still spent whatever the gateway
	// metered for it, and an attempt that reported only its successful calls
	// would understate what the control plane has to settle.
	s.meterModel(completion)
	if err != nil {
		return Completion{}, err
	}
	return completion, nil
}

// SubmitCandidate writes one produced candidate through the controlled artifact
// interface and records the write.
//
// A unit released without the artifact path refuses here, for the same reason a
// Manager cannot reason on a path it was not released with: what a unit may do
// is a property of its release, checked in one place.
func (s *Session) SubmitCandidate(
	ctx context.Context,
	task schema.AgentTask,
	candidate schema.PageCandidate,
) (schema.SharedPrimitivesArtifactReference, error) {
	if s.artifacts == nil {
		return schema.SharedPrimitivesArtifactReference{}, &BoundaryError{Refusal: RefuseUnknownDestination}
	}
	reference, err := s.artifacts.SubmitCandidate(ctx, task, candidate)
	if err != nil {
		// A submission that was not recorded is not a controlled tool call the
		// control plane has anything to settle, for the same reason an
		// unanswered model invocation is not one: the record on the other side
		// is what a call is counted against, and there is none.
		return schema.SharedPrimitivesArtifactReference{}, err
	}
	s.lock.Lock()
	s.toolCalls++
	s.lock.Unlock()
	return reference, nil
}

// meterModel records one governed invocation against the attempt.
//
// Only an invocation the gateway actually answered for is counted. An
// invocation refused before it was sent never happened, and one whose answer
// could not be attributed to this attempt is not this attempt's to charge — the
// gateway's own invocation record is what covers a call whose answer was lost,
// and inventing a figure here would double-count against it.
func (s *Session) meterModel(completion Completion) {
	if completion.InvocationID == "" {
		return
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	s.modelCalls++
	s.inputTokens += completion.InputTokens
	s.outTokens += completion.OutputTokens
	s.invocations = append(s.invocations, completion.InvocationID)
	if completion.CostAmount == "" {
		return
	}
	switch {
	case s.currency == "":
		s.currency = completion.CostCurrency
	case completion.CostCurrency != "" && completion.CostCurrency != s.currency:
		// Two currencies in one attempt cannot be added, and picking one would
		// invent a number. The consumption is still reported; what is lost is
		// only the arithmetic, and the diagnostic says so.
		s.notes = append(s.notes, Diagnostic{
			Code:   "RUNTIME_USAGE_CURRENCY_CONFLICT",
			Detail: "the attempt was metered in more than one currency; cost is reported for the first",
		})
		return
	}
	if err := s.cost.add(completion.CostAmount); err != nil {
		s.notes = append(s.notes, Diagnostic{
			Code:   "RUNTIME_USAGE_COST_UNREADABLE",
			Detail: "a metered cost was not a canonical decimal amount and is not included in the total",
		})
	}
}

// Note records a bounded, coded observation the host will carry back. It is how
// an Agent says something a reviewer should see without inventing a decision.
func (s *Session) Note(code, detail string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.notes = append(s.notes, Diagnostic{Code: code, Detail: detail})
}

// Usage is what this attempt actually consumed, as observed rather than as
// declared.
//
// The duration is left to the host. What a session can see is how long each
// governed call took, and the control plane already holds that per invocation;
// what the attempt's own usage should report is how long the attempt ran, and
// only the host knows when it started.
func (s *Session) Usage() Usage {
	s.lock.Lock()
	defer s.lock.Unlock()
	currency := s.currency
	if currency == "" {
		currency = defaultCostCurrency
	}
	return Usage{
		ModelCalls:           s.modelCalls,
		ToolCalls:            s.toolCalls,
		InputTokens:          s.inputTokens,
		OutputTokens:         s.outTokens,
		DurationMilliseconds: 0,
		CostAmount:           s.cost.string(),
		CostCurrency:         currency,
	}
}

// ModelInvocations are the governed invocations this attempt made, in the order
// it made them. A produced candidate records them so a reviewer can resolve
// every model decision that went into it.
func (s *Session) ModelInvocations() []string {
	s.lock.Lock()
	defer s.lock.Unlock()
	return append([]string(nil), s.invocations...)
}

// Diagnostics are the observations recorded during the attempt.
func (s *Session) Diagnostics() []Diagnostic {
	s.lock.Lock()
	defer s.lock.Unlock()
	return append([]Diagnostic(nil), s.notes...)
}

// defaultCostCurrency is what a result reports when the gateway attributed no
// cost at all. Zero in a named currency is a fact; an empty currency is not.
const defaultCostCurrency = "USD"
