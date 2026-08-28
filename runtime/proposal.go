package runtime

// A model proposes; a runtime carries out only what its release already
// permits. The types here are how that distinction is expressed in code rather
// than in review comments: a proposal outside the permitted set becomes a typed
// refusal with a stable reason, and there is no branch that acts on it.

// ProposalReason names why a model proposal was not carried out. Each value is
// a bound the release, the definition, or the contract already set — never a
// judgement the runtime formed about the content.
type ProposalReason string

const (
	// ProposalOutsideVocabulary covers a proposed action that is not one of the
	// governed decisions. A runtime that invented a decision would be extending
	// the vocabulary the control plane branches on.
	ProposalOutsideVocabulary ProposalReason = "the model proposed an action outside the governed decision vocabulary"
	// ProposalUnboundedPlan covers a plan longer than the turn admits. One turn
	// is one decision; a plan that carried several would let a model schedule
	// work the control plane never dispatched.
	ProposalUnboundedPlan ProposalReason = "the model proposed more steps than one turn resolves"
	// ProposalDelegateNotPermitted covers delegation to anything other than the
	// single delegate this release is allowed to ask for.
	ProposalDelegateNotPermitted ProposalReason = "the model proposed a delegate this release may not ask for"
	// ProposalDelegationExhausted covers a second delegation. P0 permits one.
	ProposalDelegationExhausted ProposalReason = "this run has already delegated and P0 permits one delegation"
	// ProposalExpandsAuthority covers a proposal that tries to grant itself
	// tools, budget, credentials, endpoints, or capabilities. Authority arrives
	// with the task or not at all.
	ProposalExpandsAuthority ProposalReason = "the model proposed authority the task did not carry"
	// ProposalOutsideSchema covers composed content that the supplied component
	// schema does not admit — an unknown component, or a property no component
	// declares.
	ProposalOutsideSchema ProposalReason = "the model proposed content the supplied component schema does not admit"
	// ProposalOutsideConstraints covers composed content the supplied style or
	// animation constraints do not admit. It is separate from the schema case
	// because the two are refused for different reasons: a component the
	// catalog does not declare cannot render, and a theme the constraints do
	// not allow renders exactly as asked and is still not permitted.
	ProposalOutsideConstraints ProposalReason = "the model proposed content the supplied style or animation constraints do not admit"
	// ProposalIncomplete covers a proposal that named nothing usable at all, or
	// left out something the supplied schema requires.
	ProposalIncomplete ProposalReason = "the model proposed nothing this turn can carry out"
	// ProposalOutsideBounds is a proposal whose content the bounded decision
	// payload cannot carry: a value longer than one bounded member admits, or
	// more members than the contract admits. It is refused rather than cut
	// down, because a truncated argument or question is a different proposal
	// from the one the model made.
	ProposalOutsideBounds ProposalReason = "the model proposed content the bounded decision payload cannot carry"
)

// ProposalError is a refusal caused by what a model proposed.
//
// It is distinct from a boundary refusal: a boundary refusal means the runtime
// tried to reach something it may not reach, and this means the runtime
// declined to. Both end the turn as a refusal, and keeping them apart is what
// lets evidence tell an attempted crossing from a governed decline.
type ProposalError struct{ Reason ProposalReason }

func (e *ProposalError) Error() string { return "agent proposal refused: " + string(e.Reason) }

// RefuseProposal builds the refusal for one reason.
func RefuseProposal(reason ProposalReason) error { return &ProposalError{Reason: reason} }
