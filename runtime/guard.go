// Package runtime is the shared host every AnvilKit Agent Runtime Unit is built
// on. It resolves one bounded turn for one pinned Agent definition and returns a
// signed result.
//
// The package exists as much to make things impossible as to make them possible.
// An Agent Runtime Unit is an execution plane and nothing else: Agent Service
// owns the AgentRun, the workflow, budgets, delegation, Tool execution,
// validators, artifacts, evidence, and every approval. A runtime that could
// reach past its boundary would move authority by accident, so the boundary is
// enforced here, once, rather than trusted to each Agent's own code.
package runtime

import (
	"fmt"
	"net/url"
	"strings"
)

// Boundary is the closed set of destinations one runtime unit may reach.
//
// It is built from the unit's pinned AgentRuntimeManifest and never from
// configuration a running Agent can influence: an Agent that could name its own
// destination could select an endpoint, and endpoint selection is the control
// plane's decision.
type Boundary struct {
	// modelGateway is the single governed model destination. It is the only
	// place a runtime may send prompts.
	modelGateway string
	// controlPlane is the exact set of read-only control-plane paths this unit
	// was released with. Anything outside it is refused.
	controlPlane map[string]struct{}
}

// NewBoundary builds the closed destination set for one runtime unit.
func NewBoundary(modelGateway string, allowedControlPlaneEndpoints []string) (*Boundary, error) {
	if strings.TrimSpace(modelGateway) == "" {
		return nil, fmt.Errorf("agent runtime boundary: a governed model gateway is required")
	}
	if _, err := url.Parse(modelGateway); err != nil {
		return nil, fmt.Errorf("agent runtime boundary: model gateway is not a usable destination: %w", err)
	}
	allowed := make(map[string]struct{}, len(allowedControlPlaneEndpoints))
	for _, endpoint := range allowedControlPlaneEndpoints {
		if !strings.HasPrefix(endpoint, "/v1/") {
			return nil, fmt.Errorf("agent runtime boundary: %q is not a control-plane path", endpoint)
		}
		allowed[endpoint] = struct{}{}
	}
	return &Boundary{modelGateway: modelGateway, controlPlane: allowed}, nil
}

// Refusal names a boundary an Agent tried to cross. Each value is a rule from
// design 0001 §5.2, stated as something the runtime cannot do rather than
// something it should not.
type Refusal string

const (
	// RefusePeerCall covers any attempt to reach another Agent Runtime Unit.
	// Delegation is dispatched by Agent Service and returns through it; a
	// runtime that could call a peer would create an ungoverned Child run.
	RefusePeerCall Refusal = "an Agent Runtime Unit may not call another Agent Runtime Unit"
	// RefuseToolExecution covers executing a Tool directly. A runtime proposes;
	// Tool Guard decides and executes.
	RefuseToolExecution Refusal = "an Agent Runtime Unit may not execute Tools"
	// RefuseDomainAccess covers reaching Pagix or any business database.
	RefuseDomainAccess Refusal = "an Agent Runtime Unit may not reach domain services or their databases"
	// RefuseStateWrite covers writing Platform state. A runtime returns a
	// proposal; the control plane decides whether it becomes state.
	RefuseStateWrite Refusal = "an Agent Runtime Unit may not write Platform state"
	// RefuseCredentialSelection covers choosing credentials or endpoints. Both
	// arrive scoped to the task or not at all.
	RefuseCredentialSelection Refusal = "an Agent Runtime Unit may not select endpoints or credentials"
	// RefuseUnknownDestination covers anything not on the pinned list.
	RefuseUnknownDestination Refusal = "the destination is outside this runtime unit's released boundary"
)

// BoundaryError is returned when a runtime attempts something outside its
// boundary. It names the rule, never the destination: an error that echoed the
// destination would leak the topology a runtime is not supposed to know.
type BoundaryError struct{ Refusal Refusal }

func (e *BoundaryError) Error() string { return "agent runtime boundary: " + string(e.Refusal) }

// AllowModelGateway reports whether a destination is the governed model
// gateway. It is an exact match: a prefix match would let a lookalike host
// through.
func (b *Boundary) AllowModelGateway(destination string) error {
	if destination != b.modelGateway {
		return &BoundaryError{Refusal: RefuseUnknownDestination}
	}
	return nil
}

// AllowControlPlane reports whether a read-only control-plane path is one this
// unit was released with.
func (b *Boundary) AllowControlPlane(path string) error {
	if _, ok := b.controlPlane[path]; !ok {
		return &BoundaryError{Refusal: RefuseUnknownDestination}
	}
	return nil
}

// Peer always refuses. It exists so the rule is reachable and testable rather
// than merely documented: code that wants a peer call finds a function that
// says no.
func (b *Boundary) Peer(string) error { return &BoundaryError{Refusal: RefusePeerCall} }

// ExecuteTool always refuses. A runtime proposes a Tool call inside its
// TurnDecision and Tool Guard decides.
func (b *Boundary) ExecuteTool(string) error { return &BoundaryError{Refusal: RefuseToolExecution} }

// Domain always refuses. Pagix and every other business owner is reachable only
// through Agent Service.
func (b *Boundary) Domain(string) error { return &BoundaryError{Refusal: RefuseDomainAccess} }

// WriteState always refuses. Durable state is the control plane's.
func (b *Boundary) WriteState(string) error { return &BoundaryError{Refusal: RefuseStateWrite} }

// SelectCredential always refuses. Credentials arrive scoped to one task.
func (b *Boundary) SelectCredential(string) error {
	return &BoundaryError{Refusal: RefuseCredentialSelection}
}
