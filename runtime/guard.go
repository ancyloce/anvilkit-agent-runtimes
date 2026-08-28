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

// The governed control-plane paths of the canonical runtime boundary. They are
// named here rather than composed by callers so that no Agent can assemble a
// destination: every path a unit may reach is a constant, and reaching it still
// requires the unit's own manifest to have been released with it.
const (
	// PathModelInvocations is the governed Model Gateway. It is the only place
	// a prompt may go, and the runtime never learns which provider serves it.
	PathModelInvocations = "/v1/internal/runtime/model-invocations"
	// PathRuntimeArtifacts is the controlled artifact interface. A runtime
	// writes what it produced through it and receives an immutable reference
	// back; it never reaches storage and never mints an artifact identity.
	PathRuntimeArtifacts = "/v1/internal/runtime/artifacts"
	// PathArtifactContentGrants is the controlled read path for one artifact's
	// bytes, bounded and expiring.
	PathArtifactContentGrants = "/v1/internal/runtime/artifact-content-grants"
	// PathContractRuntimeInvocations is the deterministic Contract Runtime,
	// offered to a runtime as a controlled tool rather than as an executor.
	PathContractRuntimeInvocations = "/v1/internal/runtime/contract-runtime-invocations"
)

// Boundary is the closed set of destinations one runtime unit may reach.
//
// It is built from the unit's pinned AgentRuntimeManifest and never from
// configuration a running Agent can influence: an Agent that could name its own
// destination could select an endpoint, and endpoint selection is the control
// plane's decision.
//
// There is one origin and a closed set of released paths. That shape is the
// enforcement: a destination is reachable only if the deployment mounted the
// origin and the release named the path, so no combination of Agent behaviour
// produces a new one.
type Boundary struct {
	// controlPlane is the single origin every governed destination is resolved
	// against. It carries no path of its own: the path always comes from the
	// released set below.
	controlPlane string
	// released is the exact set of control-plane paths this unit was released
	// with. Anything outside it is refused.
	released map[string]struct{}
}

// NewBoundary builds the closed destination set for one runtime unit.
//
// controlPlane is the origin of the Agent Service runtime boundary; the
// endpoints are the paths the unit's own manifest was released with.
func NewBoundary(controlPlane string, allowedControlPlaneEndpoints []string) (*Boundary, error) {
	origin, err := normalizeOrigin(controlPlane)
	if err != nil {
		return nil, err
	}
	released := make(map[string]struct{}, len(allowedControlPlaneEndpoints))
	for _, endpoint := range allowedControlPlaneEndpoints {
		if !strings.HasPrefix(endpoint, "/v1/") {
			return nil, fmt.Errorf("agent runtime boundary: %q is not a control-plane path", endpoint)
		}
		released[endpoint] = struct{}{}
	}
	return &Boundary{controlPlane: origin, released: released}, nil
}

// normalizeOrigin proves the control-plane destination is an origin and nothing
// more. A base carrying a path, a query, or a fragment would let a deployment
// smuggle routing into a value the released path set is supposed to decide.
func normalizeOrigin(controlPlane string) (string, error) {
	trimmed := strings.TrimSpace(controlPlane)
	if trimmed == "" {
		return "", fmt.Errorf("agent runtime boundary: a governed control-plane origin is required")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("agent runtime boundary: control plane is not a usable destination: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("agent runtime boundary: control plane must be an http or https origin")
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("agent runtime boundary: control plane names no host")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || strings.Trim(parsed.Path, "/") != "" {
		return "", fmt.Errorf("agent runtime boundary: control plane must be an origin, not a route")
	}
	return parsed.Scheme + "://" + parsed.Host, nil
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

// Resolve turns a released control-plane path into the absolute destination for
// it. A path this unit was not released with has no destination at all — the
// refusal is the same whether the path is unknown to the contract or merely
// unknown to this release, because a unit is not entitled to learn which.
func (b *Boundary) Resolve(path string) (string, error) {
	if err := b.AllowControlPlane(path); err != nil {
		return "", err
	}
	return b.controlPlane + path, nil
}

// AllowControlPlane reports whether a control-plane path is one this unit was
// released with. It is an exact match: a prefix match would admit a route the
// release never named.
func (b *Boundary) AllowControlPlane(path string) error {
	if _, ok := b.released[path]; !ok {
		return &BoundaryError{Refusal: RefuseUnknownDestination}
	}
	return nil
}

// ControlPlane is the single origin this unit resolves governed paths against.
func (b *Boundary) ControlPlane() string { return b.controlPlane }

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
