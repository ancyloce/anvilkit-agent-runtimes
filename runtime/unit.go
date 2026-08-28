package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
)

// Unit is one Agent Runtime Unit: a pinned definition, the manifest it was
// released with, and the closed boundary it may reach.
//
// A unit is constructed once, at start, from material the control plane
// released. Nothing about it changes while it runs — an Agent that could
// re-point its own definition or boundary mid-run would be selecting what it
// executes, which is the registry's decision and not the runtime's.
type Unit struct {
	manifest schema.AgentRuntimeManifest
	// manifestDigest is the digest of the manifest itself, computed at start.
	// The manifest cannot carry its own digest, and no other field stands in
	// for it: the image signature attests the image, not the binding that says
	// which definition, endpoints, and limits the image was released under.
	manifestDigest string
	boundary       *Boundary
}

// NewUnit binds a runtime to exactly one manifest.
//
// The manifest carries the definition digest this unit may serve, the image and
// protocol digests it was built from, and the paths it may reach. Refusing an
// incomplete manifest at start is deliberate: a unit that began without a
// pinned identity would produce results nobody could attribute to a release.
//
// controlPlane is the origin the released paths are resolved against. It is the
// deployment's single answer to "where is the control plane"; which routes on
// it this unit may use is the manifest's answer, and neither can be widened by
// the other.
func NewUnit(manifest schema.AgentRuntimeManifest, rawManifest []byte, controlPlane string) (*Unit, error) {
	if manifest.RuntimeUnitId == "" {
		return nil, fmt.Errorf("agent runtime unit: the manifest must name its runtime unit")
	}
	if manifest.Definition.DefinitionDigest == "" || manifest.Image.ImageDigest == "" {
		return nil, fmt.Errorf("agent runtime unit: the manifest must pin a definition digest and an image digest")
	}
	if manifest.Protocol.InvocationProtocolDigest == "" {
		return nil, fmt.Errorf("agent runtime unit: the manifest must pin an invocation protocol digest")
	}
	if len(rawManifest) == 0 {
		return nil, fmt.Errorf("agent runtime unit: the released manifest bytes are required to identify the binding")
	}
	boundary, err := NewBoundary(controlPlane, manifest.Workload.AllowedControlPlaneEndpoints)
	if err != nil {
		return nil, err
	}
	return &Unit{manifest: manifest, manifestDigest: manifestDigest(rawManifest), boundary: boundary}, nil
}

// manifestDigest is the digest of the exact released manifest bytes this unit
// was deployed with.
//
// It must be the bytes, not a re-serialization: the control plane pins the
// digest of the manifest document it approved, and admits a result only if the
// binding the result reports matches that pin. A unit that re-serialized its
// manifest and digested the result would report an identity the control plane
// never approved — the same document, different bytes, a different digest — and
// every one of its results would be refused. The manifest cannot carry its own
// digest, and no other field stands in for it: the image signature attests the
// image, not the binding that says which definition, endpoints, and limits the
// image was released under.
func manifestDigest(rawManifest []byte) string {
	sum := sha256.Sum256(rawManifest)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Boundary is the closed destination set this unit may reach. It is the only
// way out of the process.
func (u *Unit) Boundary() *Boundary { return u.boundary }

// Manifest is the released binding this unit serves.
func (u *Unit) Manifest() schema.AgentRuntimeManifest { return u.manifest }

// ManifestDigest identifies the released binding, distinct from the image it
// runs.
func (u *Unit) ManifestDigest() string { return u.manifestDigest }

// Turn is what an Agent implementation actually provides: one bounded decision
// for one task.
//
// It returns a TurnDecision, never a result. Identity, provenance, usage, and
// the digests that attribute the work to a release are stamped by the host, so
// an Agent cannot claim to have run as a different definition or image than the
// one that was dispatched, and cannot claim to have spent less than it did.
//
// The session is everything the Agent may reach: the governed model path, the
// controlled artifact interface, the boundary, and the place observations are
// recorded. Nothing else is available to it, and it constructs nothing itself.
//
// The context carries the execution bound the unit's manifest declares. An
// implementation that ignored it would make that bound a promise the deployment
// cannot keep: the request would return, and the work would go on holding a
// concurrency slot the release was sized for.
type Turn interface {
	Decide(ctx context.Context, task schema.AgentTask, session *Session) (schema.AgentRuntimeResultTurnDecision, error)
}

// Usage is what one attempt consumed. It is measured by the session every
// governed call passes through, not declared by the Agent, and it is reported
// rather than enforced: budget authority is the control plane's, and a runtime
// that could enforce a budget could also decline to.
type Usage struct {
	// ModelCalls and ToolCalls are counted per physical attempt, not per run:
	// a replacement attempt that repeats work must show that work as its own.
	ModelCalls           int
	ToolCalls            int
	InputTokens          int
	OutputTokens         int
	DurationMilliseconds int
	// CostAmount and CostCurrency are what the governed gateway attributed back
	// to this attempt. An empty amount means nothing was attributed, which the
	// host reports as zero rather than omitting.
	CostAmount   string
	CostCurrency string
}

// Diagnostic is a safe, coded observation about a turn. Detail is bounded and
// carries no credential, no upstream body, and no stack trace.
type Diagnostic struct {
	Code   string
	Detail string
}
