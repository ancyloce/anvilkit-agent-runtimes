package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
// protocol digests it was built from, and the endpoints it may reach. Refusing
// an incomplete manifest at start is deliberate: a unit that began without a
// pinned identity would produce results nobody could attribute to a release.
func NewUnit(manifest schema.AgentRuntimeManifest, modelGateway string) (*Unit, error) {
	if manifest.RuntimeUnitId == "" {
		return nil, fmt.Errorf("agent runtime unit: the manifest must name its runtime unit")
	}
	if manifest.Definition.DefinitionDigest == "" || manifest.Image.ImageDigest == "" {
		return nil, fmt.Errorf("agent runtime unit: the manifest must pin a definition digest and an image digest")
	}
	if manifest.Protocol.InvocationProtocolDigest == "" {
		return nil, fmt.Errorf("agent runtime unit: the manifest must pin an invocation protocol digest")
	}
	boundary, err := NewBoundary(modelGateway, manifest.Workload.AllowedControlPlaneEndpoints)
	if err != nil {
		return nil, err
	}
	digest, err := manifestDigest(manifest)
	if err != nil {
		return nil, err
	}
	return &Unit{manifest: manifest, manifestDigest: digest, boundary: boundary}, nil
}

// manifestDigest takes the digest of the released binding. A result reports it
// so a reviewer can tell which binding produced the work, not merely which
// image ran.
func manifestDigest(manifest schema.AgentRuntimeManifest) (string, error) {
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("agent runtime unit: encode manifest for digest: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
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
// It returns a TurnDecision, never a result. Identity, provenance, and the
// digests that attribute the work to a release are stamped by the host, so an
// Agent cannot claim to have run as a different definition or image than the one
// that was dispatched.
type Turn interface {
	Decide(task schema.AgentTask, boundary *Boundary) (schema.AgentRuntimeResultTurnDecision, Usage, []Diagnostic, error)
}

// Usage is what one attempt consumed. It is reported, not enforced: budget
// authority is the control plane's, and a runtime that could enforce a budget
// could also decline to.
type Usage struct {
	InputTokens          int
	OutputTokens         int
	DurationMilliseconds int
}

// Diagnostic is a safe, coded observation about a turn. Detail is bounded and
// carries no credential, no upstream body, and no stack trace.
type Diagnostic struct {
	Code   string
	Detail string
}
