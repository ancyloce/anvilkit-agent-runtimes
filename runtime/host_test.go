package runtime

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
)

// The host is the whole execution surface of an Agent Runtime Unit. What these
// prove is the division of labour: the Agent decides, and the host — never the
// Agent — states who ran, under which release, at what cost, and with what
// provenance.

const (
	testDefinitionDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	testImageDigest      = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	testProtocolDigest   = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

type scriptedTurn struct {
	decision schema.AgentRuntimeResultTurnDecision
	usage    Usage
	notes    []Diagnostic
	err      error
	// claimed lets a test have the Agent try to state its own identity, so the
	// host's authority over the result can be observed rather than assumed.
	claimed *schema.AgentRuntimeResultTurnDecision
}

func (s *scriptedTurn) Decide(schema.AgentTask, *Boundary) (schema.AgentRuntimeResultTurnDecision, Usage, []Diagnostic, error) {
	if s.claimed != nil {
		return *s.claimed, s.usage, s.notes, s.err
	}
	return s.decision, s.usage, s.notes, s.err
}

type recordingSigner struct {
	lock       sync.Mutex
	statements [][]byte
	err        error
}

func (r *recordingSigner) Sign(statement []byte) (string, string, string, error) {
	if r.err != nil {
		return "", "", "", r.err
	}
	// The host serves up to the manifest's concurrency, so a Signer is called
	// from several goroutines at once.
	r.lock.Lock()
	defer r.lock.Unlock()
	r.statements = append(r.statements, append([]byte(nil), statement...))
	return "jws-eddsa-v1", "sha256:" + strings.Repeat("d", 64), "sha256:" + strings.Repeat("e", 64), nil
}

func testUnit(t *testing.T) *Unit {
	t.Helper()
	manifest := schema.AgentRuntimeManifest{
		Kind:          "AgentRuntimeManifest",
		RuntimeUnitId: "runtime.platform.page-change-manager",
		Definition: schema.SharedPrimitivesDefinitionReference{
			DefinitionId:     "definition.platform.page-change-manager",
			DefinitionDigest: testDefinitionDigest,
		},
		Image:    schema.AgentRuntimeManifestImage{ImageDigest: testImageDigest},
		Protocol: schema.AgentRuntimeManifestProtocol{InvocationProtocolDigest: testProtocolDigest},
	}
	unit, err := NewUnit(manifest, "https://gateway.internal/v1/models")
	if err != nil {
		t.Fatalf("build unit: %v", err)
	}
	return unit
}

func testTask() schema.AgentTask {
	return schema.AgentTask{
		Kind:                "AgentTask",
		TaskId:              "task.0001",
		RunId:               "run.0001",
		RootRunId:           "run.0001",
		ExecutionGeneration: 3,
	}
}

func hostFor(t *testing.T, turn Turn, signer Signer) *Host {
	t.Helper()
	host, err := NewHost(testUnit(t), turn, signer, func() time.Time { return time.Unix(1700000000, 0) })
	if err != nil {
		t.Fatalf("build host: %v", err)
	}
	return host
}

func TestTheHostStampsIdentityAndSelectionNotTheAgent(t *testing.T) {
	// The Agent returns a decision and nothing else. Every identifying field
	// below comes from the task or the pinned manifest.
	turn := &scriptedTurn{decision: schema.AgentRuntimeResultTurnDecision{
		Decision:        schema.AgentRuntimeResultTurnDecisionDecisionFinal,
		Payload:         schema.SharedPrimitivesBoundedStringMap{},
		ArtifactOutputs: []schema.SharedPrimitivesArtifactReference{},
	}}
	result, err := hostFor(t, turn, &recordingSigner{}).Resolve(testTask())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.TaskId != "task.0001" || result.RunId != "run.0001" || result.ExecutionGeneration != 3 {
		t.Fatalf("identity was not carried from the task: %+v", result)
	}
	// The scheduler owns physical attempts; an id the runtime invented could
	// collide with one already recorded.
	if string(result.PhysicalAttemptId) != "task.0001" {
		t.Fatalf("physical attempt = %q, want the task id", result.PhysicalAttemptId)
	}
	if string(result.Selected.DefinitionDigest) != testDefinitionDigest ||
		string(result.Selected.ImageDigest) != testImageDigest ||
		string(result.Selected.InvocationProtocolDigest) != testProtocolDigest {
		t.Fatalf("selection was not taken from the pinned manifest: %+v", result.Selected)
	}
	if string(result.Selected.RuntimeManifestDigest) == "" {
		t.Fatal("the released binding was not identified")
	}
}

func TestAFailedTurnBecomesASignedRefusalRatherThanALostResult(t *testing.T) {
	turn := &scriptedTurn{err: fmt.Errorf("the model was unreachable")}
	signer := &recordingSigner{}
	result, err := hostFor(t, turn, signer).Resolve(testTask())
	if err != nil {
		t.Fatalf("a failed turn was reported as a transport error: %v", err)
	}
	if result.TurnDecision.Decision != schema.AgentRuntimeResultTurnDecisionDecisionRefuse {
		t.Fatalf("decision = %q, want refuse", result.TurnDecision.Decision)
	}
	if len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "TURN_FAILED" {
		t.Fatalf("diagnostics = %+v", result.Diagnostics)
	}
	// The control plane can only decide what a refused turn means for the run
	// from a result it actually received, and it only trusts a signed one.
	if len(signer.statements) != 1 || result.Provenance.SignatureDigest == "" {
		t.Fatal("a refusal left the unit unsigned")
	}
	// The failure text is the Agent's, not the caller's, and never travels.
	if strings.Contains(result.Diagnostics[0].Detail, "unreachable") {
		t.Fatalf("an internal failure detail escaped: %q", result.Diagnostics[0].Detail)
	}
}

func TestABoundaryRefusalNamesTheRuleItBroke(t *testing.T) {
	turn := &scriptedTurn{err: &BoundaryError{Refusal: RefusePeerCall}}
	result, err := hostFor(t, turn, &recordingSigner{}).Resolve(testTask())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.Diagnostics[0].Code != "BOUNDARY_REFUSED" {
		t.Fatalf("code = %q, want BOUNDARY_REFUSED", result.Diagnostics[0].Code)
	}
	if result.Diagnostics[0].Detail != string(RefusePeerCall) {
		t.Fatalf("detail = %q, want the rule", result.Diagnostics[0].Detail)
	}
}

func TestProvenanceIsTakenOverTheResultWithoutItsOwnSignature(t *testing.T) {
	turn := &scriptedTurn{decision: schema.AgentRuntimeResultTurnDecision{
		Decision:        schema.AgentRuntimeResultTurnDecisionDecisionFinal,
		Payload:         schema.SharedPrimitivesBoundedStringMap{},
		ArtifactOutputs: []schema.SharedPrimitivesArtifactReference{},
	}}
	signer := &recordingSigner{}
	result, err := hostFor(t, turn, signer).Resolve(testTask())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// Read as generic JSON rather than through the generated type: the cleared
	// provenance is deliberately not a valid AgentRuntimeResult, which is the
	// property under test. The statement is only ever hashed, never decoded.
	var signed map[string]any
	if err := json.Unmarshal(signer.statements[0], &signed); err != nil {
		t.Fatalf("the signed statement is not JSON: %v", err)
	}
	// A signature cannot cover itself: the statement must carry empty
	// provenance even though the returned result does not.
	provenance, _ := signed["provenance"].(map[string]any)
	for _, field := range []string{"signatureAlgorithm", "signatureDigest", "statementDigest"} {
		if value, _ := provenance[field].(string); value != "" {
			t.Fatalf("provenance was signed over itself: %s = %q", field, value)
		}
	}
	if signed["taskId"] != string(result.TaskId) {
		t.Fatalf("the signed statement is not the result that was returned: %v", signed["taskId"])
	}
	decision, _ := signed["turnDecision"].(map[string]any)
	if decision["decision"] != string(result.TurnDecision.Decision) {
		t.Fatalf("the signed decision is not the returned decision: %v", decision["decision"])
	}
	if result.Provenance.SignatureAlgorithm != "jws-eddsa-v1" {
		t.Fatalf("algorithm = %q", result.Provenance.SignatureAlgorithm)
	}
}

func TestAResultThatCannotBeSignedIsNotReturned(t *testing.T) {
	turn := &scriptedTurn{decision: schema.AgentRuntimeResultTurnDecision{
		Decision:        schema.AgentRuntimeResultTurnDecisionDecisionFinal,
		Payload:         schema.SharedPrimitivesBoundedStringMap{},
		ArtifactOutputs: []schema.SharedPrimitivesArtifactReference{},
	}}
	_, err := hostFor(t, turn, &recordingSigner{err: fmt.Errorf("no key")}).Resolve(testTask())
	if err == nil {
		t.Fatal("an unsigned result was returned")
	}
}

func TestDiagnosticsAreKeptInsideTheContractBounds(t *testing.T) {
	notes := make([]Diagnostic, 0, 40)
	for i := 0; i < 40; i++ {
		notes = append(notes, Diagnostic{Code: "NOTE", Detail: strings.Repeat("x", 512)})
	}
	turn := &scriptedTurn{
		decision: schema.AgentRuntimeResultTurnDecision{
			Decision:        schema.AgentRuntimeResultTurnDecisionDecisionContinue,
			Payload:         schema.SharedPrimitivesBoundedStringMap{},
			ArtifactOutputs: []schema.SharedPrimitivesArtifactReference{},
		},
		notes: notes,
	}
	result, err := hostFor(t, turn, &recordingSigner{}).Resolve(testTask())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// Losing the tail of a diagnostic list is better than losing the decision
	// it accompanied, so the result is bounded rather than rejected.
	if len(result.Diagnostics) != 16 {
		t.Fatalf("diagnostics = %d, want 16", len(result.Diagnostics))
	}
	for _, diagnostic := range result.Diagnostics {
		if len(diagnostic.Detail) != 256 {
			t.Fatalf("detail length = %d, want 256", len(diagnostic.Detail))
		}
	}
}

func TestAHostCannotBeBuiltWithoutItsCollaborators(t *testing.T) {
	unit := testUnit(t)
	clock := func() time.Time { return time.Unix(0, 0) }
	for name, build := range map[string]func() (*Host, error){
		"no unit":   func() (*Host, error) { return NewHost(nil, &scriptedTurn{}, &recordingSigner{}, clock) },
		"no turn":   func() (*Host, error) { return NewHost(unit, nil, &recordingSigner{}, clock) },
		"no signer": func() (*Host, error) { return NewHost(unit, &scriptedTurn{}, nil, clock) },
		"no clock":  func() (*Host, error) { return NewHost(unit, &scriptedTurn{}, &recordingSigner{}, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := build(); err == nil {
				t.Fatal("a host was built without a required collaborator")
			}
		})
	}
}

func TestCanonicalStatementExcludesTheSignatureItWillCarry(t *testing.T) {
	// Resolve happens to build its result with provenance still zero, so the
	// end-to-end test above cannot see whether canonicalStatement clears it.
	// This calls it with provenance already populated — the case the clearing
	// exists for, and the one a re-signing or replay path would hit.
	signed, err := canonicalStatement(schema.AgentRuntimeResult{
		Kind:   "AgentRuntimeResult",
		TaskId: "task.0001",
		Provenance: schema.AgentRuntimeResultProvenance{
			SignatureAlgorithm: "jws-eddsa-v1",
			SignatureDigest:    schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("d", 64)),
			StatementDigest:    schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("e", 64)),
		},
	})
	if err != nil {
		t.Fatalf("build statement: %v", err)
	}
	var statement map[string]any
	if err := json.Unmarshal(signed, &statement); err != nil {
		t.Fatalf("statement is not JSON: %v", err)
	}
	provenance, _ := statement["provenance"].(map[string]any)
	for _, field := range []string{"signatureAlgorithm", "signatureDigest", "statementDigest"} {
		if value, _ := provenance[field].(string); value != "" {
			t.Fatalf("a signature would cover itself: %s = %q", field, value)
		}
	}
	if statement["taskId"] != "task.0001" {
		t.Fatal("clearing provenance dropped the rest of the statement")
	}
}
