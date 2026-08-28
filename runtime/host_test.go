package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
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
	// testControlPlane is an origin, and testCredential stands in for the
	// task-scoped credential admission verified. A host will not open a turn
	// without one: every governed call the turn makes carries it.
	testControlPlane = "https://control.internal"
	testCredential   = "task-scoped-credential"

	testDefinitionDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	testImageDigest      = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	testProtocolDigest   = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

type scriptedTurn struct {
	decision schema.AgentRuntimeResultTurnDecision
	notes    []Diagnostic
	err      error
	// claimed lets a test have the Agent try to state its own identity, so the
	// host's authority over the result can be observed rather than assumed.
	claimed *schema.AgentRuntimeResultTurnDecision
}

func (s *scriptedTurn) Decide(_ context.Context, _ schema.AgentTask, session *Session) (schema.AgentRuntimeResultTurnDecision, error) {
	for _, note := range s.notes {
		session.Note(note.Code, note.Detail)
	}
	if s.claimed != nil {
		return *s.claimed, s.err
	}
	return s.decision, s.err
}

type recordingSigner struct {
	lock       sync.Mutex
	statements [][]byte
	err        error
}

func (r *recordingSigner) Sign(statement []byte) (SignedStatement, error) {
	if r.err != nil {
		return SignedStatement{}, r.err
	}
	// The host serves up to the manifest's concurrency, so a Signer is called
	// from several goroutines at once.
	r.lock.Lock()
	defer r.lock.Unlock()
	r.statements = append(r.statements, append([]byte(nil), statement...))
	return SignedStatement{
		Algorithm:       "dsse-ed25519-v1",
		KeyID:           "urn:anvilkit:key:agent-runtime:synthetic",
		Signature:       strings.Repeat("s", 86),
		StatementDigest: "sha256:" + strings.Repeat("e", 64),
	}, nil
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
	unit, err := NewUnit(manifest, mustManifestBytes(manifest), testControlPlane)
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
		PhysicalAttemptId:   "attempt.0002",
		AttemptNumber:       2,
		ExecutionGeneration: 3,
		LeaseEpoch:          7,
		FenceToken:          "fence.0000000000002",
		// A real dispatch is always traced: the canonical contract makes the
		// traceparent required, and every governed call the turn makes
		// propagates this exact value.
		TraceContext: schema.SharedPrimitivesTraceContext{
			Traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		},
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
	result, err := hostFor(t, turn, &recordingSigner{}).Resolve(context.Background(), testTask(), testCredential)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.TaskId != "task.0001" || result.RunId != "run.0001" || result.ExecutionGeneration != 3 {
		t.Fatalf("identity was not carried from the task: %+v", result)
	}
	// The scheduler owns physical attempts; an id the runtime invented could
	// collide with one already recorded.
	if string(result.PhysicalAttemptId) != "attempt.0002" || result.AttemptNumber != 2 {
		t.Fatalf("physical attempt was not carried from the task: %+v", result)
	}
	// The fence is a capability the scheduler issued for this attempt. Echoing
	// it is what lets the commit decision be made against the lease that is
	// actually current; inventing one would be asking to commit unfenced.
	if result.LeaseEpoch != 7 || result.FenceToken != "fence.0000000000002" {
		t.Fatalf("the fence was not echoed: epoch=%d token=%q", result.LeaseEpoch, result.FenceToken)
	}
	if string(result.Selected.RuntimeUnitId) != "runtime.platform.page-change-manager" {
		t.Fatalf("the serving runtime unit was not identified: %q", result.Selected.RuntimeUnitId)
	}
	if result.Status.Status != schema.AgentRuntimeResultStatusStatusCompleted ||
		result.Status.ReasonCode != "RUNTIME_COMPLETED" {
		t.Fatalf("status = %+v", result.Status)
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
	result, err := hostFor(t, turn, signer).Resolve(context.Background(), testTask(), testCredential)
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
	if len(signer.statements) != 1 || result.Signature.Signature == "" || result.Signature.KeyId == "" {
		t.Fatal("a refusal left the unit unsigned")
	}
	// A turn that failed for a reason the Agent could not attribute is a failed
	// attempt, not a policy refusal, and the governed reason code says which.
	if result.Status.Status != schema.AgentRuntimeResultStatusStatusFailed ||
		result.Status.ReasonCode != "RUNTIME_INTERNAL_ERROR" {
		t.Fatalf("status = %+v", result.Status)
	}
	// The failure text is the Agent's, not the caller's, and never travels.
	if strings.Contains(result.Diagnostics[0].Detail, "unreachable") {
		t.Fatalf("an internal failure detail escaped: %q", result.Diagnostics[0].Detail)
	}
}

func TestABoundaryRefusalNamesTheRuleItBroke(t *testing.T) {
	turn := &scriptedTurn{err: &BoundaryError{Refusal: RefusePeerCall}}
	result, err := hostFor(t, turn, &recordingSigner{}).Resolve(context.Background(), testTask(), testCredential)
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

func TestTheSignatureIsTakenOverTheResultWithoutItsOwnEnvelope(t *testing.T) {
	turn := &scriptedTurn{decision: schema.AgentRuntimeResultTurnDecision{
		Decision:        schema.AgentRuntimeResultTurnDecisionDecisionFinal,
		Payload:         schema.SharedPrimitivesBoundedStringMap{},
		ArtifactOutputs: []schema.SharedPrimitivesArtifactReference{},
	}}
	signer := &recordingSigner{}
	result, err := hostFor(t, turn, signer).Resolve(context.Background(), testTask(), testCredential)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// Read as generic JSON rather than through the generated type: the statement
	// is deliberately not a complete AgentRuntimeResult, which is the property
	// under test. The statement is only ever hashed, never decoded.
	var signed map[string]any
	if err := json.Unmarshal(signer.statements[0], &signed); err != nil {
		t.Fatalf("the signed statement is not JSON: %v", err)
	}
	// A signature cannot cover itself: the envelope is absent from the signed
	// bytes even though the returned result carries it.
	if _, present := signed["signature"]; present {
		t.Fatal("the signature envelope was signed over itself")
	}
	if signed["taskId"] != string(result.TaskId) {
		t.Fatalf("the signed statement is not the result that was returned: %v", signed["taskId"])
	}
	decision, _ := signed["turnDecision"].(map[string]any)
	if decision["decision"] != string(result.TurnDecision.Decision) {
		t.Fatalf("the signed decision is not the returned decision: %v", decision["decision"])
	}
	if result.Signature.Algorithm != "dsse-ed25519-v1" {
		t.Fatalf("algorithm = %q", result.Signature.Algorithm)
	}
	if result.Signature.StatementDigest == "" || result.Signature.Signature == "" {
		t.Fatalf("the envelope is incomplete: %+v", result.Signature)
	}
}

func TestAResultThatCannotBeSignedIsNotReturned(t *testing.T) {
	turn := &scriptedTurn{decision: schema.AgentRuntimeResultTurnDecision{
		Decision:        schema.AgentRuntimeResultTurnDecisionDecisionFinal,
		Payload:         schema.SharedPrimitivesBoundedStringMap{},
		ArtifactOutputs: []schema.SharedPrimitivesArtifactReference{},
	}}
	_, err := hostFor(t, turn, &recordingSigner{err: fmt.Errorf("no key")}).Resolve(context.Background(), testTask(), testCredential)
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
	result, err := hostFor(t, turn, &recordingSigner{}).Resolve(context.Background(), testTask(), testCredential)
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
	// Resolve happens to build its result with the envelope still zero, so the
	// end-to-end test above cannot see whether canonicalStatement removes it.
	// This calls it with the envelope already populated — the case the removal
	// exists for, and the one a re-signing or replay path would hit.
	signed, err := canonicalStatement(schema.AgentRuntimeResult{
		Kind:   "AgentRuntimeResult",
		TaskId: "task.0001",
		Signature: schema.AgentRuntimeResultSignature{
			Algorithm:       "dsse-ed25519-v1",
			KeyId:           "urn:anvilkit:key:agent-runtime:synthetic",
			Signature:       strings.Repeat("s", 86),
			StatementDigest: schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("e", 64)),
		},
	})
	if err != nil {
		t.Fatalf("build statement: %v", err)
	}
	var statement map[string]any
	if err := json.Unmarshal(signed, &statement); err != nil {
		t.Fatalf("statement is not JSON: %v", err)
	}
	if _, present := statement["signature"]; present {
		t.Fatal("a signature would cover itself")
	}
	if statement["taskId"] != "task.0001" {
		t.Fatal("removing the envelope dropped the rest of the statement")
	}
	// Canonical bytes, not language-native bytes: the verifier is a different
	// implementation in a different language, and only RFC 8785 makes the two
	// agree on what was signed. Member order is the visible half of that — JCS
	// sorts by key, while Go emits struct order.
	var keys []string
	decoder := json.NewDecoder(bytes.NewReader(signed))
	if _, err := decoder.Token(); err != nil {
		t.Fatalf("statement is not an object: %v", err)
	}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			t.Fatalf("read statement member: %v", err)
		}
		keys = append(keys, token.(string))
		var discard json.RawMessage
		if err := decoder.Decode(&discard); err != nil {
			t.Fatalf("read statement value: %v", err)
		}
	}
	if !sort.StringsAreSorted(keys) {
		t.Fatalf("the statement is not RFC 8785 canonical: members are %v", keys)
	}
}

// releasedUnit is a unit whose manifest carries the given control-plane paths,
// so what a turn can reach is decided the way a real release decides it. The
// origin is a live server that refuses everything: a released capability then
// fails as a governed call rather than as a name that does not resolve, which
// is both faster and the difference these tests are about.
func releasedUnit(t *testing.T, origin string, paths ...string) *Unit {
	t.Helper()
	manifest := schema.AgentRuntimeManifest{
		Kind:          "AgentRuntimeManifest",
		RuntimeUnitId: "runtime.platform.page-candidate-specialist",
		Definition: schema.SharedPrimitivesDefinitionReference{
			DefinitionId:     "definition.platform.page-candidate-specialist",
			DefinitionDigest: testDefinitionDigest,
		},
		Image:    schema.AgentRuntimeManifestImage{ImageDigest: testImageDigest},
		Protocol: schema.AgentRuntimeManifestProtocol{InvocationProtocolDigest: testProtocolDigest},
		Workload: schema.AgentRuntimeManifestWorkload{AllowedControlPlaneEndpoints: paths},
	}
	unit, err := NewUnit(manifest, mustManifestBytes(manifest), origin)
	if err != nil {
		t.Fatalf("build unit: %v", err)
	}
	return unit
}

// reachingTurn tries both governed capabilities and records what answered.
type reachingTurn struct {
	modelErr    error
	artifactErr error
}

func (r *reachingTurn) Decide(ctx context.Context, task schema.AgentTask, session *Session) (schema.AgentRuntimeResultTurnDecision, error) {
	_, r.modelErr = session.Model(ctx, task, Prompt{Operation: "model.plan"})
	_, r.artifactErr = session.SubmitCandidate(ctx, task, schema.PageCandidate{})
	return schema.AgentRuntimeResultTurnDecision{
		Decision:        schema.AgentRuntimeResultTurnDecisionDecisionContinue,
		Payload:         schema.SharedPrimitivesBoundedStringMap{},
		ArtifactOutputs: []schema.SharedPrimitivesArtifactReference{},
	}, nil
}

func TestWhatATurnCanReachIsDecidedByTheRelease(t *testing.T) {
	for name, testCase := range map[string]struct {
		released            []string
		modelOK, artifactOK bool
	}{
		"released for both":    {[]string{PathModelInvocations, PathRuntimeArtifacts}, true, true},
		"a manager's release":  {[]string{PathModelInvocations}, true, false},
		"released for neither": {nil, false, false},
	} {
		t.Run(name, func(t *testing.T) {
			refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			defer refusing.Close()
			turn := &reachingTurn{}
			host, err := NewHost(releasedUnit(t, refusing.URL, testCase.released...), turn, &recordingSigner{}, func() time.Time {
				return time.Unix(1700000000, 0)
			})
			if err != nil {
				t.Fatalf("build host: %v", err)
			}
			if _, err := host.Resolve(context.Background(), testTask(), testCredential); err != nil {
				t.Fatalf("resolve: %v", err)
			}
			// A capability the release does not carry refuses at the boundary
			// rather than existing and failing later. A released one is built
			// and reaches the (absent) control plane, which is a different
			// failure entirely.
			var boundary *BoundaryError
			if reachedModel := !errors.As(turn.modelErr, &boundary); reachedModel != testCase.modelOK {
				t.Fatalf("model reachable = %v, want %v (err %v)", reachedModel, testCase.modelOK, turn.modelErr)
			}
			boundary = nil
			if reachedArtifacts := !errors.As(turn.artifactErr, &boundary); reachedArtifacts != testCase.artifactOK {
				t.Fatalf("artifacts reachable = %v, want %v (err %v)", reachedArtifacts, testCase.artifactOK, turn.artifactErr)
			}
		})
	}
}

func TestATurnCannotBeOpenedWithoutTheAttemptsCredential(t *testing.T) {
	// Every governed call the turn makes carries this credential. A host that
	// opened a turn without one would be about to act with authority nobody
	// issued it.
	_, err := hostFor(t, &scriptedTurn{}, &recordingSigner{}).Resolve(context.Background(), testTask(), "")
	if err == nil {
		t.Fatal("a turn was opened with no task-scoped credential")
	}
}

func TestEveryTurnFailureBecomesAGovernedStatusAndReason(t *testing.T) {
	// The control plane branches on these to decide whether an attempt is
	// retried, replaced, or abandoned, so each one is a value from the
	// runtime-result-reason registry rather than prose. The split that matters
	// most is refused (the governed path declined — do not retry) against
	// failed (it did not answer — the attempt may be replaced).
	for name, testCase := range map[string]struct {
		err        error
		status     schema.AgentRuntimeResultStatusStatus
		reason     string
		diagnostic string
	}{
		"a boundary refusal": {
			&BoundaryError{Refusal: RefusePeerCall},
			schema.AgentRuntimeResultStatusStatusRefused, "RUNTIME_REFUSED_BY_GUARDRAIL", "BOUNDARY_REFUSED",
		},
		"an incomplete dispatch": {
			&ContextError{Key: "model.promptDigest"},
			schema.AgentRuntimeResultStatusStatusRefused, "RUNTIME_REFUSED_BY_GUARDRAIL", "RUNTIME_TASK_CONTEXT_INCOMPLETE",
		},
		"unusable governed output": {
			&ModelOutputError{Key: "plan"},
			schema.AgentRuntimeResultStatusStatusRefused, "RUNTIME_REFUSED_BY_GUARDRAIL", "RUNTIME_MODEL_OUTPUT_INVALID",
		},
		"a refused proposal": {
			RefuseProposal(ProposalDelegateNotPermitted),
			schema.AgentRuntimeResultStatusStatusRefused, "RUNTIME_REFUSED_BY_GUARDRAIL", "RUNTIME_PROPOSAL_REFUSED",
		},
		"a governed model refusal": {
			ModelRefusedError{Outcome: "refused", ReasonCode: "MODEL_REFUSED_BY_POLICY"},
			schema.AgentRuntimeResultStatusStatusRefused, "RUNTIME_REFUSED_BY_POLICY", "GATEWAY_MODEL_REFUSED",
		},
		// A budget the gateway could not fund is a halt the control plane
		// branches on, not a policy decision: it travels as failed under the
		// governed budget reason, exactly as the in-process stand-in reports
		// it, so both execution paths agree.
		"a budget the gateway could not fund": {
			ModelRefusedError{Outcome: "refused", ReasonCode: "RUNTIME_BUDGET_EXHAUSTED"},
			schema.AgentRuntimeResultStatusStatusFailed, "RUNTIME_BUDGET_EXHAUSTED", "GATEWAY_BUDGET_EXHAUSTED",
		},
		// A delegated Specialist that did not answer fails the Manager's turn
		// under the Specialist's own governed reason; a reason outside the
		// governed shape never reaches a result.
		"a delegation that did not answer": {
			&DelegationFailedError{ReasonCode: "RUNTIME_MODEL_UNAVAILABLE"},
			schema.AgentRuntimeResultStatusStatusFailed, "RUNTIME_MODEL_UNAVAILABLE", "RUNTIME_DELEGATION_FAILED",
		},
		"a delegation that failed for an ungoverned reason": {
			&DelegationFailedError{ReasonCode: "the provider key was rejected"},
			schema.AgentRuntimeResultStatusStatusFailed, "RUNTIME_INTERNAL_ERROR", "RUNTIME_DELEGATION_FAILED",
		},
		"an unavailable model path": {
			ModelUnavailableError{Detail: "the governed model path did not answer"},
			schema.AgentRuntimeResultStatusStatusFailed, "RUNTIME_MODEL_UNAVAILABLE", "RUNTIME_MODEL_UNAVAILABLE",
		},
		"an artifact that was not recorded": {
			ArtifactWriteError{Detail: "the controlled artifact path did not answer"},
			schema.AgentRuntimeResultStatusStatusFailed, "RUNTIME_TOOL_FAILED", "RUNTIME_ARTIFACT_WRITE_FAILED",
		},
		"an exceeded deadline": {
			fmt.Errorf("compose: %w", context.DeadlineExceeded),
			schema.AgentRuntimeResultStatusStatusFailed, "RUNTIME_DEADLINE_EXCEEDED", "RUNTIME_DEADLINE_EXCEEDED",
		},
		"a cancellation": {
			fmt.Errorf("compose: %w", context.Canceled),
			schema.AgentRuntimeResultStatusStatusFailed, "RUNTIME_CANCELLED", "RUNTIME_CANCELLED",
		},
		"anything unattributable": {
			fmt.Errorf("the provider key at /run/secrets/provider was rejected"),
			schema.AgentRuntimeResultStatusStatusFailed, "RUNTIME_INTERNAL_ERROR", "TURN_FAILED",
		},
	} {
		t.Run(name, func(t *testing.T) {
			result, err := hostFor(t, &scriptedTurn{err: testCase.err}, &recordingSigner{}).
				Resolve(context.Background(), testTask(), testCredential)
			if err != nil {
				t.Fatalf("a failed turn was reported as a transport error: %v", err)
			}
			if result.Status.Status != testCase.status || result.Status.ReasonCode != testCase.reason {
				t.Fatalf("status = %+v, want %v/%s", result.Status, testCase.status, testCase.reason)
			}
			if len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != testCase.diagnostic {
				t.Fatalf("diagnostics = %+v, want %s", result.Diagnostics, testCase.diagnostic)
			}
			// A refused turn is still a decision the control plane received, and
			// it is still signed.
			if result.Signature.Signature == "" {
				t.Fatal("a refusal left the unit unsigned")
			}
			// An unattributable failure's own text is the one most likely to
			// carry something that should not travel.
			for _, secret := range []string{"/run/secrets", "provider key"} {
				if strings.Contains(result.Diagnostics[0].Detail, secret) {
					t.Fatalf("a diagnostic echoed %q: %q", secret, result.Diagnostics[0].Detail)
				}
			}
		})
	}
}
