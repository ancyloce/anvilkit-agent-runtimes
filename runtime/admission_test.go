package runtime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
)

// The admission boundary is what an Agent Runtime Unit is, from outside. These
// tests are written from that outside: they build a real request, present a
// real credential, and assert the status and stable code the canonical runtime
// boundary description says the unit answers with.
//
// Every case here is an attack or a mistake that must have exactly one
// deterministic answer. A refusal that varied — by timing, by which check ran
// first, or by a message that named the failing field — would tell a caller how
// to construct the request that gets through.

const (
	testCredentialKeyID = "urn:anvilkit:key:agent-service-task-credential"
	testAudience        = "urn:anvilkit:audience:runtime-page-change-manager"
	testProvenance      = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
)

var admissionNow = time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)

// testIssuer mints task credentials the way Agent Service does.
//
// It is a second implementation of the minting half on purpose: these tests
// prove the verifier against bytes it did not produce, and the known-answer
// vector proves this implementation and Agent Service's agree.
type testIssuer struct {
	key    ed25519.PrivateKey
	keyID  string
	header string
}

func newTestIssuer(t *testing.T, keyID string) *testIssuer {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	header, err := json.Marshal(map[string]string{"alg": credentialAlgorithm, "kid": keyID, "typ": credentialType})
	if err != nil {
		t.Fatal(err)
	}
	return &testIssuer{
		key:    ed25519.NewKeyFromSeed(seed),
		keyID:  keyID,
		header: base64.RawURLEncoding.EncodeToString(header),
	}
}

// issue mints a credential for one task, optionally rewritten by the caller so
// a test can present a credential that is valid and wrong.
func (i *testIssuer) issue(t *testing.T, task schema.AgentTask, audience string, expiry time.Time, rewrite func(map[string]any)) string {
	t.Helper()
	claims := map[string]any{
		"iss": credentialIssuer,
		"aud": audience,
		"sub": "urn:anvilkit:attempt:" + string(task.PhysicalAttemptId),
		"jti": string(task.PhysicalAttemptId),
		"iat": admissionNow.Add(-time.Minute).Unix(),
		"nbf": admissionNow.Add(-time.Minute).Unix(),
		"exp": expiry.Unix(),
		credentialBindingClaim: map[string]any{
			"operation":                operationExecute,
			"workspaceId":              "workspace.synthetic",
			"projectId":                "project.synthetic",
			"runId":                    string(task.RunId),
			"rootRunId":                string(task.RootRunId),
			"taskId":                   string(task.TaskId),
			"physicalAttemptId":        string(task.PhysicalAttemptId),
			"attemptNumber":            task.AttemptNumber,
			"executionGeneration":      task.ExecutionGeneration,
			"leaseEpoch":               task.LeaseEpoch,
			"runtimeUnitId":            string(task.RuntimeBinding.RuntimeUnitId),
			"runtimeManifestDigest":    string(task.RuntimeBinding.RuntimeManifestDigest),
			"invocationProtocolDigest": string(task.RuntimeBinding.InvocationProtocolDigest),
		},
	}
	if rewrite != nil {
		rewrite(claims)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := i.header + "." + base64.RawURLEncoding.EncodeToString(payload)
	signature := ed25519.Sign(i.key, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// trustRootFile writes the operator document that approves this issuer, so the
// verifier reads real material from a real file exactly as a deployment does.
func trustRootFile(t *testing.T, issuer *testIssuer, audiences []string, status string, notAfter time.Time) string {
	t.Helper()
	key := map[string]any{
		"keyId":      issuer.keyID,
		"issuer":     credentialIssuer,
		"audiences":  audiences,
		"algorithms": []string{credentialAlgorithm},
		"publicKeyJwk": map[string]string{
			"kty": "OKP", "crv": "Ed25519",
			"x": base64.RawURLEncoding.EncodeToString(issuer.key.Public().(ed25519.PublicKey)),
		},
		"status":    status,
		"notBefore": admissionNow.Add(-24 * time.Hour).Format(trustTimestamp),
		"notAfter":  notAfter.Format(trustTimestamp),
	}
	document, err := json.Marshal(map[string]any{
		"kind":                    trustRootKind,
		"snapshotId":              "task-credential-trust-test",
		"issuedAt":                admissionNow.Add(-24 * time.Hour).Format(trustTimestamp),
		"nextUpdate":              admissionNow.Add(24 * time.Hour).Format(trustTimestamp),
		"maximumClockSkewSeconds": 0,
		"keys":                    []any{key},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "task-credential-trust-root.json")
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// admittingManifest is a released binding complete enough to admit against:
// every field the boundary compares a task to has to be on it.
func admittingManifest(maxConcurrency int) schema.AgentRuntimeManifest {
	manifest := servingManifest(maxConcurrency)
	manifest.Workload.Audience = testAudience
	manifest.Image.ProvenanceDigest = testProvenance
	manifest.Execution.TimeoutMilliseconds = 60000
	return manifest
}

// dispatchedFor builds the task the manifest under test would actually be sent.
//
// The manifest digest is computed from the manifest, so a task naming it cannot
// be written as a literal: a fixture with a hard-coded digest would stop
// matching the moment the manifest gained a field.
func dispatchedFor(t *testing.T, unit *Unit) schema.AgentTask {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "agent-task.minimum.json"))
	if err != nil {
		t.Fatal(err)
	}
	var task schema.AgentTask
	if err := decodeStrictJSON(body, &task); err != nil {
		t.Fatal(err)
	}
	manifest := unit.Manifest()
	task.RuntimeBinding.RuntimeUnitId = manifest.RuntimeUnitId
	task.RuntimeBinding.RuntimeManifestDigest = schema.SharedPrimitivesDigest(unit.ManifestDigest())
	task.RuntimeBinding.RuntimeImageDigest = manifest.Image.ImageDigest
	task.RuntimeBinding.InvocationProtocolDigest = manifest.Protocol.InvocationProtocolDigest
	task.RuntimeBinding.RuntimeAudience = manifest.Workload.Audience
	task.AuthorizationAudience = manifest.Workload.Audience
	task.Definition.DefinitionId = manifest.Definition.DefinitionId
	task.Definition.DefinitionDigest = manifest.Definition.DefinitionDigest
	task.ExecutionGeneration = 1
	task.LeaseEpoch = 1
	task.ExpiresAt = schema.SharedPrimitivesTimestamp(admissionNow.Add(time.Hour))
	return task
}

// dispatch builds the request Agent Service's HTTP adapter sends: the canonical
// task, the bearer credential, and the three headers the description requires.
func dispatch(t *testing.T, task schema.AgentTask, credential string, rewrite func(*http.Request, []byte)) *http.Request {
	t.Helper()
	body, err := json.Marshal(task)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/task", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+credential)
	request.Header.Set(idempotencyHeaderName, string(task.PhysicalAttemptId))
	request.Header.Set(requestDigestHeaderName, digestOf(body))
	request.Header.Set(traceparentHeaderName, task.TraceContext.Traceparent)
	if rewrite != nil {
		rewrite(request, body)
	}
	return request
}

// admissionHarness is one unit, its boundary, and the issuer the operator
// approved for it.
type admissionHarness struct {
	handler   http.Handler
	unit      *Unit
	issuer    *testIssuer
	manifest  schema.AgentRuntimeManifest
	turn      Turn
	host      *Host
	admission *Admission
}

func newAdmissionHarness(t *testing.T, turn Turn, manifest schema.AgentRuntimeManifest, draining <-chan struct{}) *admissionHarness {
	t.Helper()
	unit, err := NewUnit(manifest, mustManifestBytes(manifest), testControlPlane)
	if err != nil {
		t.Fatal(err)
	}
	issuer := newTestIssuer(t, testCredentialKeyID)
	verifier, err := NewCredentialVerifier(
		trustRootFile(t, issuer, []string{testAudience}, "active", admissionNow.Add(24*time.Hour)),
		manifest.Workload.Audience)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := NewAdmission(unit, verifier, func() time.Time { return admissionNow })
	if err != nil {
		t.Fatal(err)
	}
	host, err := NewHost(unit, turn, &recordingSigner{}, func() time.Time { return admissionNow })
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(host, admission, manifest, draining)
	if err != nil {
		t.Fatal(err)
	}
	return &admissionHarness{handler: handler, unit: unit, issuer: issuer, manifest: manifest, turn: turn, host: host, admission: admission}
}

// send dispatches one well-formed request and returns what the unit answered.
func (h *admissionHarness) send(t *testing.T, mutate func(*schema.AgentTask), rewriteClaims func(map[string]any), rewriteRequest func(*http.Request, []byte)) *httptest.ResponseRecorder {
	t.Helper()
	task := dispatchedFor(t, h.unit)
	if mutate != nil {
		mutate(&task)
	}
	credential := h.issuer.issue(t, task, h.manifest.Workload.Audience, admissionNow.Add(time.Minute), rewriteClaims)
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, dispatch(t, task, credential, rewriteRequest))
	return recorder
}

// assertRefused proves a request was answered with exactly the status and code
// the boundary owes it, in the governed problem shape.
func assertRefused(t *testing.T, recorder *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if recorder.Code != status {
		t.Fatalf("status = %d, want %d (body %s)", recorder.Code, status, recorder.Body.String())
	}
	var problem struct {
		Kind         string `json:"kind"`
		Code         string `json:"code"`
		Retryability string `json:"retryability"`
		Message      string `json:"message"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &problem); err != nil {
		t.Fatalf("refusal body is not a problem document: %v", err)
	}
	if problem.Kind != "ProblemDetails" || problem.Code != code || problem.Retryability == "" {
		t.Fatalf("refusal = %+v, want the governed %s problem", problem, code)
	}
	if got := recorder.Header().Get("Content-Type"); got != problemContentTypeHeader {
		t.Fatalf("refusal content type = %q, want %q", got, problemContentTypeHeader)
	}
}

// A complete, correctly credentialed dispatch is admitted and answered. Every
// refusal below is only meaningful against this.
func TestAWellFormedDispatchIsAdmitted(t *testing.T) {
	harness := newAdmissionHarness(t, &scriptedTurn{}, admittingManifest(2), make(chan struct{}))
	recorder := harness.send(t, nil, nil, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("a well-formed dispatch = %d, want 200 (%s)", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get(requestDigestHeaderName); !digestPattern.MatchString(got) {
		t.Fatalf("accepted request digest header = %q", got)
	}
}

// Nothing without a verifiable credential is executed. The unit does not know
// and must not guess who is calling it.
func TestUnauthenticatedDispatchIsRefused(t *testing.T) {
	harness := newAdmissionHarness(t, &countingTurn{}, admittingManifest(2), make(chan struct{}))
	for name, rewrite := range map[string]func(*http.Request, []byte){
		"no credential":     func(r *http.Request, _ []byte) { r.Header.Del("Authorization") },
		"empty bearer":      func(r *http.Request, _ []byte) { r.Header.Set("Authorization", "Bearer ") },
		"another scheme":    func(r *http.Request, _ []byte) { r.Header.Set("Authorization", "Basic abcdef") },
		"not a compact JWS": func(r *http.Request, _ []byte) { r.Header.Set("Authorization", "Bearer not.a-jws") },
		"truncated":         func(r *http.Request, _ []byte) { r.Header.Set("Authorization", "Bearer a.b") },
	} {
		t.Run(name, func(t *testing.T) {
			assertRefused(t, harness.send(t, nil, nil, rewrite), http.StatusUnauthorized, reasonUnauthenticated)
		})
	}
}

// A credential signed by a key nobody approved, or altered after signing, is
// not a credential. This is the property that makes the whole boundary worth
// having: possession of a well-shaped token proves nothing.
func TestForgedAndTamperedCredentialsAreRefused(t *testing.T) {
	harness := newAdmissionHarness(t, &countingTurn{}, admittingManifest(2), make(chan struct{}))

	t.Run("signed by an unapproved key", func(t *testing.T) {
		foreign := newTestIssuer(t, testCredentialKeyID)
		foreign.key = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
		task := dispatchedFor(t, harness.unit)
		credential := foreign.issue(t, task, testAudience, admissionNow.Add(time.Minute), nil)
		recorder := httptest.NewRecorder()
		harness.handler.ServeHTTP(recorder, dispatch(t, task, credential, nil))
		assertRefused(t, recorder, http.StatusUnauthorized, reasonUnauthenticated)
	})

	t.Run("claims rewritten after signing", func(t *testing.T) {
		task := dispatchedFor(t, harness.unit)
		credential := harness.issuer.issue(t, task, testAudience, admissionNow.Add(time.Minute), nil)
		forged := rewritePayload(t, credential, func(claims map[string]any) {
			binding := claims[credentialBindingClaim].(map[string]any)
			binding["workspaceId"] = "workspace.somewhere-else"
		})
		recorder := httptest.NewRecorder()
		harness.handler.ServeHTTP(recorder, dispatch(t, task, forged, nil))
		assertRefused(t, recorder, http.StatusUnauthorized, reasonUnauthenticated)
	})

	t.Run("algorithm downgraded", func(t *testing.T) {
		task := dispatchedFor(t, harness.unit)
		credential := harness.issuer.issue(t, task, testAudience, admissionNow.Add(time.Minute), nil)
		downgraded := rewriteHeader(t, credential, func(header map[string]any) { header["alg"] = "none" })
		recorder := httptest.NewRecorder()
		harness.handler.ServeHTTP(recorder, dispatch(t, task, downgraded, nil))
		assertRefused(t, recorder, http.StatusUnauthorized, reasonUnauthenticated)
	})

	if harness.executions() != 0 {
		t.Fatal("an unverifiable credential reached the Agent")
	}
}

// A credential minted for another release must not be usable here, even though
// it is perfectly valid where it was issued. The audience is the unit's own and
// is never read from the token.
func TestACredentialForAnotherAudienceIsRefused(t *testing.T) {
	harness := newAdmissionHarness(t, &countingTurn{}, admittingManifest(2), make(chan struct{}))
	recorder := harness.send(t, nil, func(claims map[string]any) {
		claims["aud"] = "urn:anvilkit:audience:runtime-page-candidate-specialist"
	}, nil)
	assertRefused(t, recorder, http.StatusUnauthorized, reasonUnauthenticated)
	if harness.executions() != 0 {
		t.Fatal("a credential for another release reached the Agent")
	}
}

// A credential whose window has closed is refused even though it verifies. An
// expired credential is exactly what a captured one becomes.
func TestAnExpiredCredentialIsRefused(t *testing.T) {
	harness := newAdmissionHarness(t, &countingTurn{}, admittingManifest(2), make(chan struct{}))
	recorder := harness.send(t, nil, func(claims map[string]any) {
		claims["exp"] = admissionNow.Add(-time.Second).Unix()
		claims["nbf"] = admissionNow.Add(-time.Hour).Unix()
		claims["iat"] = admissionNow.Add(-time.Hour).Unix()
	}, nil)
	assertRefused(t, recorder, http.StatusUnauthorized, reasonUnauthenticated)
	if harness.executions() != 0 {
		t.Fatal("an expired credential reached the Agent")
	}
}

// A revoked key stops verifying immediately. This is the control that makes a
// leaked issuing key recoverable without redeploying every runtime.
func TestARevokedIssuingKeyStopsAdmittingWork(t *testing.T) {
	manifest := admittingManifest(2)
	unit, err := NewUnit(manifest, mustManifestBytes(manifest), testControlPlane)
	if err != nil {
		t.Fatal(err)
	}
	issuer := newTestIssuer(t, testCredentialKeyID)
	for _, status := range []string{"active", "revoked"} {
		t.Run(status, func(t *testing.T) {
			verifier, err := NewCredentialVerifier(
				trustRootFile(t, issuer, []string{testAudience}, status, admissionNow.Add(24*time.Hour)),
				manifest.Workload.Audience)
			if err != nil {
				t.Fatal(err)
			}
			task := dispatchedFor(t, unit)
			_, err = verifier.Verify(issuer.issue(t, task, testAudience, admissionNow.Add(time.Minute), nil), admissionNow)
			if status == "active" && err != nil {
				t.Fatalf("an approved key did not verify: %v", err)
			}
			if status == "revoked" && err == nil {
				t.Fatal("a revoked key still verified a credential")
			}
		})
	}
}

// A key rotation must not drop work in flight: both the outgoing and incoming
// keys verify while the operator marks them overlapping.
func TestOverlappingKeysBothVerifyDuringARotation(t *testing.T) {
	manifest := admittingManifest(2)
	unit, err := NewUnit(manifest, mustManifestBytes(manifest), testControlPlane)
	if err != nil {
		t.Fatal(err)
	}
	issuer := newTestIssuer(t, testCredentialKeyID)
	verifier, err := NewCredentialVerifier(
		trustRootFile(t, issuer, []string{testAudience}, "overlap", admissionNow.Add(24*time.Hour)),
		manifest.Workload.Audience)
	if err != nil {
		t.Fatal(err)
	}
	task := dispatchedFor(t, unit)
	if _, err := verifier.Verify(issuer.issue(t, task, testAudience, admissionNow.Add(time.Minute), nil), admissionNow); err != nil {
		t.Fatalf("an overlapping key did not verify during rotation: %v", err)
	}
}

// A trust root past its own freshness bound is refused rather than used with a
// warning: a snapshot that outlives its declared life is how a revoked key
// keeps working.
func TestAStaleTrustRootAdmitsNothing(t *testing.T) {
	manifest := admittingManifest(2)
	unit, err := NewUnit(manifest, mustManifestBytes(manifest), testControlPlane)
	if err != nil {
		t.Fatal(err)
	}
	issuer := newTestIssuer(t, testCredentialKeyID)
	verifier, err := NewCredentialVerifier(
		trustRootFile(t, issuer, []string{testAudience}, "active", admissionNow.Add(24*time.Hour)),
		manifest.Workload.Audience)
	if err != nil {
		t.Fatal(err)
	}
	task := dispatchedFor(t, unit)
	credential := issuer.issue(t, task, testAudience, admissionNow.Add(48*time.Hour), nil)
	// The same credential, read a week after the snapshot said to refresh.
	if _, err := verifier.Verify(credential, admissionNow.Add(7*24*time.Hour)); err == nil {
		t.Fatal("a trust root past its freshness bound still admitted work")
	}
}

// A verified credential is authority for one attempt. Presenting it beside any
// other work is a replay, and a replay must not execute.
func TestACredentialIsAuthorityForOneAttemptOnly(t *testing.T) {
	harness := newAdmissionHarness(t, &countingTurn{}, admittingManifest(2), make(chan struct{}))
	for name, rewrite := range map[string]func(map[string]any){
		"another attempt": func(claims map[string]any) {
			claims[credentialBindingClaim].(map[string]any)["physicalAttemptId"] = "attempt.somewhere-else"
		},
		"another task": func(claims map[string]any) {
			claims[credentialBindingClaim].(map[string]any)["taskId"] = "task.somewhere-else"
		},
		"another run": func(claims map[string]any) {
			claims[credentialBindingClaim].(map[string]any)["runId"] = "run.somewhere-else"
		},
		"another generation": func(claims map[string]any) {
			claims[credentialBindingClaim].(map[string]any)["executionGeneration"] = 99
		},
		"another lease": func(claims map[string]any) {
			claims[credentialBindingClaim].(map[string]any)["leaseEpoch"] = 99
		},
		"another attempt number": func(claims map[string]any) {
			claims[credentialBindingClaim].(map[string]any)["attemptNumber"] = 99
		},
		"another release": func(claims map[string]any) {
			claims[credentialBindingClaim].(map[string]any)["runtimeUnitId"] = "runtime.platform.page-candidate-specialist"
		},
		"another manifest": func(claims map[string]any) {
			claims[credentialBindingClaim].(map[string]any)["runtimeManifestDigest"] = testProvenance
		},
		"cancellation only": func(claims map[string]any) {
			claims[credentialBindingClaim].(map[string]any)["operation"] = "cancel"
		},
		"no tenant": func(claims map[string]any) {
			claims[credentialBindingClaim].(map[string]any)["workspaceId"] = ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			// The subject and token id are rewritten with the attempt so the
			// credential stays internally consistent: what is being tested is
			// the binding to the task, not a malformed token.
			recorder := harness.send(t, nil, func(claims map[string]any) {
				rewrite(claims)
				attempt := claims[credentialBindingClaim].(map[string]any)["physicalAttemptId"].(string)
				claims["sub"] = "urn:anvilkit:attempt:" + attempt
				claims["jti"] = attempt
			}, nil)
			assertRefused(t, recorder, http.StatusForbidden, reasonNotAuthorized)
		})
	}
	if harness.executions() != 0 {
		t.Fatal("a credential bound to other work reached the Agent")
	}
}

// A task addressed to another release is refused by the unit it reached, not
// merely routed correctly by the caller. Routing is a guarantee the control
// plane makes; this is the unit refusing to rely on it.
func TestATaskBoundToAnotherReleaseIsRefused(t *testing.T) {
	harness := newAdmissionHarness(t, &countingTurn{}, admittingManifest(2), make(chan struct{}))
	other := schema.SharedPrimitivesDigest("sha256:" + "9999999999999999999999999999999999999999999999999999999999999999")
	for name, mutate := range map[string]func(*schema.AgentTask){
		"another unit": func(task *schema.AgentTask) {
			task.RuntimeBinding.RuntimeUnitId = "runtime.platform.page-candidate-specialist"
		},
		"another manifest": func(task *schema.AgentTask) { task.RuntimeBinding.RuntimeManifestDigest = other },
		"another image":    func(task *schema.AgentTask) { task.RuntimeBinding.RuntimeImageDigest = other },
		"another protocol": func(task *schema.AgentTask) { task.RuntimeBinding.InvocationProtocolDigest = other },
		"another definition": func(task *schema.AgentTask) {
			task.Definition.DefinitionId = "definition.platform.page-candidate-specialist"
		},
		"another audience": func(task *schema.AgentTask) {
			task.RuntimeBinding.RuntimeAudience = "urn:anvilkit:audience:runtime-page-candidate-specialist"
		},
	} {
		t.Run(name, func(t *testing.T) {
			assertRefused(t, harness.send(t, mutate, nil, nil), http.StatusForbidden, reasonNotAuthorized)
		})
	}
	if harness.executions() != 0 {
		t.Fatal("a task for another release reached the Agent")
	}
}

// Work whose admission window has closed, or that carries no attempt identity
// that could ever be fenced, is refused before it costs anything. Executing it
// would spend a model call on a result the control plane must throw away.
func TestWorkThatCouldNeverCommitIsNotExecuted(t *testing.T) {
	harness := newAdmissionHarness(t, &countingTurn{}, admittingManifest(2), make(chan struct{}))
	for name, expectation := range map[string]struct {
		mutate func(*schema.AgentTask)
		status int
		code   string
	}{
		"expired": {func(task *schema.AgentTask) {
			task.ExpiresAt = schema.SharedPrimitivesTimestamp(admissionNow.Add(-time.Second))
		}, http.StatusGone, reasonAdmissionWindow},
		// The canonical contract bounds the fence and the attempt number, so a
		// task without either is refused as an invalid document before
		// admission is reached. That the two checks overlap is the point: the
		// unit does not depend on the contract having caught it.
		"no fence": {func(task *schema.AgentTask) { task.FenceToken = "" },
			http.StatusUnprocessableEntity, reasonContractInvalid},
		"no attempt number": {func(task *schema.AgentTask) { task.AttemptNumber = 0 },
			http.StatusUnprocessableEntity, reasonContractInvalid},
		// The generation and lease epoch are not bounded by the contract — a
		// child run legitimately starts at zero in other contexts — so these
		// are admission's own refusals.
		"no lease": {func(task *schema.AgentTask) { task.LeaseEpoch = 0 }, http.StatusForbidden, reasonNotAuthorized},
		"no generation": {func(task *schema.AgentTask) { task.ExecutionGeneration = 0 },
			http.StatusForbidden, reasonNotAuthorized},
	} {
		t.Run(name, func(t *testing.T) {
			assertRefused(t, harness.send(t, expectation.mutate, nil, nil), expectation.status, expectation.code)
		})
	}
	if harness.executions() != 0 {
		t.Fatal("work that could never commit reached the Agent")
	}
}

// The request shape itself is part of admission. A body that is not a canonical
// AgentTask, or that arrives without the parameters the description requires,
// is refused before anything is verified.
func TestMalformedRequestsAreRefusedBeforeVerification(t *testing.T) {
	harness := newAdmissionHarness(t, &countingTurn{}, admittingManifest(2), make(chan struct{}))
	for name, expectation := range map[string]struct {
		rewrite func(*http.Request, []byte)
		status  int
		code    string
	}{
		"no content type": {func(r *http.Request, _ []byte) { r.Header.Del("Content-Type") },
			http.StatusBadRequest, reasonMalformedRequest},
		"wrong content type": {func(r *http.Request, _ []byte) { r.Header.Set("Content-Type", "text/plain") },
			http.StatusBadRequest, reasonMalformedRequest},
		"no idempotency key": {func(r *http.Request, _ []byte) { r.Header.Del(idempotencyHeaderName) },
			http.StatusBadRequest, reasonMalformedRequest},
		"idempotency key naming other work": {func(r *http.Request, _ []byte) {
			r.Header.Set(idempotencyHeaderName, "attempt.somewhere-else")
		}, http.StatusBadRequest, reasonMalformedRequest},
		"no request digest": {func(r *http.Request, _ []byte) { r.Header.Del(requestDigestHeaderName) },
			http.StatusBadRequest, reasonMalformedRequest},
		"request digest of other bytes": {func(r *http.Request, _ []byte) {
			r.Header.Set(requestDigestHeaderName, testProvenance)
		}, http.StatusBadRequest, reasonMalformedRequest},
		"no traceparent": {func(r *http.Request, _ []byte) { r.Header.Del(traceparentHeaderName) },
			http.StatusBadRequest, reasonMalformedRequest},
	} {
		t.Run(name, func(t *testing.T) {
			assertRefused(t, harness.send(t, nil, nil, expectation.rewrite), expectation.status, expectation.code)
		})
	}
	if harness.executions() != 0 {
		t.Fatal("a malformed request reached the Agent")
	}
}

// The canonical contract decides the shape, and it is enforced on decode: an
// unknown member, a duplicate member, a missing required field, and trailing
// content are all documents this unit will not act on.
func TestOnlyACanonicalAgentTaskIsDecoded(t *testing.T) {
	harness := newAdmissionHarness(t, &countingTurn{}, admittingManifest(2), make(chan struct{}))
	for name, corrupt := range map[string]func([]byte) []byte{
		"unknown member":     func(body []byte) []byte { return injectMember(body, `"unexpected":true`) },
		"duplicate member":   func(body []byte) []byte { return injectMember(body, `"taskId":"task.other"`) },
		"trailing content":   func(body []byte) []byte { return append(append([]byte{}, body...), []byte(`{"more":1}`)...) },
		"missing capability": func(body []byte) []byte { return removeMember(body, "capability") },
	} {
		t.Run(name, func(t *testing.T) {
			task := dispatchedFor(t, harness.unit)
			credential := harness.issuer.issue(t, task, testAudience, admissionNow.Add(time.Minute), nil)
			body, err := json.Marshal(task)
			if err != nil {
				t.Fatal(err)
			}
			corrupted := corrupt(body)
			request := httptest.NewRequest(http.MethodPost, "/task", bytes.NewReader(corrupted))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer "+credential)
			request.Header.Set(idempotencyHeaderName, string(task.PhysicalAttemptId))
			request.Header.Set(requestDigestHeaderName, digestOf(corrupted))
			request.Header.Set(traceparentHeaderName, task.TraceContext.Traceparent)
			recorder := httptest.NewRecorder()
			harness.handler.ServeHTTP(recorder, request)
			assertRefused(t, recorder, http.StatusUnprocessableEntity, reasonContractInvalid)
		})
	}
	if harness.executions() != 0 {
		t.Fatal("a document that is not a canonical AgentTask reached the Agent")
	}
}

// A body larger than the contract admits is refused rather than read. An
// unbounded reader is a way to exhaust a unit without ever sending a task.
func TestAnUnboundedBodyIsRefused(t *testing.T) {
	harness := newAdmissionHarness(t, &countingTurn{}, admittingManifest(2), make(chan struct{}))
	oversized := make([]byte, maximumTaskBytes+1)
	for index := range oversized {
		oversized[index] = ' '
	}
	request := httptest.NewRequest(http.MethodPost, "/task", bytes.NewReader(oversized))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer irrelevant.because.unread")
	request.Header.Set(idempotencyHeaderName, "attempt.synthetic.001")
	request.Header.Set(requestDigestHeaderName, digestOf(oversized))
	request.Header.Set(traceparentHeaderName, "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01")
	recorder := httptest.NewRecorder()
	harness.handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("an unbounded body = %d, want 400", recorder.Code)
	}
	if harness.executions() != 0 {
		t.Fatal("an unbounded body reached the Agent")
	}
}

// A network retry of the same attempt is answered from what the unit already
// produced rather than executed again. The same key over different bytes is a
// different request wearing the same name, and is refused.
// The register claims an attempt for the delivery about to execute it, holds
// a concurrent second delivery, refuses a reuse of the identity with other
// bytes, gives a claim back when the execution recorded nothing, and replays
// the answer once one is recorded.
func TestTheReplayRegisterClaimsAnAttemptUntilItIsAnsweredOrReleased(t *testing.T) {
	register := newReplayRegister(4)
	if _, _, _, inFlight := register.reserve("attempt.1", "sha256:a"); inFlight {
		t.Fatal("the first claim was reported in flight")
	}
	if _, _, _, inFlight := register.reserve("attempt.1", "sha256:a"); !inFlight {
		t.Fatal("a concurrent second delivery was not held")
	}
	if _, _, reused, _ := register.reserve("attempt.1", "sha256:b"); !reused {
		t.Fatal("an in-flight identity reused with other bytes was not refused")
	}
	register.release("attempt.1")
	if _, _, _, inFlight := register.reserve("attempt.1", "sha256:a"); inFlight {
		t.Fatal("a released claim still held the attempt")
	}
	register.record("attempt.1", "sha256:a", []byte("answer"))
	if result, replayed, _, _ := register.reserve("attempt.1", "sha256:a"); !replayed || string(result) != "answer" {
		t.Fatalf("a recorded answer was not replayed: replayed=%v result=%q", replayed, result)
	}
	if _, _, reused, _ := register.reserve("attempt.1", "sha256:b"); !reused {
		t.Fatal("a recorded identity reused with other bytes was not refused")
	}
}

func TestARetriedAttemptIsAnsweredNotReexecuted(t *testing.T) {
	harness := newAdmissionHarness(t, &countingTurn{}, admittingManifest(2), make(chan struct{}))
	first := harness.send(t, nil, nil, nil)
	if first.Code != http.StatusOK {
		t.Fatalf("first dispatch = %d, want 200 (%s)", first.Code, first.Body.String())
	}
	second := harness.send(t, nil, nil, nil)
	if second.Code != http.StatusOK {
		t.Fatalf("retry = %d, want 200", second.Code)
	}
	if second.Header().Get(replayedHeaderName) != "true" {
		t.Fatal("a retried attempt was not answered from the recorded outcome")
	}
	if first.Body.String() != second.Body.String() {
		t.Fatal("a retried attempt was answered with a different result")
	}
	if harness.executions() != 1 {
		t.Fatalf("the Agent ran %d times for one attempt", harness.executions())
	}

	reused := harness.send(t, func(task *schema.AgentTask) { task.Parameters["mode"] = "something-else" }, nil, nil)
	assertRefused(t, reused, http.StatusConflict, reasonIdempotencyReuse)
	if harness.executions() != 1 {
		t.Fatal("a reused idempotency key executed a second, different request")
	}
}

// A recorded answer is not handed to a caller that has not proved it may ask
// for one. Replaying is cheaper than verifying, which is exactly why the order
// matters: a recorded answer is the product of real work, and returning one to
// an unauthenticated caller is disclosure rather than caching.
func TestARecordedAnswerIsNotDisclosedToAnUnauthenticatedCaller(t *testing.T) {
	harness := newAdmissionHarness(t, &countingTurn{}, admittingManifest(2), make(chan struct{}))
	first := harness.send(t, nil, nil, nil)
	if first.Code != http.StatusOK {
		t.Fatalf("first dispatch = %d, want 200 (%s)", first.Code, first.Body.String())
	}
	// The same attempt and the same bytes, with no credential at all: exactly
	// the request that would be replayed if the register were consulted first.
	replayed := harness.send(t, nil, nil, func(r *http.Request, _ []byte) { r.Header.Del("Authorization") })
	assertRefused(t, replayed, http.StatusUnauthorized, reasonUnauthenticated)
	if replayed.Header().Get(replayedHeaderName) == "true" {
		t.Fatal("a recorded answer was replayed to an unauthenticated caller")
	}
	if replayed.Body.String() == first.Body.String() {
		t.Fatal("an unauthenticated caller received the recorded result")
	}

	// And a caller holding a credential for other work gets the same refusal
	// rather than the recorded answer.
	misbound := harness.send(t, nil, func(claims map[string]any) {
		claims[credentialBindingClaim].(map[string]any)["runId"] = "run.somewhere-else"
	}, nil)
	assertRefused(t, misbound, http.StatusForbidden, reasonNotAuthorized)
	if misbound.Header().Get(replayedHeaderName) == "true" {
		t.Fatal("a recorded answer was replayed to a caller credentialed for other work")
	}
}

// The endpoint answers only with statuses the canonical runtime boundary
// description declares for it. A status outside that list is a surface a caller
// has no contract for, however sensible it looks in isolation.
func TestEveryRefusalIsAStatusTheDescriptionDeclares(t *testing.T) {
	// The set the canonical description enumerates for POST /task, plus the
	// method refusal that is inherent to routing and the capacity refusal the
	// released concurrency bound produces.
	declared := map[int]bool{
		http.StatusOK: true, http.StatusBadRequest: true, http.StatusUnauthorized: true,
		http.StatusForbidden: true, http.StatusNotFound: true, http.StatusConflict: true,
		http.StatusGone: true, http.StatusUnprocessableEntity: true,
		http.StatusInternalServerError: true,
		http.StatusMethodNotAllowed:    true, http.StatusTooManyRequests: true,
	}
	for _, denied := range []refusal{
		malformedRequest, invalidCredential, notAdmissible, contractInvalid,
		idempotencyReused, admissionClosed, capacityExhausted, internalRefusal,
	} {
		if !declared[denied.Status] {
			t.Fatalf("refusal %s answers %d, which the boundary description does not declare", denied.Code, denied.Status)
		}
		if denied.Retryability == "" || denied.Code == "" {
			t.Fatalf("refusal %+v does not say what it is or whether it can be retried", denied)
		}
	}
}

// A draining unit admits nothing new. Readiness alone leaves a window between
// the control plane's last read and a dispatch it had already decided to send.
func TestADrainingUnitAdmitsNothingNew(t *testing.T) {
	draining := make(chan struct{})
	harness := newAdmissionHarness(t, &countingTurn{}, admittingManifest(2), draining)
	close(draining)
	assertRefused(t, harness.send(t, nil, nil, nil), http.StatusTooManyRequests, reasonCapacityExhausted)
	if harness.executions() != 0 {
		t.Fatal("a draining unit executed new work")
	}
}

// No refusal names the check that failed. A caller able to tell an expired
// credential from one issued for another attempt could search for the
// difference; the unit's own telemetry is where that distinction belongs.
func TestRefusalsDoNotDescribeTheCheckThatFailed(t *testing.T) {
	harness := newAdmissionHarness(t, &countingTurn{}, admittingManifest(2), make(chan struct{}))
	bodies := map[string]string{}
	bodies["expired credential"] = harness.send(t, nil, func(claims map[string]any) {
		claims["exp"] = admissionNow.Add(-time.Second).Unix()
		claims["nbf"] = admissionNow.Add(-time.Hour).Unix()
		claims["iat"] = admissionNow.Add(-time.Hour).Unix()
	}, nil).Body.String()
	bodies["wrong audience"] = harness.send(t, nil, func(claims map[string]any) {
		claims["aud"] = "urn:anvilkit:audience:runtime-page-candidate-specialist"
	}, nil).Body.String()
	bodies["unapproved key"] = harness.send(t, nil, nil, func(r *http.Request, _ []byte) {
		r.Header.Set("Authorization", "Bearer "+rewriteSignature(t, r.Header.Get("Authorization")))
	}).Body.String()

	var first string
	for name, body := range bodies {
		if first == "" {
			first = body
			continue
		}
		if body != first {
			t.Fatalf("%q produced a distinguishable refusal:\n%s\n%s", name, first, body)
		}
	}
	// And nothing in it echoes the credential, the fence, or the task.
	for _, secret := range []string{"fence.synthetic", "Bearer", "eyJ", "workspace.synthetic"} {
		if containsSubstring(first, secret) {
			t.Fatalf("a refusal echoed %q: %s", secret, first)
		}
	}
}

// countingTurn counts the turns an Agent was actually asked to take.
type countingTurn struct {
	scriptedTurn
	lock  sync.Mutex
	taken int
}

func (c *countingTurn) Decide(ctx context.Context, task schema.AgentTask, session *Session) (schema.AgentRuntimeResultTurnDecision, error) {
	c.lock.Lock()
	c.taken++
	c.lock.Unlock()
	return c.scriptedTurn.Decide(ctx, task, session)
}

func (c *countingTurn) runs() int {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.taken
}

// rewriteHeader and rewritePayload alter one half of a signed credential and
// leave the signature as it was, which is what an interception looks like: the
// bytes changed and the proof did not.
func rewriteHeader(t *testing.T, credential string, rewrite func(map[string]any)) string {
	t.Helper()
	return rewritePart(t, credential, 0, rewrite)
}

func rewritePayload(t *testing.T, credential string, rewrite func(map[string]any)) string {
	t.Helper()
	return rewritePart(t, credential, 1, rewrite)
}

func rewritePart(t *testing.T, credential string, index int, rewrite func(map[string]any)) string {
	t.Helper()
	parts := strings.Split(credential, ".")
	if len(parts) != 3 {
		t.Fatalf("credential is not a compact JWS")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[index])
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	rewrite(document)
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	parts[index] = base64.RawURLEncoding.EncodeToString(encoded)
	return strings.Join(parts, ".")
}

// rewriteSignature replaces a credential's signature with one that is
// well-formed and wrong.
func rewriteSignature(t *testing.T, authorization string) string {
	t.Helper()
	parts := strings.Split(strings.TrimPrefix(authorization, "Bearer "), ".")
	if len(parts) != 3 {
		t.Fatalf("credential is not a compact JWS")
	}
	parts[2] = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	return strings.Join(parts, ".")
}

// injectMember and removeMember corrupt an encoded document without decoding it
// first, so the corruption survives to the decoder under test. A round trip
// through a map would silently repair a duplicate member.
func injectMember(body []byte, member string) []byte {
	return append([]byte("{"+member+","), body[1:]...)
}

func removeMember(body []byte, name string) []byte {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(body, &document); err != nil {
		return body
	}
	delete(document, name)
	encoded, err := json.Marshal(document)
	if err != nil {
		return body
	}
	return encoded
}

func containsSubstring(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}

// executions is how many times an Agent was actually reached, which is what
// every refusal above ultimately has to prove.
func (h *admissionHarness) executions() int {
	if turn, ok := h.turn.(*countingTurn); ok {
		return turn.runs()
	}
	return 0
}
