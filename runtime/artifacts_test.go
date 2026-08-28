package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
)

// The controlled artifact interface is the whole of a unit's write authority.
// What these prove is that it is authority to *submit*, not to record: the
// runtime hands over bytes and believes the reference it gets back only when
// that reference is demonstrably about the bytes it sent.

func artifactServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(PathRuntimeArtifacts, handler)
	return httptest.NewServer(mux)
}

func artifactsFor(t *testing.T, origin string, released ...string) Artifacts {
	t.Helper()
	if len(released) == 0 {
		released = []string{PathRuntimeArtifacts}
	}
	guard, err := NewBoundary(origin, released)
	if err != nil {
		t.Fatalf("build boundary: %v", err)
	}
	client, err := NewArtifacts(guard, testCredential, 5*time.Second)
	if err != nil {
		t.Fatalf("build artifacts: %v", err)
	}
	return client
}

// testCandidate is a minimal well-formed candidate. Its content does not matter
// here; what matters is that submitting it produces exactly one set of bytes.
func testCandidate() schema.PageCandidate {
	digest := func(character string) schema.SharedPrimitivesDigest {
		return schema.SharedPrimitivesDigest("sha256:" + strings.Repeat(character, 64))
	}
	reference := schema.SharedPrimitivesArtifactReference{
		ArtifactId: "artifact.preview.001",
		Digest:     digest("a"),
		MediaType:  "application/json",
		SizeBytes:  128,
	}
	return schema.PageCandidate{
		Kind: "PageCandidate",
		Target: schema.SharedPrimitivesTargetReference{
			TargetType: "pagix-page", TargetId: "page.0001",
			WorkspaceId: "workspace.0001", ProjectId: "project.0001",
		},
		BaseRevision: "revision.0001",
		PageData:     reference,
		Digests: schema.PageCandidateDigests{
			TargetDigest: digest("a"), CatalogDigest: digest("b"),
			ContractBomDigest: digest("c"), DefinitionDigest: digest("d"), PolicyDigest: digest("e"),
		},
		CandidateDigest:    digest("f"),
		ValidationReceipts: []schema.SharedPrimitivesArtifactReference{},
		Preview:            schema.PageCandidatePreview{TaskId: "task.preview.0001", ResultArtifact: reference},
		Generation:         schema.PageCandidateGeneration{Summary: "a candidate", Assumptions: []string{}},
		References: schema.PageCandidateReferences{
			ModelInvocations: []schema.SharedPrimitivesOpaqueId{},
			ToolInvocations:  []schema.SharedPrimitivesOpaqueId{},
			Delegations:      []schema.SharedPrimitivesOpaqueId{},
			Evidence:         []schema.SharedPrimitivesOpaqueId{},
		},
		Warnings: []schema.PageCandidateWarningsElem{},
	}
}

// recordedArtifact renders the answer a control plane gives for a submission.
func recordedArtifact(task schema.AgentTask, digest string, size int) schema.AgentArtifact {
	return schema.AgentArtifact{
		ContractType: "AgentArtifact",
		ArtifactId:   "artifact.candidate.0001",
		Kind:         schema.AgentArtifactKindAgentPlan,
		Schema: schema.SharedPrimitivesSchemaReference{
			ComponentName: "anvilkit.contract.schema.page-candidate",
			Digest:        schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("1", 64)),
		},
		Digest: schema.SharedPrimitivesDigest(digest),
		Reference: schema.AgentArtifactReference{
			Bucket:    "anvilkit-agent-artifacts",
			ObjectKey: "workspace/project/run/candidate.json",
			SizeBytes: size,
			MediaType: "application/json",
		},
		Lineage: []schema.SharedPrimitivesArtifactReference{},
		Producer: schema.AgentArtifactProducer{
			TaskId:              task.TaskId,
			RecoveryEpoch:       0,
			ExecutionGeneration: task.ExecutionGeneration,
			PhysicalAttemptId:   task.PhysicalAttemptId,
			LeaseEpoch:          task.LeaseEpoch,
		},
		Validation: schema.AgentArtifactValidation{
			ValidatedAt: schema.SharedPrimitivesTimestamp(mustTime("2026-08-27T00:00:00.000Z")),
			Checks: []schema.AgentArtifactValidationChecksElem{{
				Name:           "schema",
				Result:         schema.AgentArtifactValidationChecksElemResultPassed,
				EvidenceDigest: schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("2", 64)),
			}},
		},
		Lifecycle: schema.AgentArtifactLifecycleValid,
		CreatedAt: schema.SharedPrimitivesTimestamp(mustTime("2026-08-27T00:00:00.000Z")),
	}
}

func mustTime(value string) time.Time {
	parsed, err := time.Parse("2006-01-02T15:04:05.000Z", value)
	if err != nil {
		panic(err)
	}
	return parsed
}

func TestASubmissionCarriesTheAttemptsOwnCredentialAndIdentity(t *testing.T) {
	task := testTask()
	var seenAuthorization, seenKey, seenDigest, seenTrace, seenType string
	var seenBody []byte
	server := artifactServer(t, func(w http.ResponseWriter, r *http.Request) {
		seenAuthorization = r.Header.Get("Authorization")
		seenKey = r.Header.Get(idempotencyHeaderName)
		seenDigest = r.Header.Get(requestDigestHeaderName)
		seenTrace = r.Header.Get(traceparentHeaderName)
		seenType = r.Header.Get("Content-Type")
		seenBody, _ = readAll(r)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(recordedArtifact(task, digestOf(seenBody), len(seenBody)))
	})
	defer server.Close()

	reference, err := artifactsFor(t, server.URL).SubmitCandidate(context.Background(), task, testCandidate())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if reference.ArtifactId != "artifact.candidate.0001" || string(reference.Digest) != digestOf(seenBody) {
		t.Fatalf("reference = %+v", reference)
	}
	if reference.SizeBytes != len(seenBody) || reference.MediaType != "application/json" {
		t.Fatalf("reference = %+v", reference)
	}
	// A unit holds no durable write authority: the same short-lived credential
	// the model path uses is what opens this one.
	if seenAuthorization != "Bearer "+testCredential || seenType != "application/json" {
		t.Fatalf("authorization = %q content type = %q", seenAuthorization, seenType)
	}
	// The submission is deduplicated by the attempt and the operation, so a
	// retried turn replays the record instead of producing a second immutable
	// artifact for the same work.
	if seenKey != string(task.PhysicalAttemptId)+":artifact.candidate" {
		t.Fatalf("idempotency key = %q", seenKey)
	}
	if seenDigest != digestOf(seenBody) || seenTrace != task.TraceContext.Traceparent {
		t.Fatalf("digest = %q traceparent = %q", seenDigest, seenTrace)
	}
}

// A redirect is not followed: the submission carries the candidate and the
// attempt's credential, and neither is delivered anywhere the release did not
// name.
func TestASubmissionDoesNotFollowARedirect(t *testing.T) {
	forwarded := 0
	mux := http.NewServeMux()
	mux.HandleFunc(PathRuntimeArtifacts, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusPermanentRedirect)
	})
	mux.HandleFunc("/elsewhere", func(w http.ResponseWriter, _ *http.Request) {
		forwarded++
		w.WriteHeader(http.StatusCreated)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	if _, err := artifactsFor(t, server.URL).SubmitCandidate(context.Background(), testTask(), testCandidate()); err == nil {
		t.Fatal("a redirected submission was reported as recorded")
	}
	if forwarded != 0 {
		t.Fatal("the candidate and its credential followed a redirect")
	}
}

func TestTheBytesSubmittedAreCanonicalAndAreWhatTheDigestCovers(t *testing.T) {
	task := testTask()
	var first, second []byte
	server := artifactServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := readAll(r)
		if first == nil {
			first = body
		} else {
			second = body
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(recordedArtifact(task, digestOf(body), len(body)))
	})
	defer server.Close()

	client := artifactsFor(t, server.URL)
	for i := 0; i < 2; i++ {
		if _, err := client.SubmitCandidate(context.Background(), task, testCandidate()); err != nil {
			t.Fatalf("submit: %v", err)
		}
	}
	// Canonical bytes, not language-native serialization: the control plane
	// verifies this digest with a different implementation, and two encodings
	// of the same value would produce two digests for one document.
	if string(first) != string(second) {
		t.Fatalf("the same candidate submitted two different byte sequences:\n%s\n%s", first, second)
	}
	canonical, err := canonicalBytes(testCandidate())
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if string(first) != string(canonical) {
		t.Fatalf("the submitted bytes are not the canonical bytes:\n%s\n%s", first, canonical)
	}
}

func TestAReferenceThatIsNotAboutTheSubmittedDocumentIsRefused(t *testing.T) {
	task := testTask()
	for name, corrupt := range map[string]func(*schema.AgentArtifact, []byte){
		"another document's digest": func(a *schema.AgentArtifact, _ []byte) {
			a.Digest = schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("9", 64))
		},
		"another document's size": func(a *schema.AgentArtifact, body []byte) { a.Reference.SizeBytes = len(body) + 1 },
		"no identity":             func(a *schema.AgentArtifact, _ []byte) { a.ArtifactId = "" },
	} {
		t.Run(name, func(t *testing.T) {
			server := artifactServer(t, func(w http.ResponseWriter, r *http.Request) {
				body, _ := readAll(r)
				recorded := recordedArtifact(task, digestOf(body), len(body))
				corrupt(&recorded, body)
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(recorded)
			})
			defer server.Close()
			// Returning this reference would hand the control plane a pointer to
			// a document the runtime never produced.
			_, err := artifactsFor(t, server.URL).SubmitCandidate(context.Background(), task, testCandidate())
			var write ArtifactWriteError
			if !errors.As(err, &write) {
				t.Fatalf("a reference that is not about the submitted document was accepted: %v", err)
			}
		})
	}
}

func TestAReplayedSubmissionIsTheSameFactAsANewOne(t *testing.T) {
	task := testTask()
	server := artifactServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := readAll(r)
		// 200 with Idempotency-Replayed is what a retry of the same attempt and
		// the same bytes gets. For a runtime that is the same fact as a 201:
		// the artifact exists and this is its reference.
		w.Header().Set(replayedHeaderName, "true")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(recordedArtifact(task, digestOf(body), len(body)))
	})
	defer server.Close()

	if _, err := artifactsFor(t, server.URL).SubmitCandidate(context.Background(), task, testCandidate()); err != nil {
		t.Fatalf("a replayed submission was treated as a failure: %v", err)
	}
}

func TestAUnitNotReleasedToWriteArtifactsHasNoWriter(t *testing.T) {
	guard, err := NewBoundary(testControlPlane, []string{PathModelInvocations})
	if err != nil {
		t.Fatalf("build boundary: %v", err)
	}
	// A Manager produces no artifacts and is released without the path. The
	// difference between "this release does not write artifacts" and "this
	// write failed" has to be visible, and it is visible here.
	if _, err := NewArtifacts(guard, testCredential, time.Second); err == nil {
		t.Fatal("a writer was built for a path this release does not carry")
	}
	if _, err := NewArtifacts(nil, testCredential, time.Second); err == nil {
		t.Fatal("a writer was built with no boundary")
	}
	released, err := NewBoundary(testControlPlane, []string{PathRuntimeArtifacts})
	if err != nil {
		t.Fatalf("build boundary: %v", err)
	}
	if _, err := NewArtifacts(released, "", time.Second); err == nil {
		t.Fatal("a writer was built without a task-scoped credential")
	}
	if _, err := NewArtifacts(released, testCredential, 0); err == nil {
		t.Fatal("a writer was built with no timeout")
	}
}

func TestASubmissionFailureNamesTheInterfaceAndNotTheDestination(t *testing.T) {
	server := artifactServer(t, func(http.ResponseWriter, *http.Request) {})
	origin := server.URL
	server.Close()

	_, err := artifactsFor(t, origin).SubmitCandidate(context.Background(), testTask(), testCandidate())
	if err == nil {
		t.Fatal("a dead artifact path was reported as success")
	}
	if strings.Contains(err.Error(), strings.TrimPrefix(origin, "http://")) {
		t.Fatalf("the failure echoed the internal destination: %v", err)
	}
}

func TestAnAnswerThatIsNotARecordedArtifactIsRefused(t *testing.T) {
	for name, answer := range map[string]string{
		"not json":       `{{{`,
		"unknown member": `{"contractType":"AgentArtifact","surprise":true}`,
		"empty":          ``,
	} {
		t.Run(name, func(t *testing.T) {
			server := artifactServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(answer))
			})
			defer server.Close()
			if _, err := artifactsFor(t, server.URL).SubmitCandidate(context.Background(), testTask(), testCandidate()); err == nil {
				t.Fatalf("a non-conforming answer was accepted: %s", answer)
			}
		})
	}
}

// readAll drains a request body without a bound, which is acceptable only in a
// test double standing in for the control plane.
func readAll(r *http.Request) ([]byte, error) {
	buffer := make([]byte, 0, 4096)
	chunk := make([]byte, 4096)
	for {
		read, err := r.Body.Read(chunk)
		buffer = append(buffer, chunk[:read]...)
		if err != nil {
			return buffer, nil
		}
	}
}
