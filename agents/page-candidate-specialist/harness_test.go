package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-runtimes/runtime"
)

// The Specialist is exercised against a real session over a real governed
// plane, so what these tests observe is the bytes a released unit would
// actually submit — not a candidate assembled by the test and inspected in
// place.

const (
	testCredential = "task-scoped-credential"
	traceparent    = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

	// The supplied brief. It is small on purpose: everything the Specialist may
	// use is here, so a page containing anything else came from somewhere it
	// should not have.
	componentSchemaJSON = `{"components":[` +
		`{"name":"Hero","properties":{` +
		`"title":{"type":"string","maxLength":40,"required":true},` +
		`"subtitle":{"type":"string","maxLength":80},` +
		`"align":{"type":"enum","values":["left","center"]},` +
		`"columns":{"type":"number","minimum":1,"maximum":4},` +
		`"boxed":{"type":"boolean"}}},` +
		`{"name":"Footer","properties":{"note":{"type":"string","maxLength":40}}}]}`
	defaultPropertiesJSON = `{"Hero":{"align":"center","columns":2}}`
	defaultDataJSON       = `{"Hero":{"title":"Welcome","subtitle":"a default subtitle"}}`
	styleJSON             = `{"allowedThemes":["light","dark"],"theme":"light","allowedSpacing":["compact","regular"],"spacing":"regular","maximumSections":3}`
	animationJSON         = `{"allowedEffects":["none","fade","slide"],"maximumDurationMilliseconds":600,"reducedMotion":false}`

	compositionJSON = `{"sections":[{"component":"Hero","properties":{"title":"Ship faster"},` +
		`"animation":{"effect":"fade","durationMilliseconds":300}}],` +
		`"summary":"refreshed the hero","assumptions":["the brand voice is unchanged"]}`
)

func previewArtifact() schema.SharedPrimitivesArtifactReference {
	return schema.SharedPrimitivesArtifactReference{
		ArtifactId: "artifact.preview.0001",
		Digest:     schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("a", 64)),
		MediaType:  "application/json",
		SizeBytes:  2048,
	}
}

// specialistTask is a dispatched task carrying the whole supplied brief.
func specialistTask(overrides map[string]string, inputs ...schema.SharedPrimitivesArtifactReference) schema.AgentTask {
	preview := previewArtifact()
	if inputs == nil {
		inputs = []schema.SharedPrimitivesArtifactReference{preview}
	}
	values := map[string]string{
		"model.contextDigest": "sha256:" + strings.Repeat("c", 64),
		"model.promptDigest":  "sha256:" + strings.Repeat("d", 64),
		"model.policyId":      "policy.model.default",
		"model.policyVersion": "v1",
		"model.policyDigest":  "sha256:" + strings.Repeat("e", 64),

		"candidate.target.type":                       "pagix-page",
		"candidate.target.id":                         "page.0001",
		"candidate.target.workspaceId":                "workspace.0001",
		"candidate.target.projectId":                  "project.0001",
		"candidate.baseRevision":                      "revision.0001",
		"candidate.digests.target":                    "sha256:" + strings.Repeat("5", 64),
		"candidate.digests.catalog":                   "sha256:" + strings.Repeat("6", 64),
		"candidate.digests.policy":                    "sha256:" + strings.Repeat("7", 64),
		"candidate.preview.taskId":                    "task.preview.0001",
		"candidate.preview.resultArtifact.artifactId": string(preview.ArtifactId),
		"candidate.preview.resultArtifact.digest":     string(preview.Digest),
		"candidate.preview.resultArtifact.mediaType":  preview.MediaType,
		"candidate.preview.resultArtifact.sizeBytes":  "2048",

		"page.componentSchema":      componentSchemaJSON,
		"page.defaultProperties":    defaultPropertiesJSON,
		"page.defaultData":          defaultDataJSON,
		"page.styleConstraints":     styleJSON,
		"page.animationConstraints": animationJSON,
	}
	for key, value := range overrides {
		if value == "" {
			delete(values, key)
			continue
		}
		values[key] = value
	}
	return schema.AgentTask{
		Kind:                "AgentTask",
		TaskId:              "task.0002",
		RunId:               "run.0002",
		RootRunId:           "run.0001",
		PhysicalAttemptId:   "attempt.0003",
		AttemptNumber:       1,
		ExecutionGeneration: 3,
		LeaseEpoch:          7,
		FenceToken:          "fence.0000000000003",
		Definition: schema.SharedPrimitivesDefinitionReference{
			DefinitionId:     "definition.platform.page-candidate-specialist",
			DefinitionDigest: schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("1", 64)),
		},
		ContractBomReference: schema.SharedPrimitivesContractBomReference{
			Repository:             "anvilkit/contracts",
			BomDigest:              schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("2", 64)),
			OciManifestDigest:      schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("3", 64)),
			EvidenceManifestDigest: schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("4", 64)),
		},
		ArtifactInputs: inputs,
		Parameters:     schema.SharedPrimitivesBoundedStringMap(values),
		TraceContext:   schema.SharedPrimitivesTraceContext{Traceparent: traceparent},
	}
}

// governedPlane serves the model path and the controlled artifact interface,
// and keeps every candidate that was submitted so a test can read the exact
// bytes a released unit would have sent.
type governedPlane struct {
	server *httptest.Server

	lock       sync.Mutex
	asked      int
	submitted  [][]byte
	refuseWith int
}

func planeServing(t *testing.T, output map[string]string) *governedPlane {
	t.Helper()
	plane := &governedPlane{}
	mux := http.NewServeMux()
	mux.HandleFunc(runtime.PathModelInvocations, func(w http.ResponseWriter, _ *http.Request) {
		plane.lock.Lock()
		plane.asked++
		plane.lock.Unlock()
		digest, err := runtime.CanonicalDigest(schema.SharedPrimitivesBoundedStringMap(output))
		if err != nil {
			t.Errorf("digest output: %v", err)
			return
		}
		_ = json.NewEncoder(w).Encode(schema.ModelInvocationResult{
			Kind:                "ModelInvocationResult",
			InvocationId:        "invocation.0001",
			TaskId:              "task.0002",
			PhysicalAttemptId:   "attempt.0003",
			AttemptNumber:       1,
			ExecutionGeneration: 3,
			Outcome:             schema.ModelInvocationResultOutcomeOk,
			ReasonCode:          "MODEL_COMPLETED",
			Output:              schema.SharedPrimitivesBoundedStringMap(output),
			OutputDigest:        schema.SharedPrimitivesDigest(digest),
			Usage: schema.ModelInvocationResultUsage{
				InputTokens: 11, OutputTokens: 7, DurationMilliseconds: 42,
				Cost: schema.SharedPrimitivesCost{Amount: "0.002", Currency: "USD"},
			},
			TraceContext: schema.SharedPrimitivesTraceContext{Traceparent: traceparent},
		})
	})
	mux.HandleFunc(runtime.PathRuntimeArtifacts, func(w http.ResponseWriter, r *http.Request) {
		body := drain(r)
		plane.lock.Lock()
		plane.submitted = append(plane.submitted, body)
		refuse := plane.refuseWith
		plane.lock.Unlock()
		if refuse != 0 {
			w.WriteHeader(refuse)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(recordedArtifact(body))
	})
	plane.server = httptest.NewServer(mux)
	t.Cleanup(plane.server.Close)
	return plane
}

func (p *governedPlane) session(t *testing.T) *runtime.Session {
	t.Helper()
	boundary, err := runtime.NewBoundary(p.server.URL, []string{runtime.PathModelInvocations, runtime.PathRuntimeArtifacts})
	if err != nil {
		t.Fatalf("build boundary: %v", err)
	}
	gateway, err := runtime.NewModelGateway(boundary, testCredential, 5*time.Second)
	if err != nil {
		t.Fatalf("build gateway: %v", err)
	}
	writer, err := runtime.NewArtifacts(boundary, testCredential, 5*time.Second)
	if err != nil {
		t.Fatalf("build artifacts: %v", err)
	}
	session, err := runtime.NewSession(boundary, gateway, writer)
	if err != nil {
		t.Fatalf("build session: %v", err)
	}
	return session
}

func (p *governedPlane) lastSubmission(t *testing.T) []byte {
	t.Helper()
	p.lock.Lock()
	defer p.lock.Unlock()
	if len(p.submitted) == 0 {
		t.Fatal("nothing was submitted through the controlled artifact interface")
	}
	return p.submitted[len(p.submitted)-1]
}

// recordedArtifact is the answer the control plane gives for a submission.
func recordedArtifact(body []byte) schema.AgentArtifact {
	sum := sha256Of(body)
	return schema.AgentArtifact{
		ContractType: "AgentArtifact",
		ArtifactId:   "artifact.candidate.0001",
		Kind:         schema.AgentArtifactKindAgentPlan,
		Schema: schema.SharedPrimitivesSchemaReference{
			ComponentName: "anvilkit.contract.schema.page-candidate",
			Digest:        schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("1", 64)),
		},
		Digest: schema.SharedPrimitivesDigest(sum),
		Reference: schema.AgentArtifactReference{
			Bucket:    "anvilkit-agent-artifacts",
			ObjectKey: "workspace/project/run/candidate.json",
			SizeBytes: len(body),
			MediaType: "application/json",
		},
		Lineage: []schema.SharedPrimitivesArtifactReference{},
		Producer: schema.AgentArtifactProducer{
			TaskId: "task.0002", RecoveryEpoch: 0, ExecutionGeneration: 3,
			PhysicalAttemptId: "attempt.0003", LeaseEpoch: 7,
		},
		Validation: schema.AgentArtifactValidation{
			ValidatedAt: schema.SharedPrimitivesTimestamp(mustTime()),
			Checks: []schema.AgentArtifactValidationChecksElem{{
				Name:           "schema",
				Result:         schema.AgentArtifactValidationChecksElemResultPassed,
				EvidenceDigest: schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("2", 64)),
			}},
		},
		Lifecycle: schema.AgentArtifactLifecycleValid,
		CreatedAt: schema.SharedPrimitivesTimestamp(mustTime()),
	}
}

func mustTime() time.Time {
	parsed, err := time.Parse("2006-01-02T15:04:05.000Z", "2026-08-27T00:00:00.000Z")
	if err != nil {
		panic(err)
	}
	return parsed
}

func drain(r *http.Request) []byte {
	buffer := make([]byte, 0, 4096)
	chunk := make([]byte, 4096)
	for {
		read, err := r.Body.Read(chunk)
		buffer = append(buffer, chunk[:read]...)
		if err != nil {
			return buffer
		}
	}
}

// sha256Of is the digest the control plane records for submitted bytes. It
// mirrors what the controlled artifact interface computes, because a reference
// whose digest is not about the submitted bytes is refused.
func sha256Of(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}
