package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-runtimes/runtime"
)

// The Manager's turns are exercised against a real session over a real
// governed plane. A test that handed the Manager a hand-built decision would
// prove the Manager's switch statement and nothing about what a released unit
// does with what a gateway actually answers.

const (
	testCredential = "task-scoped-credential"
	traceparent    = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
)

// managerTask is a dispatched task carrying the context a Manager compiles.
func managerTask(parameters map[string]string, inputs ...schema.SharedPrimitivesArtifactReference) schema.AgentTask {
	if inputs == nil {
		inputs = []schema.SharedPrimitivesArtifactReference{}
	}
	values := map[string]string{
		"model.contextDigest": "sha256:" + strings.Repeat("c", 64),
		"model.promptDigest":  "sha256:" + strings.Repeat("d", 64),
		"model.policyId":      "policy.model.default",
		"model.policyVersion": "v1",
		"model.policyDigest":  "sha256:" + strings.Repeat("e", 64),
	}
	for key, value := range parameters {
		values[key] = value
	}
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
		Definition: schema.SharedPrimitivesDefinitionReference{
			DefinitionId:     "definition.platform.page-change-manager",
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

// governedPlane answers the model path with whatever the test scripts, and
// counts what was asked. A Manager that consulted a model on a turn it should
// not have is visible as a count, not inferred.
type governedPlane struct {
	server *httptest.Server
	asked  int
}

func planeServing(t *testing.T, output map[string]string) *governedPlane {
	t.Helper()
	plane := &governedPlane{}
	mux := http.NewServeMux()
	mux.HandleFunc(runtime.PathModelInvocations, func(w http.ResponseWriter, _ *http.Request) {
		plane.asked++
		digest, err := runtime.CanonicalDigest(schema.SharedPrimitivesBoundedStringMap(output))
		if err != nil {
			t.Errorf("digest output: %v", err)
			return
		}
		_ = json.NewEncoder(w).Encode(schema.ModelInvocationResult{
			Kind:                "ModelInvocationResult",
			InvocationId:        "invocation.0001",
			TaskId:              "task.0001",
			PhysicalAttemptId:   "attempt.0002",
			AttemptNumber:       2,
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
	plane.server = httptest.NewServer(mux)
	t.Cleanup(plane.server.Close)
	return plane
}

// session composes what a Manager release may reach: the governed model path
// and nothing else. A Manager produces no artifacts, so it is deliberately not
// released with the artifact path.
func (p *governedPlane) session(t *testing.T) *runtime.Session {
	t.Helper()
	boundary, err := runtime.NewBoundary(p.server.URL, []string{runtime.PathModelInvocations})
	if err != nil {
		t.Fatalf("build boundary: %v", err)
	}
	gateway, err := runtime.NewModelGateway(boundary, testCredential, 5*time.Second)
	if err != nil {
		t.Fatalf("build gateway: %v", err)
	}
	session, err := runtime.NewSession(boundary, gateway, nil)
	if err != nil {
		t.Fatalf("build session: %v", err)
	}
	return session
}

// planOutput renders one governed output carrying a plan document.
func planOutput(plan string) map[string]string {
	return map[string]string{"plan": plan}
}
