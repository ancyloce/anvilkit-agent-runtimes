package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
)

// The gateway is a runtime unit's only way out of its process. What matters is
// that it can only reach where it was released to reach, that it carries the
// task's credential and nothing more durable, that it names the governed inputs
// rather than sending them, that it never decides to try again, and that a
// hostile answer cannot exhaust it or be believed without proof.

// governedServer stands in for the Agent Service runtime boundary. It serves
// the canonical path and nothing else, so a client reaching anywhere else finds
// a 404 rather than a helpful answer.
func governedServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(PathModelInvocations, handler)
	return httptest.NewServer(mux)
}

func gatewayFor(t *testing.T, origin string, released ...string) (*ModelGateway, *Boundary) {
	t.Helper()
	if len(released) == 0 {
		released = []string{PathModelInvocations}
	}
	guard, err := NewBoundary(origin, released)
	if err != nil {
		t.Fatalf("build boundary: %v", err)
	}
	gateway, err := NewModelGateway(guard, testCredential, 5*time.Second)
	if err != nil {
		t.Fatalf("build gateway: %v", err)
	}
	return gateway, guard
}

// governedPrompt is a complete, well-formed invocation: the digests and the
// policy the control plane pinned, and nothing the runtime chose.
func governedPrompt() Prompt {
	return Prompt{
		Operation:     "model.plan",
		ContextDigest: "sha256:" + strings.Repeat("c", 64),
		PromptDigest:  "sha256:" + strings.Repeat("d", 64),
		ModelPolicy: schema.SharedPrimitivesPolicyReference{
			PolicyId: "policy.model.default",
			Version:  "v1",
			Digest:   schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("e", 64)),
		},
	}
}

// governedResult renders a conformant answer for one task, with the output
// digest the gateway is obliged to attest.
func governedResult(t *testing.T, task schema.AgentTask, output map[string]string) schema.ModelInvocationResult {
	t.Helper()
	digest, err := canonicalDigest(schema.SharedPrimitivesBoundedStringMap(output))
	if err != nil {
		t.Fatalf("digest output: %v", err)
	}
	return schema.ModelInvocationResult{
		Kind:                "ModelInvocationResult",
		InvocationId:        "invocation.0001",
		TaskId:              task.TaskId,
		PhysicalAttemptId:   task.PhysicalAttemptId,
		AttemptNumber:       task.AttemptNumber,
		ExecutionGeneration: task.ExecutionGeneration,
		Outcome:             schema.ModelInvocationResultOutcomeOk,
		ReasonCode:          "MODEL_COMPLETED",
		Output:              schema.SharedPrimitivesBoundedStringMap(output),
		OutputDigest:        schema.SharedPrimitivesDigest(digest),
		Usage: schema.ModelInvocationResultUsage{
			InputTokens:          11,
			OutputTokens:         7,
			DurationMilliseconds: 42,
			Cost:                 schema.SharedPrimitivesCost{Amount: "0.002", Currency: "USD"},
		},
		TraceContext: task.TraceContext,
	}
}

func TestAGatewayCannotBeBuiltOutsideItsReleasedBoundary(t *testing.T) {
	// A unit released without the governed model path has no model path at
	// all. Failing at construction is deliberate: a unit configured to reason
	// on a route nobody released it for should not discover that on its first
	// real turn.
	unreleased, err := NewBoundary("https://control.internal", []string{PathRuntimeArtifacts})
	if err != nil {
		t.Fatalf("build boundary: %v", err)
	}
	if _, err := NewModelGateway(unreleased, testCredential, time.Second); err == nil {
		t.Fatal("a gateway was built for a path this release does not carry")
	}
	released, err := NewBoundary("https://control.internal", []string{PathModelInvocations})
	if err != nil {
		t.Fatalf("build boundary: %v", err)
	}
	if _, err := NewModelGateway(nil, testCredential, time.Second); err == nil {
		t.Fatal("a gateway was built with no boundary")
	}
	// A credential arrives with the task or not at all.
	if _, err := NewModelGateway(released, "", time.Second); err == nil {
		t.Fatal("a gateway was built without a task-scoped credential")
	}
	if _, err := NewModelGateway(released, testCredential, 0); err == nil {
		t.Fatal("a gateway was built with no timeout")
	}
}

func TestABoundaryRefusesAnythingThatIsNotAnOrigin(t *testing.T) {
	for name, destination := range map[string]string{
		"a route":      "https://control.internal/v1/internal/runtime/model-invocations",
		"a query":      "https://control.internal?to=elsewhere",
		"no scheme":    "control.internal",
		"wrong scheme": "file:///etc/passwd",
		"empty":        "   ",
	} {
		t.Run(name, func(t *testing.T) {
			// The deployment says where the control plane is; the release says
			// which routes on it may be used. A base carrying a route would let
			// a deployment answer the release's question.
			if _, err := NewBoundary(destination, []string{PathModelInvocations}); err == nil {
				t.Fatalf("%q was accepted as a control-plane origin", destination)
			}
		})
	}
}

func TestAnInvocationCarriesTheTaskCredentialAndNoProviderChoice(t *testing.T) {
	var seenAuthorization, seenBody, seenKey, seenDigest, seenTrace string
	task := testTask()
	server := governedServer(t, func(w http.ResponseWriter, r *http.Request) {
		seenAuthorization = r.Header.Get("Authorization")
		seenKey = r.Header.Get(idempotencyHeaderName)
		seenDigest = r.Header.Get(requestDigestHeaderName)
		seenTrace = r.Header.Get(traceparentHeaderName)
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		seenBody = string(body)
		_ = json.NewEncoder(w).Encode(governedResult(t, task, map[string]string{"plan": "{}"}))
	})
	defer server.Close()

	gateway, _ := gatewayFor(t, server.URL)
	completion, err := gateway.Invoke(context.Background(), task, governedPrompt())
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if completion.InvocationID != "invocation.0001" || completion.InputTokens != 11 || completion.OutputTokens != 7 {
		t.Fatalf("completion = %+v", completion)
	}
	if seenAuthorization != "Bearer "+testCredential {
		t.Fatalf("authorization = %q", seenAuthorization)
	}
	// The canonical boundary makes all three of these required parameters, and
	// the idempotency identity is the attempt and the operation: a retry of the
	// same turn must replay the answer it already bought.
	if seenKey != string(task.PhysicalAttemptId)+":model.plan" {
		t.Fatalf("idempotency key = %q", seenKey)
	}
	if !digestPattern.MatchString(seenDigest) || seenTrace != task.TraceContext.Traceparent {
		t.Fatalf("request digest = %q traceparent = %q", seenDigest, seenTrace)
	}
	// The runtime never learns which provider serves a request, so the
	// invocation carries no model, provider, or routing hint for it to have
	// chosen — and no prompt text either: it names the compiled context and the
	// prompt by digest, so it cannot send text nobody compiled.
	for _, forbidden := range []string{"provider", "\"model\"", "endpoint", "apiKey", "route", "prompt\":\"", "input"} {
		if strings.Contains(seenBody, forbidden) {
			t.Fatalf("the invocation carried something the runtime may not choose: %q in %s", forbidden, seenBody)
		}
	}
}

func TestAnInvocationWithoutItsPinnedInputsIsNotSent(t *testing.T) {
	var reached atomic.Int32
	server := governedServer(t, func(http.ResponseWriter, *http.Request) { reached.Add(1) })
	defer server.Close()
	gateway, _ := gatewayFor(t, server.URL)

	for name, prompt := range map[string]Prompt{
		"no operation":     {ContextDigest: governedPrompt().ContextDigest, PromptDigest: governedPrompt().PromptDigest, ModelPolicy: governedPrompt().ModelPolicy},
		"no context":       {Operation: "model.plan", PromptDigest: governedPrompt().PromptDigest, ModelPolicy: governedPrompt().ModelPolicy},
		"no prompt digest": {Operation: "model.plan", ContextDigest: governedPrompt().ContextDigest, ModelPolicy: governedPrompt().ModelPolicy},
		"no policy":        {Operation: "model.plan", ContextDigest: governedPrompt().ContextDigest, PromptDigest: governedPrompt().PromptDigest},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := gateway.Invoke(context.Background(), testTask(), prompt); err == nil {
				t.Fatal("an invocation missing a pinned input was sent")
			}
		})
	}
	// None of them reached the gateway: an incomplete invocation is refused
	// here rather than turned into a question the gateway has to answer.
	if reached.Load() != 0 {
		t.Fatalf("%d incomplete invocations were sent", reached.Load())
	}
}

func TestTheGatewayNeverRetriesOnItsOwn(t *testing.T) {
	var attempts atomic.Int32
	server := governedServer(t, func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	defer server.Close()

	gateway, _ := gatewayFor(t, server.URL)
	if _, err := gateway.Invoke(context.Background(), testTask(), governedPrompt()); err == nil {
		t.Fatal("a refused invocation was reported as success")
	}
	// Retry, backoff, and replacement dispatch are the scheduler's decisions. A
	// runtime that retried would spend budget nobody agreed to.
	if got := attempts.Load(); got != 1 {
		t.Fatalf("attempts = %d, want exactly 1", got)
	}
}

// A redirect is not followed. The invocation carries the attempt's credential,
// and a client that followed the answer wherever it pointed would deliver that
// credential to a destination the release never named.
func TestARedirectIsNotFollowedWithTheCredential(t *testing.T) {
	var forwarded atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc(PathModelInvocations, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/elsewhere", func(w http.ResponseWriter, _ *http.Request) {
		forwarded.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	gateway, _ := gatewayFor(t, server.URL)
	if _, err := gateway.Invoke(context.Background(), testTask(), governedPrompt()); err == nil {
		t.Fatal("a redirected invocation was reported as success")
	}
	if forwarded.Load() != 0 {
		t.Fatal("the credential followed a redirect")
	}
}

func TestAnAnswerForAnotherAttemptIsNotBelieved(t *testing.T) {
	task := testTask()
	server := governedServer(t, func(w http.ResponseWriter, _ *http.Request) {
		result := governedResult(t, task, map[string]string{"plan": "{}"})
		// The same task, a different physical attempt: a gateway answering with
		// another attempt's result would attribute its tokens, and its output,
		// to work that did not ask for it.
		result.PhysicalAttemptId = "attempt.9999"
		_ = json.NewEncoder(w).Encode(result)
	})
	defer server.Close()

	gateway, _ := gatewayFor(t, server.URL)
	if _, err := gateway.Invoke(context.Background(), task, governedPrompt()); err == nil {
		t.Fatal("a result belonging to another attempt was accepted")
	}
}

func TestOutputIsCheckedAgainstTheDigestTheGatewayAttested(t *testing.T) {
	task := testTask()
	server := governedServer(t, func(w http.ResponseWriter, _ *http.Request) {
		result := governedResult(t, task, map[string]string{"plan": "{}"})
		// The digest still covers the original output; the output does not.
		// A runtime that composed from this would be reasoning over bytes no
		// invocation record covers.
		result.Output = schema.SharedPrimitivesBoundedStringMap{"plan": `{"kind":"AgentPlan"}`}
		_ = json.NewEncoder(w).Encode(result)
	})
	defer server.Close()

	gateway, _ := gatewayFor(t, server.URL)
	if _, err := gateway.Invoke(context.Background(), task, governedPrompt()); err == nil {
		t.Fatal("output that did not match its attested digest was accepted")
	}
}

func TestAGovernedRefusalIsReportedAsARefusalNotAFailure(t *testing.T) {
	task := testTask()
	server := governedServer(t, func(w http.ResponseWriter, _ *http.Request) {
		result := governedResult(t, task, map[string]string{})
		result.Outcome = schema.ModelInvocationResultOutcomeRefused
		result.ReasonCode = "MODEL_REFUSED_BY_POLICY"
		_ = json.NewEncoder(w).Encode(result)
	})
	defer server.Close()

	gateway, _ := gatewayFor(t, server.URL)
	_, err := gateway.Invoke(context.Background(), task, governedPrompt())
	var refused ModelRefusedError
	if !errors.As(err, &refused) {
		t.Fatalf("a governed refusal was not distinguishable from a failure: %v", err)
	}
	// The two are different facts, and the scheduler acts differently on them:
	// a refusal is the governed path working and saying no, and retrying it
	// would spend budget re-asking a question that was answered.
	if refused.ReasonCode != "MODEL_REFUSED_BY_POLICY" {
		t.Fatalf("reason = %q", refused.ReasonCode)
	}
}

func TestAnAnswerLargerThanTheBoundIsRefusedRatherThanRead(t *testing.T) {
	// Deliberately *valid* JSON, and larger than the 1 MiB bound. That makes
	// the test a discriminator rather than a formality: truncating at the limit
	// cuts the string mid-value and fails to parse, while an unbounded read
	// would parse it happily and succeed. An oversized blob of garbage would
	// fail either way and would prove nothing about the bound.
	task := testTask()
	oversized := governedResult(t, task, map[string]string{"plan": strings.Repeat("a", (1<<20)+(1<<16))})
	encoded, err := json.Marshal(oversized)
	if err != nil {
		t.Fatalf("encode oversized answer: %v", err)
	}
	if len(encoded) <= maximumGovernedResponseBytes {
		t.Fatalf("the fixture is not larger than the bound: %d bytes", len(encoded))
	}
	server := governedServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(encoded)
	})
	defer server.Close()

	gateway, _ := gatewayFor(t, server.URL)
	if _, err := gateway.Invoke(context.Background(), task, governedPrompt()); err == nil {
		t.Fatal("an answer past the bound was read in full and accepted")
	}
}

func TestATransportFailureDoesNotEchoInternalTopology(t *testing.T) {
	server := governedServer(t, func(http.ResponseWriter, *http.Request) {})
	origin := server.URL
	server.Close() // nothing is listening now

	gateway, _ := gatewayFor(t, origin)
	_, err := gateway.Invoke(context.Background(), testTask(), governedPrompt())
	if err == nil {
		t.Fatal("a dead gateway was reported as success")
	}
	// Diagnostics travel back to the control plane inside a result, so a
	// transport error naming internal hosts or ports would leak topology.
	host := strings.TrimPrefix(origin, "http://")
	if strings.Contains(err.Error(), host) {
		t.Fatalf("the failure echoed the internal destination: %v", err)
	}
}

func TestAnAnswerThatIsNotAGovernedResultIsRefused(t *testing.T) {
	for name, answer := range map[string]string{
		"not json":       `not json at all`,
		"unknown member": `{"kind":"ModelInvocationResult","surprise":true}`,
		"trailing value": `{"kind":"ModelInvocationResult"} {"kind":"ModelInvocationResult"}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := governedServer(t, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(answer))
			})
			defer server.Close()
			gateway, _ := gatewayFor(t, server.URL)
			if _, err := gateway.Invoke(context.Background(), testTask(), governedPrompt()); err == nil {
				t.Fatalf("a non-conforming answer was accepted: %s", answer)
			}
		})
	}
}
