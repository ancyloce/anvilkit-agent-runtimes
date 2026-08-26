package runtime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The gateway is a runtime unit's only way out of its process. What matters is
// that it can only reach where it was released to reach, that it carries the
// task's credential and nothing more durable, that it never decides to try
// again, and that a hostile answer cannot exhaust it.

func gatewayFor(t *testing.T, endpoint string) (*ModelGateway, *Boundary) {
	t.Helper()
	guard, err := NewBoundary(endpoint, nil)
	if err != nil {
		t.Fatalf("build boundary: %v", err)
	}
	gateway, err := NewModelGateway(guard, endpoint, "task-scoped-token", 5*time.Second)
	if err != nil {
		t.Fatalf("build gateway: %v", err)
	}
	return gateway, guard
}

func TestAGatewayCannotBeBuiltOutsideItsBoundary(t *testing.T) {
	guard, err := NewBoundary("https://gateway.internal/v1/models", nil)
	if err != nil {
		t.Fatalf("build boundary: %v", err)
	}
	// Checked at construction, not at call time: a unit configured to talk
	// somewhere it was not released to talk fails at start rather than on its
	// first real turn.
	if _, err := NewModelGateway(guard, "https://elsewhere.example/v1/models", "token", time.Second); err == nil {
		t.Fatal("a gateway was built for a destination outside the boundary")
	}
	if _, err := NewModelGateway(nil, "https://gateway.internal/v1/models", "token", time.Second); err == nil {
		t.Fatal("a gateway was built with no boundary")
	}
	// A credential arrives with the task or not at all.
	if _, err := NewModelGateway(guard, "https://gateway.internal/v1/models", "", time.Second); err == nil {
		t.Fatal("a gateway was built without a task-scoped credential")
	}
	if _, err := NewModelGateway(guard, "https://gateway.internal/v1/models", "token", 0); err == nil {
		t.Fatal("a gateway was built with no timeout")
	}
}

func TestAPromptCarriesTheTaskCredentialAndNoProviderChoice(t *testing.T) {
	var seenAuthorization, seenBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuthorization = r.Header.Get("Authorization")
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		seenBody = string(body)
		_ = json.NewEncoder(w).Encode(Completion{Output: "answer", InputTokens: 11, OutputTokens: 7})
	}))
	defer server.Close()

	gateway, _ := gatewayFor(t, server.URL)
	completion, err := gateway.Invoke(context.Background(), Prompt{Capability: "page.compose", Input: "hello"})
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if completion.Output != "answer" || completion.InputTokens != 11 || completion.OutputTokens != 7 {
		t.Fatalf("completion = %+v", completion)
	}
	if seenAuthorization != "Bearer task-scoped-token" {
		t.Fatalf("authorization = %q", seenAuthorization)
	}
	// The runtime never learns which provider serves a request, so the prompt
	// carries no model, provider, or routing hint for it to have chosen.
	for _, forbidden := range []string{"provider", "model", "endpoint", "apiKey", "route"} {
		if strings.Contains(seenBody, forbidden) {
			t.Fatalf("the prompt carried a routing decision the runtime may not make: %q in %s", forbidden, seenBody)
		}
	}
}

func TestTheGatewayNeverRetriesOnItsOwn(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	gateway, _ := gatewayFor(t, server.URL)
	if _, err := gateway.Invoke(context.Background(), Prompt{Capability: "page.compose", Input: "hello"}); err == nil {
		t.Fatal("a refused invocation was reported as success")
	}
	// Retry, backoff, and replacement dispatch are the scheduler's decisions. A
	// runtime that retried would spend budget nobody agreed to.
	if got := attempts.Load(); got != 1 {
		t.Fatalf("attempts = %d, want exactly 1", got)
	}
}

func TestAnAnswerLargerThanTheBoundIsRefusedRatherThanRead(t *testing.T) {
	// Deliberately *valid* JSON, and larger than the 1 MiB bound. That makes
	// the test a discriminator rather than a formality: truncating at the limit
	// cuts the string mid-value and fails to parse, while an unbounded read
	// would parse it happily and succeed. An oversized blob of garbage would
	// fail either way and would prove nothing about the bound.
	oversized := Completion{Output: strings.Repeat("a", (1<<20)+(1<<16)), InputTokens: 1, OutputTokens: 1}
	encoded, err := json.Marshal(oversized)
	if err != nil {
		t.Fatalf("encode oversized answer: %v", err)
	}
	if len(encoded) <= 1<<20 {
		t.Fatalf("the fixture is not larger than the bound: %d bytes", len(encoded))
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(encoded)
	}))
	defer server.Close()

	gateway, _ := gatewayFor(t, server.URL)
	if _, err := gateway.Invoke(context.Background(), Prompt{Capability: "page.compose", Input: "hello"}); err == nil {
		t.Fatal("an answer past the bound was read in full and accepted")
	}
}

func TestATransportFailureDoesNotEchoInternalTopology(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	endpoint := server.URL
	server.Close() // nothing is listening now

	gateway, _ := gatewayFor(t, endpoint)
	_, err := gateway.Invoke(context.Background(), Prompt{Capability: "page.compose", Input: "hello"})
	if err == nil {
		t.Fatal("a dead gateway was reported as success")
	}
	// Diagnostics travel back to the control plane inside a result, so a
	// transport error naming internal hosts or ports would leak topology.
	host := strings.TrimPrefix(endpoint, "http://")
	if strings.Contains(err.Error(), host) {
		t.Fatalf("the failure echoed the internal destination: %v", err)
	}
}

func TestAnAnswerThatIsNotACompletionIsRefused(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`not json at all`))
	}))
	defer server.Close()

	gateway, _ := gatewayFor(t, server.URL)
	if _, err := gateway.Invoke(context.Background(), Prompt{Capability: "page.compose", Input: "hello"}); err == nil {
		t.Fatal("a non-completion answer was accepted")
	}
}
