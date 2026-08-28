package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
)

// A session is where an attempt's usage is *observed*. The Agent never declares
// what it spent, because it never touches the numbers: everything it can do
// goes through this object, so under-reporting would require not doing the work.

// governedPlane serves both canonical paths, so a session can be built the way
// a real turn builds one.
func governedPlane(t *testing.T, model, artifacts http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	if model != nil {
		mux.HandleFunc(PathModelInvocations, model)
	}
	if artifacts != nil {
		mux.HandleFunc(PathRuntimeArtifacts, artifacts)
	}
	return httptest.NewServer(mux)
}

func sessionFor(t *testing.T, origin string, released ...string) *Session {
	t.Helper()
	guard, err := NewBoundary(origin, released)
	if err != nil {
		t.Fatalf("build boundary: %v", err)
	}
	var gateway *ModelGateway
	if guard.AllowControlPlane(PathModelInvocations) == nil {
		gateway, err = NewModelGateway(guard, testCredential, 5*time.Second)
		if err != nil {
			t.Fatalf("build gateway: %v", err)
		}
	}
	var writer Artifacts
	if guard.AllowControlPlane(PathRuntimeArtifacts) == nil {
		writer, err = NewArtifacts(guard, testCredential, 5*time.Second)
		if err != nil {
			t.Fatalf("build artifacts: %v", err)
		}
	}
	session, err := NewSession(guard, gateway, writer)
	if err != nil {
		t.Fatalf("build session: %v", err)
	}
	return session
}

func TestUsageIsMeasuredByTheSessionRatherThanDeclared(t *testing.T) {
	task := testTask()
	calls := 0
	server := governedPlane(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		result := governedResult(t, task, map[string]string{"plan": "{}"})
		result.InvocationId = schema.SharedPrimitivesOpaqueId("invocation.000" + string(rune('0'+calls)))
		result.Usage.Cost.Amount = "0.0015"
		_ = json.NewEncoder(w).Encode(result)
	}, func(w http.ResponseWriter, r *http.Request) {
		body, _ := readAll(r)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(recordedArtifact(task, digestOf(body), len(body)))
	})
	defer server.Close()

	session := sessionFor(t, server.URL, PathModelInvocations, PathRuntimeArtifacts)
	for _, operation := range []string{"model.plan", "model.compose"} {
		prompt := governedPrompt()
		prompt.Operation = operation
		if _, err := session.Model(context.Background(), task, prompt); err != nil {
			t.Fatalf("invoke: %v", err)
		}
	}
	if _, err := session.SubmitCandidate(context.Background(), task, testCandidate()); err != nil {
		t.Fatalf("submit: %v", err)
	}

	usage := session.Usage()
	if usage.ModelCalls != 2 || usage.ToolCalls != 1 {
		t.Fatalf("usage = %+v", usage)
	}
	if usage.InputTokens != 22 || usage.OutputTokens != 14 {
		t.Fatalf("usage = %+v", usage)
	}
	// Cost is summed exactly. A runtime that floated two costs together would
	// report a number nobody could reconcile against the invocation records the
	// control plane settled from.
	if usage.CostAmount != "0.003" || usage.CostCurrency != "USD" {
		t.Fatalf("cost = %q %q", usage.CostAmount, usage.CostCurrency)
	}
	// Every governed invocation is recorded in order, so a candidate can name
	// the model decisions that went into it.
	invocations := session.ModelInvocations()
	if len(invocations) != 2 || invocations[0] != "invocation.0001" || invocations[1] != "invocation.0002" {
		t.Fatalf("invocations = %v", invocations)
	}
}

func TestAnAttemptThatSpentTokensAndThenFailedStillReportsThem(t *testing.T) {
	task := testTask()
	server := governedPlane(t, func(w http.ResponseWriter, _ *http.Request) {
		result := governedResult(t, task, map[string]string{})
		result.Outcome = schema.ModelInvocationResultOutcomeRefused
		result.ReasonCode = "MODEL_REFUSED_BY_POLICY"
		_ = json.NewEncoder(w).Encode(result)
	}, nil)
	defer server.Close()

	session := sessionFor(t, server.URL, PathModelInvocations)
	if _, err := session.Model(context.Background(), task, governedPrompt()); err == nil {
		t.Fatal("a governed refusal was reported as success")
	}
	// A refused invocation still spent what the gateway metered for it. An
	// attempt that reported only its successful calls would understate what the
	// control plane has to settle.
	usage := session.Usage()
	if usage.ModelCalls != 1 || usage.InputTokens != 11 || usage.CostAmount != "0.002" {
		t.Fatalf("usage after a refusal = %+v", usage)
	}
}

func TestACapabilityThisReleaseDoesNotCarryRefusesRatherThanPanics(t *testing.T) {
	// A Manager is released without the artifact path; a unit released without
	// the model path was not released to reason. Both are the released boundary
	// answering, not a configuration accident.
	noModel := sessionFor(t, testControlPlane, PathRuntimeArtifacts)
	_, err := noModel.Model(context.Background(), testTask(), governedPrompt())
	var boundary *BoundaryError
	if !errors.As(err, &boundary) || boundary.Refusal != RefuseUnknownDestination {
		t.Fatalf("a model call on a release without the model path = %v", err)
	}
	noArtifacts := sessionFor(t, testControlPlane, PathModelInvocations)
	_, err = noArtifacts.SubmitCandidate(context.Background(), testTask(), testCandidate())
	if !errors.As(err, &boundary) || boundary.Refusal != RefuseUnknownDestination {
		t.Fatalf("an artifact write on a release without the artifact path = %v", err)
	}
	if _, err := NewSession(nil, nil, nil); err == nil {
		t.Fatal("a session was built with no boundary")
	}
}

func TestTwoCurrenciesInOneAttemptAreReportedRatherThanAdded(t *testing.T) {
	task := testTask()
	currencies := []string{"USD", "EUR"}
	server := governedPlane(t, func(w http.ResponseWriter, _ *http.Request) {
		result := governedResult(t, task, map[string]string{"plan": "{}"})
		result.Usage.Cost.Currency = currencies[0]
		currencies = currencies[1:]
		_ = json.NewEncoder(w).Encode(result)
	}, nil)
	defer server.Close()

	session := sessionFor(t, server.URL, PathModelInvocations)
	for _, operation := range []string{"model.plan", "model.compose"} {
		prompt := governedPrompt()
		prompt.Operation = operation
		if _, err := session.Model(context.Background(), task, prompt); err != nil {
			t.Fatalf("invoke: %v", err)
		}
	}
	// Two currencies cannot be added, and picking one would invent a number.
	// The consumption is still reported; only the arithmetic is withheld, and
	// the diagnostic says so.
	usage := session.Usage()
	if usage.ModelCalls != 2 || usage.CostAmount != "0.002" || usage.CostCurrency != "USD" {
		t.Fatalf("usage = %+v", usage)
	}
	if !hasDiagnostic(session.Diagnostics(), "RUNTIME_USAGE_CURRENCY_CONFLICT") {
		t.Fatalf("diagnostics = %+v", session.Diagnostics())
	}
}

func TestAnAttemptThatSpentNothingReportsZeroInANamedCurrency(t *testing.T) {
	session := sessionFor(t, testControlPlane, PathModelInvocations)
	usage := session.Usage()
	// Zero in a named currency is a fact; an empty currency is not.
	if usage.CostAmount != "0" || usage.CostCurrency != "USD" {
		t.Fatalf("usage = %+v", usage)
	}
}

func hasDiagnostic(diagnostics []Diagnostic, code string) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			return true
		}
	}
	return false
}

func TestAnInvocationThatNeverHappenedIsNotCounted(t *testing.T) {
	session := sessionFor(t, testControlPlane, PathModelInvocations)
	// Refused before anything was sent: no request left the process, so there
	// is nothing for the control plane to settle and nothing to count.
	if _, err := session.Model(context.Background(), testTask(), Prompt{Operation: "model.plan"}); err == nil {
		t.Fatal("an incomplete invocation was sent")
	}
	if usage := session.Usage(); usage.ModelCalls != 0 || usage.InputTokens != 0 {
		t.Fatalf("an invocation that never happened was counted: %+v", usage)
	}
}

func TestASubmissionThatWasNotRecordedIsNotCountedEither(t *testing.T) {
	task := testTask()
	server := governedPlane(t, nil, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	defer server.Close()

	session := sessionFor(t, server.URL, PathRuntimeArtifacts)
	if _, err := session.SubmitCandidate(context.Background(), task, testCandidate()); err == nil {
		t.Fatal("a refused submission was reported as success")
	}
	// The record on the other side is what a call is counted against, and there
	// is none — the same rule the model path follows.
	if usage := session.Usage(); usage.ToolCalls != 0 {
		t.Fatalf("an unrecorded submission was counted: %+v", usage)
	}
}
