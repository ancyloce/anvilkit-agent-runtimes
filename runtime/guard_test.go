package runtime

import (
	"errors"
	"testing"
)

// The boundary is the whole point of the shared host: an Agent Runtime Unit is
// an execution plane and nothing else. Each rule below is one of design 0001
// §5.2's prohibitions, asserted as something the code refuses rather than
// something the documentation asks for.

func boundary(t *testing.T) *Boundary {
	t.Helper()
	value, err := NewBoundary("https://gateway.internal/v1/models", []string{"/v1/context", "/v1/artifacts"})
	if err != nil {
		t.Fatalf("build boundary: %v", err)
	}
	return value
}

func refusalOf(t *testing.T, err error) Refusal {
	t.Helper()
	var boundaryError *BoundaryError
	if !errors.As(err, &boundaryError) {
		t.Fatalf("expected a boundary refusal, got %v", err)
	}
	return boundaryError.Refusal
}

func TestEveryProhibitedActionIsRefused(t *testing.T) {
	guard := boundary(t)
	for name, testCase := range map[string]struct {
		attempt func() error
		want    Refusal
	}{
		"calling a peer agent":      {func() error { return guard.Peer("page-candidate-specialist") }, RefusePeerCall},
		"executing a tool":          {func() error { return guard.ExecuteTool("anvilkit.tool.context-echo") }, RefuseToolExecution},
		"reaching the domain owner": {func() error { return guard.Domain("https://pagix.internal/pages") }, RefuseDomainAccess},
		"writing platform state":    {func() error { return guard.WriteState("agent_run") }, RefuseStateWrite},
		"selecting a credential":    {func() error { return guard.SelectCredential("provider-key") }, RefuseCredentialSelection},
	} {
		t.Run(name, func(t *testing.T) {
			err := testCase.attempt()
			if err == nil {
				t.Fatal("a prohibited action was permitted")
			}
			if got := refusalOf(t, err); got != testCase.want {
				t.Fatalf("refusal = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestOnlyTheGovernedGatewayIsReachable(t *testing.T) {
	guard := boundary(t)
	if err := guard.AllowModelGateway("https://gateway.internal/v1/models"); err != nil {
		t.Fatalf("the governed gateway was refused: %v", err)
	}
	// Exact match, deliberately. A prefix or suffix rule lets a lookalike host
	// through, and a runtime that reaches a lookalike has selected an endpoint.
	for _, lookalike := range []string{
		"https://gateway.internal/v1/models/../../elsewhere",
		"https://gateway.internal/v1/models2",
		"https://gateway.internal.evil.example/v1/models",
		"https://gateway.internal/v1/model",
		"",
	} {
		if err := guard.AllowModelGateway(lookalike); err == nil {
			t.Fatalf("a destination that is not the gateway was allowed: %q", lookalike)
		} else if got := refusalOf(t, err); got != RefuseUnknownDestination {
			t.Fatalf("refusal for %q = %q", lookalike, got)
		}
	}
}

func TestOnlyReleasedControlPlanePathsAreReachable(t *testing.T) {
	guard := boundary(t)
	for _, released := range []string{"/v1/context", "/v1/artifacts"} {
		if err := guard.AllowControlPlane(released); err != nil {
			t.Fatalf("a released path was refused: %q", released)
		}
	}
	for _, outside := range []string{"/v1/runs", "/v1/context/", "/v1/artifacts/../runs", "", "/v1/"} {
		if err := guard.AllowControlPlane(outside); err == nil {
			t.Fatalf("a path outside the released set was allowed: %q", outside)
		}
	}
}

func TestABoundaryCannotBeBuiltWithoutAGovernedGateway(t *testing.T) {
	if _, err := NewBoundary("", nil); err == nil {
		t.Fatal("a boundary with no model gateway was built")
	}
	if _, err := NewBoundary("   ", nil); err == nil {
		t.Fatal("a boundary with a blank model gateway was built")
	}
	// A control-plane entry that is not a control-plane path is a
	// misconfiguration, and a unit that started with one would be reachable
	// somewhere nobody released it to.
	if _, err := NewBoundary("https://gateway.internal/v1/models", []string{"https://elsewhere.example/"}); err == nil {
		t.Fatal("a non-control-plane destination was accepted into the released set")
	}
}

func TestARefusalNamesTheRuleAndNotTheDestination(t *testing.T) {
	guard := boundary(t)
	err := guard.Domain("https://pagix.internal/secret-topology")
	message := err.Error()
	// The topology a runtime is refused is topology it is not supposed to know.
	if want := "https://pagix.internal/secret-topology"; contains(message, want) {
		t.Fatalf("the refusal echoed the destination: %q", message)
	}
	if !contains(message, string(RefuseDomainAccess)) {
		t.Fatalf("the refusal did not name the rule: %q", message)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		}()
}
