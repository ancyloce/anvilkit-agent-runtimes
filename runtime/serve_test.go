package runtime

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
)

// These are the operational promises a manifest makes on a unit's behalf:
// where health and readiness live, that readiness drops the moment a drain
// begins, and that the unit accepts exactly the concurrency it was released
// for. A rollout, a scaling policy, and an in-flight run all depend on them.

func servingManifest(maxConcurrency int) schema.AgentRuntimeManifest {
	return schema.AgentRuntimeManifest{
		Kind:          "AgentRuntimeManifest",
		RuntimeUnitId: "runtime.platform.page-change-manager",
		Definition: schema.SharedPrimitivesDefinitionReference{
			DefinitionId:     "definition.platform.page-change-manager",
			DefinitionDigest: testDefinitionDigest,
		},
		Image:     schema.AgentRuntimeManifestImage{ImageDigest: testImageDigest},
		Protocol:  schema.AgentRuntimeManifestProtocol{InvocationProtocolDigest: testProtocolDigest},
		Execution: schema.AgentRuntimeManifestExecution{MaxConcurrency: maxConcurrency},
		Telemetry: schema.AgentRuntimeManifestTelemetry{
			HealthPath:    "/healthz",
			ReadinessPath: "/readyz",
		},
	}
}

// blockingTurn holds every task inside Decide until released, so concurrency is
// observable rather than inferred from timing.
type blockingTurn struct {
	entered chan struct{}
	release chan struct{}
}

func (b *blockingTurn) Decide(schema.AgentTask, *Boundary) (schema.AgentRuntimeResultTurnDecision, Usage, []Diagnostic, error) {
	b.entered <- struct{}{}
	<-b.release
	return schema.AgentRuntimeResultTurnDecision{
		Decision:        schema.AgentRuntimeResultTurnDecisionDecisionFinal,
		Payload:         schema.SharedPrimitivesBoundedStringMap{},
		ArtifactOutputs: []schema.SharedPrimitivesArtifactReference{},
	}, Usage{}, nil, nil
}

func handlerFor(t *testing.T, turn Turn, manifest schema.AgentRuntimeManifest, draining <-chan struct{}) http.Handler {
	t.Helper()
	unit, err := NewUnit(manifest, "https://gateway.internal/v1/models")
	if err != nil {
		t.Fatalf("build unit: %v", err)
	}
	host, err := NewHost(unit, turn, &recordingSigner{}, func() time.Time { return time.Unix(1700000000, 0) })
	if err != nil {
		t.Fatalf("build host: %v", err)
	}
	return NewHandler(host, manifest, draining)
}

// dispatchedTask is the canonical AgentTask fixture, used verbatim. Hand-built
// tasks pass through Resolve but not through the wire: the generated type
// enforces the contract's required set on decode, which is exactly the boundary
// these tests exercise.
func dispatchedTask(t *testing.T) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "agent-task.minimum.json"))
	if err != nil {
		t.Fatalf("read canonical task fixture: %v", err)
	}
	return body
}

func postTask(t *testing.T, handler http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/task", bytes.NewReader(dispatchedTask(t))))
	return recorder
}

func TestHealthAndReadinessLiveWhereTheManifestSaysTheyDo(t *testing.T) {
	manifest := servingManifest(1)
	handler := handlerFor(t, &scriptedTurn{}, manifest, make(chan struct{}))
	for _, path := range []string{manifest.Telemetry.HealthPath, manifest.Telemetry.ReadinessPath} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s = %d, want 200", path, recorder.Code)
		}
	}
}

func TestReadinessDropsTheMomentADrainBegins(t *testing.T) {
	manifest := servingManifest(1)
	draining := make(chan struct{})
	handler := handlerFor(t, &scriptedTurn{}, manifest, draining)

	ready := httptest.NewRecorder()
	handler.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusOK {
		t.Fatalf("readiness before drain = %d, want 200", ready.Code)
	}

	close(draining)

	drained := httptest.NewRecorder()
	handler.ServeHTTP(drained, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if drained.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness during drain = %d, want 503", drained.Code)
	}
	// Health stays up: the process is alive and finishing what it accepted.
	// Failing health here would have the platform kill in-flight runs.
	alive := httptest.NewRecorder()
	handler.ServeHTTP(alive, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if alive.Code != http.StatusOK {
		t.Fatalf("health during drain = %d, want 200", alive.Code)
	}
}

func TestConcurrencyBeyondTheReleasedBoundIsRefusedNotQueued(t *testing.T) {
	const bound = 2
	turn := &blockingTurn{entered: make(chan struct{}, bound), release: make(chan struct{})}
	handler := handlerFor(t, turn, servingManifest(bound), make(chan struct{}))

	// Fill every released slot and wait until each task is genuinely inside the
	// Agent, so the next request meets a full unit rather than a race.
	var inFlight sync.WaitGroup
	for i := 0; i < bound; i++ {
		inFlight.Add(1)
		go func() {
			defer inFlight.Done()
			postTask(t, handler)
		}()
	}
	for i := 0; i < bound; i++ {
		select {
		case <-turn.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("a released slot never accepted a task")
		}
	}

	// Refused, not queued: queueing would hide the pressure the scaling policy
	// is supposed to see, and would let a unit hold more work than it was sized
	// for.
	overflow := postTask(t, handler)
	if overflow.Code != http.StatusTooManyRequests {
		t.Fatalf("overflow = %d, want 429", overflow.Code)
	}

	close(turn.release)
	inFlight.Wait()

	// Capacity returns once the accepted work finishes. The release channel is
	// already closed, so this task passes straight through rather than
	// blocking — what is being observed is that a slot was freed.
	if after := postTask(t, handler); after.Code != http.StatusOK {
		t.Fatalf("after drain of in-flight work = %d, want 200", after.Code)
	}
}

func TestTheTaskEndpointRefusesAnythingButAPostedTask(t *testing.T) {
	handler := handlerFor(t, &scriptedTurn{}, servingManifest(1), make(chan struct{}))

	notAllowed := httptest.NewRecorder()
	handler.ServeHTTP(notAllowed, httptest.NewRequest(http.MethodGet, "/task", nil))
	if notAllowed.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /task = %d, want 405", notAllowed.Code)
	}

	malformed := httptest.NewRecorder()
	handler.ServeHTTP(malformed, httptest.NewRequest(http.MethodPost, "/task", bytes.NewReader([]byte("{"))))
	if malformed.Code != http.StatusBadRequest {
		t.Fatalf("malformed task = %d, want 400", malformed.Code)
	}
}

func TestThereIsNoAdministrativeSurface(t *testing.T) {
	manifest := servingManifest(1)
	handler := handlerFor(t, &scriptedTurn{}, manifest, make(chan struct{}))
	// A runtime with an admin path would be a place to change behaviour outside
	// a release. Only the three declared paths answer.
	for _, path := range []string{"/", "/admin", "/debug/pprof/", "/config", "/metrics"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s answered %d; a runtime unit exposes only health, readiness, and /task", path, recorder.Code)
		}
	}
}
