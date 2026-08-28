package runtime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
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

func (b *blockingTurn) Decide(context.Context, schema.AgentTask, *Session) (schema.AgentRuntimeResultTurnDecision, error) {
	b.entered <- struct{}{}
	<-b.release
	return schema.AgentRuntimeResultTurnDecision{
		Decision:        schema.AgentRuntimeResultTurnDecisionDecisionFinal,
		Payload:         schema.SharedPrimitivesBoundedStringMap{},
		ArtifactOutputs: []schema.SharedPrimitivesArtifactReference{},
	}, nil
}

// handlerFor builds a unit's whole request surface behind its real admission
// boundary. These tests go through that boundary rather than around it: an
// operational promise proven against a handler that admitted anything would be
// a promise about a unit nobody deploys.
func handlerFor(t *testing.T, turn Turn, manifest schema.AgentRuntimeManifest, draining <-chan struct{}) *admissionHarness {
	t.Helper()
	return newAdmissionHarness(t, turn, manifest, draining)
}

// postTask dispatches one credentialed task, with a distinct attempt identity
// per call so the unit's replay register answers none of them from an earlier
// one.
func postTask(t *testing.T, harness *admissionHarness) *httptest.ResponseRecorder {
	t.Helper()
	return harness.send(t, func(task *schema.AgentTask) {
		task.PhysicalAttemptId = schema.SharedPrimitivesOpaqueId("attempt.synthetic." + nextAttempt())
	}, nil, nil)
}

// nextAttempt hands out a fresh attempt identity. Concurrency tests dispatch
// from several goroutines at once, so it has to be safe to call from all of
// them.
var attemptCounter struct {
	lock  sync.Mutex
	value int
}

func nextAttempt() string {
	attemptCounter.lock.Lock()
	defer attemptCounter.lock.Unlock()
	attemptCounter.value++
	return strconv.Itoa(attemptCounter.value)
}

func TestHealthAndReadinessLiveWhereTheManifestSaysTheyDo(t *testing.T) {
	manifest := admittingManifest(1)
	harness := handlerFor(t, &scriptedTurn{}, manifest, make(chan struct{}))
	for _, path := range []string{manifest.Telemetry.HealthPath, manifest.Telemetry.ReadinessPath} {
		recorder := httptest.NewRecorder()
		harness.handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s = %d, want 200", path, recorder.Code)
		}
	}
}

func TestReadinessDropsTheMomentADrainBegins(t *testing.T) {
	manifest := admittingManifest(1)
	draining := make(chan struct{})
	harness := handlerFor(t, &scriptedTurn{}, manifest, draining)

	ready := httptest.NewRecorder()
	harness.handler.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusOK {
		t.Fatalf("readiness before drain = %d, want 200", ready.Code)
	}

	close(draining)

	drained := httptest.NewRecorder()
	harness.handler.ServeHTTP(drained, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if drained.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness during drain = %d, want 503", drained.Code)
	}
	// Health stays up: the process is alive and finishing what it accepted.
	// Failing health here would have the platform kill in-flight runs.
	alive := httptest.NewRecorder()
	harness.handler.ServeHTTP(alive, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if alive.Code != http.StatusOK {
		t.Fatalf("health during drain = %d, want 200", alive.Code)
	}
}

func TestConcurrencyBeyondTheReleasedBoundIsRefusedNotQueued(t *testing.T) {
	const bound = 2
	turn := &blockingTurn{entered: make(chan struct{}, bound), release: make(chan struct{})}
	harness := handlerFor(t, turn, admittingManifest(bound), make(chan struct{}))

	// Fill every released slot and wait until each task is genuinely inside the
	// Agent, so the next request meets a full unit rather than a race.
	var inFlight sync.WaitGroup
	for i := 0; i < bound; i++ {
		inFlight.Add(1)
		go func() {
			defer inFlight.Done()
			postTask(t, harness)
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
	overflow := postTask(t, harness)
	if overflow.Code != http.StatusTooManyRequests {
		t.Fatalf("overflow = %d, want 429", overflow.Code)
	}

	close(turn.release)
	inFlight.Wait()

	// Capacity returns once the accepted work finishes. The release channel is
	// already closed, so this task passes straight through rather than
	// blocking — what is being observed is that a slot was freed.
	if after := postTask(t, harness); after.Code != http.StatusOK {
		t.Fatalf("after drain of in-flight work = %d, want 200", after.Code)
	}
}

// Two deliveries of one attempt arriving together execute it once. The first
// claims the attempt at admission; the second is told to come back and, once
// the first has answered, is answered from the record. The register is what
// stands between a duplicated dispatch and two governed invocations billed to
// one attempt.
func TestASecondDeliveryOfAnAttemptInFlightIsNotExecutedTwice(t *testing.T) {
	turn := &blockingTurn{entered: make(chan struct{}, 2), release: make(chan struct{})}
	harness := handlerFor(t, turn, admittingManifest(4), make(chan struct{}))
	same := func(task *schema.AgentTask) { task.PhysicalAttemptId = "attempt.in-flight.0001" }
	first := make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- harness.send(t, same, nil, nil) }()
	<-turn.entered

	duplicate := harness.send(t, same, nil, nil)
	assertRefused(t, duplicate, http.StatusTooManyRequests, reasonCapacityExhausted)

	close(turn.release)
	if answered := <-first; answered.Code != http.StatusOK {
		t.Fatalf("the first delivery = %d, want 200 (%s)", answered.Code, answered.Body.String())
	}
	replay := harness.send(t, same, nil, nil)
	if replay.Code != http.StatusOK || replay.Header().Get(replayedHeaderName) != "true" {
		t.Fatalf("the delivery after the answer = %d replayed=%q, want the recorded answer", replay.Code, replay.Header().Get(replayedHeaderName))
	}
	select {
	case <-turn.entered:
		t.Fatal("one attempt executed twice")
	default:
	}
}

// The unit counts what its surface did under closed vocabularies only: an
// admission refusal by its stable code, an answered task by governed status
// and reason, and what is in flight — never a task, attempt, or credential.
func TestTheSurfaceCountsRefusalsAndAnswersByStableCode(t *testing.T) {
	metrics := NewMetrics()
	draining := make(chan struct{})
	harness := newAdmissionHarness(t, &scriptedTurn{}, admittingManifest(1), draining)
	instrumented, err := newHandler(harness.host, harness.admission, harness.manifest, draining, metrics)
	if err != nil {
		t.Fatal(err)
	}
	harness.handler = instrumented
	if answered := harness.send(t, nil, nil, nil); answered.Code != http.StatusOK {
		t.Fatalf("dispatch = %d (%s)", answered.Code, answered.Body.String())
	}
	harness.send(t, nil, func(claims map[string]any) { claims["aud"] = "urn:anvilkit:audience:runtime-somewhere-else" }, nil)
	close(draining)
	harness.send(t, func(task *schema.AgentTask) { task.PhysicalAttemptId = "attempt.after-drain" }, nil, nil)

	snapshot := metrics.Snapshot()
	if snapshot.Answers["completed/RUNTIME_COMPLETED"] != 1 {
		t.Fatalf("answers = %v, want one completed answer", snapshot.Answers)
	}
	if snapshot.Refusals[reasonCapacityExhausted] != 1 || snapshot.Refusals[reasonNotAuthorized]+snapshot.Refusals[reasonUnauthenticated] != 1 {
		t.Fatalf("refusals = %v, want one drain refusal and one credential refusal", snapshot.Refusals)
	}
	if snapshot.InFlight != 0 {
		t.Fatalf("in flight = %d after every task answered", snapshot.InFlight)
	}
	for key := range snapshot.Refusals {
		if strings.Contains(key, "attempt.") {
			t.Fatalf("a refusal was counted under an attempt identity: %q", key)
		}
	}
}

func TestTheTaskEndpointRefusesAnythingButAPostedTask(t *testing.T) {
	harness := handlerFor(t, &scriptedTurn{}, admittingManifest(1), make(chan struct{}))

	notAllowed := httptest.NewRecorder()
	harness.handler.ServeHTTP(notAllowed, httptest.NewRequest(http.MethodGet, "/task", nil))
	if notAllowed.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /task = %d, want 405", notAllowed.Code)
	}

	// A body that is not a document is refused for its shape, before anything
	// about it is verified: the request never became a task to authorize.
	malformed := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/task", bytes.NewReader([]byte("{")))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer irrelevant.because.unread")
	request.Header.Set(idempotencyHeaderName, "attempt.synthetic.malformed")
	request.Header.Set(requestDigestHeaderName, digestOf([]byte("{")))
	request.Header.Set(traceparentHeaderName, "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01")
	harness.handler.ServeHTTP(malformed, request)
	if malformed.Code != http.StatusUnprocessableEntity {
		t.Fatalf("malformed task = %d, want 422 (%s)", malformed.Code, malformed.Body.String())
	}
}

func TestThereIsNoAdministrativeSurface(t *testing.T) {
	manifest := admittingManifest(1)
	harness := handlerFor(t, &scriptedTurn{}, manifest, make(chan struct{}))
	// A runtime with an admin path would be a place to change behaviour outside
	// a release. Only the three declared paths answer.
	for _, path := range []string{"/", "/admin", "/debug/pprof/", "/config", "/metrics"} {
		recorder := httptest.NewRecorder()
		harness.handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s answered %d; a runtime unit exposes only health, readiness, and /task", path, recorder.Code)
		}
	}
}

// drainingServer is one unit server bound to a free port, whose /task handler
// holds every request until released, so a drain has admitted work to wait
// for.
type drainingServer struct {
	server  *http.Server
	address string
	entered chan struct{}
	release chan struct{}
	stop    chan os.Signal
	exited  chan error
}

func newDrainingServer(t *testing.T, window time.Duration) *drainingServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	unit := &drainingServer{
		address: address,
		entered: make(chan struct{}, 8),
		release: make(chan struct{}),
		stop:    make(chan os.Signal, 1),
		exited:  make(chan error, 1),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/task", func(w http.ResponseWriter, _ *http.Request) {
		unit.entered <- struct{}{}
		<-unit.release
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"answered":true}`))
	})
	unit.server = &http.Server{Addr: address, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		unit.exited <- serveUntilDrained(unit.server, make(chan struct{}), unit.stop, window, NewMetrics())
	}()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		response, probeErr := http.Get("http://" + address + "/healthz")
		if probeErr == nil {
			_ = response.Body.Close()
			return unit
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the unit server never started listening")
	return nil
}

func (u *drainingServer) dispatch() <-chan error {
	answered := make(chan error, 1)
	go func() {
		response, err := http.Post("http://"+u.address+"/task", "application/json", bytes.NewReader([]byte("{}")))
		if err != nil {
			answered <- err
			return
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			answered <- fmt.Errorf("status %d", response.StatusCode)
			return
		}
		answered <- nil
	}()
	return answered
}

// A drain lets the tasks the unit already admitted run to their answer and
// only then releases the process; nothing new is admitted meanwhile. A unit
// that exited the moment its listener closed would turn every in-flight task
// of a rollout into a lost response.
func TestADrainingUnitAnswersAdmittedWorkBeforeItExits(t *testing.T) {
	unit := newDrainingServer(t, 10*time.Second)
	answered := unit.dispatch()
	<-unit.entered

	unit.stop <- syscall.SIGTERM
	// Admission stops: a new connection is refused once the listener closes.
	refusedBy := time.Now().Add(5 * time.Second)
	for {
		_, err := http.Post("http://"+unit.address+"/task", "application/json", bytes.NewReader([]byte("{}")))
		if err != nil {
			break
		}
		if time.Now().After(refusedBy) {
			t.Fatal("a draining unit kept admitting new tasks")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The admitted task is still executing, and the unit has not exited.
	select {
	case err := <-unit.exited:
		t.Fatalf("the unit exited with admitted work still executing: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	close(unit.release)
	if err := <-answered; err != nil {
		t.Fatalf("the admitted task was not answered across the drain: %v", err)
	}
	select {
	case err := <-unit.exited:
		if err != nil {
			t.Fatalf("the drain reported %v after its admitted work answered", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the unit did not exit once its admitted work had answered")
	}
}

// The released window bounds the drain: admitted work that never answers is
// abandoned when the window closes, and the unit reports it rather than
// pretending the drain was clean.
func TestTheReleasedDrainWindowBoundsAdmittedWork(t *testing.T) {
	unit := newDrainingServer(t, 300*time.Millisecond)
	answered := unit.dispatch()
	<-unit.entered
	unit.stop <- syscall.SIGTERM
	select {
	case err := <-unit.exited:
		if err == nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("a drain past its window reported %v, want the deadline", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the unit did not stop when its drain window closed")
	}
	close(unit.release)
	<-answered
}
