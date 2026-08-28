package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
)

// Serve runs one Agent Runtime Unit until it is asked to drain.
//
// The unit exposes exactly three things: the health and readiness paths its
// manifest declares, and one endpoint that resolves a dispatched task. There is
// no administrative surface — a runtime with one would be a place to change
// behaviour outside a release.
func Serve(host *Host, admission *Admission, manifest schema.AgentRuntimeManifest, listen string) error {
	// Readiness is flipped false the moment a drain begins, so the control
	// plane stops routing new tasks here while the tasks already accepted run
	// to completion. That is what makes a rollout able to leave in-flight runs
	// pinned to the image that started them.
	draining := make(chan struct{})

	metrics := NewMetrics()
	handler, err := newHandler(host, admission, manifest, draining, metrics)
	if err != nil {
		return err
	}
	// The read deadlines are the transport's half of admission: a client that
	// opens a connection and sends its request slowly must not be able to hold
	// a concurrency slot the manifest sized. The write deadline is the
	// execution bound — generous enough for the timeout the release declares,
	// and finite either way.
	execution := time.Duration(manifest.Execution.TimeoutMilliseconds) * time.Millisecond
	if execution <= 0 {
		execution = time.Minute
	}
	server := &http.Server{
		Addr:              listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      execution + 30*time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    maximumHeaderBytes,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(stop)

	// The drain window comes from the manifest, so how long a unit is given
	// to finish is a released decision rather than a deployment accident.
	return serveUntilDrained(server, draining, stop, time.Duration(manifest.Release.DrainSeconds)*time.Second, metrics)
}

// serveUntilDrained serves until the stop signal and then drains: admission
// stops, the tasks already admitted run to their answer, and the unit is
// released only when the last of them has been answered or the released
// window has closed on it.
//
// ListenAndServe returns the moment the listener closes, which is the start
// of a drain, not its end. A unit that returned there would exit with its
// admitted tasks still executing, and the control plane would see each of
// them as a lost response to replace — the rollout would cost every run in
// flight one attempt. So the return waits for the shutdown itself.
//
// What the drain cost — how long it took, whether the window closed, and how
// many admitted tasks were still unanswered when it did — is reported through
// the unit's metrics: each unanswered task is a run the control plane replaces.
func serveUntilDrained(server *http.Server, draining chan<- struct{}, stop <-chan os.Signal, window time.Duration, metrics *Metrics) error {
	drained := make(chan error, 1)
	go func() {
		<-stop
		close(draining)
		slog.Info("draining", "drainSeconds", int(window/time.Second))
		started := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), window)
		defer cancel()
		err := server.Shutdown(ctx)
		metrics.Drained(time.Since(started), err != nil)
		drained <- err
	}()

	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("agent runtime serve: %w", err)
	}
	if err := <-drained; err != nil {
		return fmt.Errorf("agent runtime drain: the released window closed on admitted work: %w", err)
	}
	return nil
}

// NewHandler builds the unit's entire request surface: the health and readiness
// paths its manifest declares, and one endpoint that resolves a dispatched task.
// There is no administrative surface — a runtime with one would be a place to
// change behaviour outside a release.
//
// It is separate from Serve so the operational contract the manifest declares —
// readiness flipping on drain, concurrency bounded to what the unit was released
// to accept, and every admission refusal — can be exercised without binding a
// port.
func NewHandler(host *Host, admission *Admission, manifest schema.AgentRuntimeManifest, draining <-chan struct{}) (http.Handler, error) {
	return newHandler(host, admission, manifest, draining, NewMetrics())
}

// newHandler is NewHandler with the unit's own counters, so a drain can report
// what it found in flight and a test can read what the surface counted.
func newHandler(host *Host, admission *Admission, manifest schema.AgentRuntimeManifest, draining <-chan struct{}, metrics *Metrics) (http.Handler, error) {
	if host == nil || admission == nil {
		return nil, fmt.Errorf("agent runtime serve: a host and an admission boundary are both required")
	}
	mux := http.NewServeMux()

	mux.HandleFunc(manifest.Telemetry.HealthPath, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc(manifest.Telemetry.ReadinessPath, func(w http.ResponseWriter, _ *http.Request) {
		select {
		case <-draining:
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			w.WriteHeader(http.StatusOK)
		}
	})

	// Concurrency is bounded by the manifest, not by the machine. A unit that
	// accepted more than it was released to accept would invalidate the
	// resource and scaling profile the control plane sized it against.
	slots := make(chan struct{}, manifest.Execution.MaxConcurrency)

	mux.HandleFunc("/task", func(w http.ResponseWriter, r *http.Request) {
		// A draining unit admits nothing new. Refusing here rather than at
		// readiness alone closes the window between the control plane's last
		// readiness read and the dispatch it had already decided to send.
		select {
		case <-draining:
			metrics.Refused(capacityExhausted.Code)
			writeRefusal(w, capacityExhausted)
			return
		default:
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			// Refusing is correct: the scheduler can place the task on a unit
			// with capacity, whereas queueing it here would hide the pressure
			// the scaling policy is supposed to see.
			metrics.Refused(capacityExhausted.Code)
			writeRefusal(w, capacityExhausted)
			return
		}

		accepted, err := admission.Admit(w, r)
		if err != nil {
			if errors.Is(err, errReplayed) {
				return
			}
			var denied refusal
			if !errors.As(err, &denied) {
				denied = internalRefusal
			}
			// The refusal is counted and logged by code and by attempt, never
			// by the values that failed: a log line carrying a credential, a
			// fence, or a signature would move the secret to somewhere with a
			// longer retention than the request.
			metrics.Refused(denied.Code)
			slog.Warn("task refused at admission", "code", denied.Code, "status", denied.Status)
			writeRefusal(w, denied)
			return
		}
		metrics.Admitted()

		// The execution bound is the release's own. A turn that outran it must
		// end here rather than hold a concurrency slot for as long as whatever
		// it is waiting on is willing to wait.
		ctx := r.Context()
		if timeout := time.Duration(manifest.Execution.TimeoutMilliseconds) * time.Millisecond; timeout > 0 {
			bounded, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			ctx = bounded
		}
		result, err := host.Resolve(ctx, accepted.task, accepted.credential)
		if err != nil {
			// Nothing was answered, so nothing is recorded, and the claim on
			// the attempt is given back: the redelivery that follows must
			// execute it rather than be told it is still in flight.
			admission.Release(accepted.attemptID)
			metrics.Answered("unanswered", internalRefusal.Code)
			slog.Error("task could not be resolved", "taskId", accepted.task.TaskId)
			writeRefusal(w, internalRefusal)
			return
		}
		// The bytes are built once and both written and recorded, so a retry is
		// answered with the same document byte for byte. Encoding twice would
		// make the replay differ from the original in whatever the two encoders
		// disagree about, and a caller comparing them would be right to object.
		encoded, err := json.Marshal(result)
		if err != nil {
			admission.Release(accepted.attemptID)
			metrics.Answered("unanswered", internalRefusal.Code)
			writeRefusal(w, internalRefusal)
			return
		}
		metrics.Answered(string(result.Status.Status), result.Status.ReasonCode)
		// The answer is recorded before it is written. A result written and not
		// recorded would be executed again by the retry that follows a lost
		// response, which is the one thing the register exists to prevent.
		admission.Record(accepted.attemptID, accepted.requestDigest, encoded)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(requestDigestHeaderName, accepted.requestDigest)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(encoded)
	})

	return mux, nil
}
