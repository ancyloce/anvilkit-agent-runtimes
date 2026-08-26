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
func Serve(host *Host, manifest schema.AgentRuntimeManifest, listen string) error {
	// Readiness is flipped false the moment a drain begins, so the control
	// plane stops routing new tasks here while the tasks already accepted run
	// to completion. That is what makes a rollout able to leave in-flight runs
	// pinned to the image that started them.
	draining := make(chan struct{})

	server := &http.Server{
		Addr:              listen,
		Handler:           NewHandler(host, manifest, draining),
		ReadHeaderTimeout: 10 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		<-stop
		close(draining)
		slog.Info("draining", "drainSeconds", manifest.Release.DrainSeconds)
		// The drain window comes from the manifest, so how long a unit is given
		// to finish is a released decision rather than a deployment accident.
		ctx, cancel := context.WithTimeout(
			context.Background(), time.Duration(manifest.Release.DrainSeconds)*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("agent runtime serve: %w", err)
	}
	return nil
}

// NewHandler builds the unit's entire request surface: the health and readiness
// paths its manifest declares, and one endpoint that resolves a dispatched task.
// There is no administrative surface — a runtime with one would be a place to
// change behaviour outside a release.
//
// It is separate from Serve so the operational contract the manifest declares —
// readiness flipping on drain, and concurrency bounded to what the unit was
// released to accept — can be exercised without binding a port.
func NewHandler(host *Host, manifest schema.AgentRuntimeManifest, draining <-chan struct{}) http.Handler {
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
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			// Refusing is correct: the scheduler can place the task on a unit
			// with capacity, whereas queueing it here would hide the pressure
			// the scaling policy is supposed to see.
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}

		var task schema.AgentTask
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&task); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		result, err := host.Resolve(task)
		if err != nil {
			slog.Error("task could not be resolved", "taskId", task.TaskId)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	})

	return mux
}
