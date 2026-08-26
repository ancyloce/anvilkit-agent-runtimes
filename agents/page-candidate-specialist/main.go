// Command page-candidate-specialist is the Page Candidate Specialist Agent Runtime Unit.
//
// It produces a bounded page candidate for a parent run. It is invoked through
// Agent Service as a tool and never becomes a root-run authority; a Specialist
// capability that must also be invoked directly is paired with a standalone-entry
// Manager definition rather than promoting this one.
package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-runtimes/runtime"
)

func main() {
	if err := run(); err != nil {
		slog.Error("page-candidate-specialist did not start", "error", err)
		os.Exit(1)
	}
}

func run() error {
	// The manifest is release material, not source. The release pipeline
	// produces it with the image, provenance, and protocol digests of the
	// artifact actually being deployed, and mounts it here. A unit that
	// invented its own manifest would be attesting to a release nobody made.
	manifestPath := os.Getenv("ANVILKIT_RUNTIME_MANIFEST")
	if manifestPath == "" {
		return fmt.Errorf("ANVILKIT_RUNTIME_MANIFEST is required: a runtime unit will not start without its released binding")
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read runtime manifest: %w", err)
	}
	var manifest schema.AgentRuntimeManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return fmt.Errorf("parse runtime manifest: %w", err)
	}

	gateway := os.Getenv("ANVILKIT_MODEL_GATEWAY")
	if gateway == "" {
		return fmt.Errorf("ANVILKIT_MODEL_GATEWAY is required: there is no other model path")
	}

	unit, err := runtime.NewUnit(manifest, gateway)
	if err != nil {
		return err
	}

	signer, err := runtime.SignerFromEnvironment()
	if err != nil {
		return err
	}
	host, err := runtime.NewHost(unit, &specialistTurn{}, signer, time.Now)
	if err != nil {
		return err
	}

	slog.Info("page-candidate-specialist ready",
		"runtimeUnit", manifest.RuntimeUnitId,
		"manifestDigest", unit.ManifestDigest(),
		"telemetryNamespace", manifest.Telemetry.Namespace)

	listen := os.Getenv("ANVILKIT_LISTEN")
	if listen == "" {
		listen = ":8080"
	}
	return runtime.Serve(host, manifest, listen)
}
