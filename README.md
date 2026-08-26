# anvilkit-agent-runtimes

Every enabled AnvilKit Manager and Specialist, built and released as an
independent **Agent Runtime Unit**.

One repository, one shared runtime host, and a separate build and release target
per Agent. One repository per Agent is deliberately *not* the model (design 0001
§4.1): units share source and the runtime SDK, and share nothing in production.

## What a runtime unit is

A unit resolves one bounded turn for one pinned Agent definition and returns a
signed `AgentRuntimeResult`. It has its own image digest, workload identity, task
channel, concurrency and resource policy, telemetry namespace, release pipeline,
and rollback target — so any one Agent can be scaled, released, drained, or
rolled back without touching another, without touching Agent Service, and
without disturbing runs already in flight.

## What a runtime unit is not

This is an execution plane. Agent Service remains the sole authority for the
AgentRun and its durable workflow, the registry and runtime selection, budgets
and usage, delegation and Child AgentRun creation, Tool Guard and Tool
execution, validators, artifacts and evidence, and every review and approval.

`runtime/guard.go` enforces that rather than documenting it. A unit cannot call
another unit, execute a Tool, create a Child AgentRun, write Platform state,
select an endpoint or credential, bypass a validator, or reach Pagix. Those are
functions that refuse, so code wanting them meets a compile-time destination and
a runtime refusal instead of an undocumented capability.

A unit may reach exactly two kinds of destination: the governed Model Gateway,
and the read-only control-plane paths its own manifest was released with.

## Contracts

`contracts/generated` holds the canonical Agent bindings, generated in
`anvilkit-platform` and vendored here — these repositories integrate through
contracts and generated clients, never source imports. `contracts/pin.json`
records the digests of the generated bindings, the P0-Kernel profile, and the
canonical lock they came from. Re-vendor and re-pin after any canonical contract
change; never edit the generated file here.

## Layout

```
contracts/           vendored canonical bindings + pin
runtime/             the shared host every unit is built on
agents/<agent>/      one directory per Agent Runtime Unit: entrypoint,
                     image build, deployment descriptor, release target
```

## Status

Repository ownership was approved on 2026-08-24 (ADR-025 §14, approval 2), and
this repository is now a Platform submodule at `services/agent-runtimes`,
tracking `github.com/ancyloce/anvilkit-agent-runtimes`.

The units are implementation-complete and covered, but **nothing has been
released**: no `AgentRuntimeManifest` exists yet, and a unit refuses to start
without one (`ANVILKIT_RUNTIME_MANIFEST`). Manifests are release material,
produced by the release pipeline with the image, provenance, and protocol
digests of the artifact actually being deployed — they are deliberately not
committed here.
