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

A unit may reach exactly one origin, and on it only the control-plane paths its
own manifest was released with.

## Admission

`/task` is the whole execution surface, and `runtime/admission.go` is what it
will not accept. Nothing reaches an Agent until the request has passed, in this
order — cheapest first, so a malformed request cannot make the unit do the
expensive part:

1. POST, an explicit `application/json` content type, and bounded headers.
2. The three parameters the canonical boundary description requires:
   `Idempotency-Key` (the physical attempt), `X-AnvilKit-Request-Digest`, and
   `traceparent`.
3. A bounded body whose digest matches the one the caller declared.
4. Strict decoding against the generated canonical bindings — unknown members,
   duplicate members, missing required fields, out-of-pattern values, and
   trailing content are all refused.
5. A recorded answer for this exact attempt and these exact bytes is replayed
   rather than executed again; the same key over different bytes is
   `IDEMPOTENCY_KEY_REUSED`.
6. A task-scoped credential that verifies against the operator-distributed trust
   root, and that binds this run, task, attempt, generation, lease epoch, and
   release.
7. A task addressed to *this* release — unit, manifest, image, protocol,
   audience, and definition.
8. An admission window that is still open, and an attempt identity that could be
   fenced.

Refusals are answered in the governed problem shape, with the control plane's own
problem codes rather than a second vocabulary invented here — `REQUEST_INVALID`,
`AUTHENTICATION_INVALID`, `AUTHORIZATION_DENIED`, `CONTRACT_INVALID`,
`IDEMPOTENCY_KEY_REUSED`, `TASK_DISPATCH_DENIED`, `ADMISSION_OVERLOADED`,
`INTERNAL_ERROR` — and only with statuses the canonical boundary description
declares. None of them names the check that failed: a caller able to tell an
expired credential from one issued for another attempt could search for the
difference.

The credential is a bearer JWT (`EdDSA`, `typ: anvilkit-task-credential+jwt`)
minted by Agent Service. It is asymmetric on purpose — a shared secret would let
any unit holding it mint credentials for every other unit. Agent Service and this
repository implement the format independently and share no code;
`runtime/testdata/task-credential.vector.json` is the known-answer vector that
holds the two to one format, and both suites verify against the same copy.

### Deployment inputs

| Variable | What it is |
|---|---|
| `ANVILKIT_RUNTIME_MANIFEST` | The released binding this unit serves. Release material, never source. |
| `ANVILKIT_CONTROL_PLANE` | The origin of the Agent Service runtime boundary. An origin only — which routes on it this unit may use is the manifest's answer, not the deployment's. |
| `ANVILKIT_RESULT_SIGNING_KEY` / `..._KEY_ID` | The Ed25519 key this unit signs results with, and the identity a verifier resolves it by. |
| `ANVILKIT_TASK_CREDENTIAL_TRUST_ROOT` | The operator-distributed trust root task credentials are admitted against. Mounted, never fetched from the control plane. |
| `ANVILKIT_LISTEN` | Listen address (default `:8080`). |

A unit refuses to start without any of the first four. An unsigned result cannot
be attributed to a release, and a unit that could not verify a credential could
not tell a dispatched task from one anybody sent it.

## Reaching out

A unit reaches exactly one origin and, on it, exactly the paths its own
`AgentRuntimeManifest` was released with. There is no second address and no
route a running Agent can name, which is what makes "an Agent may not select an
endpoint" a property of the code rather than a rule in a document.

| Released path | What it is |
|---|---|
| `/v1/internal/runtime/model-invocations` | The governed Model Gateway. |
| `/v1/internal/runtime/artifacts` | The controlled artifact interface. |
| `/v1/internal/runtime/artifact-content-grants` | Bounded, expiring read access to one artifact's bytes. |
| `/v1/internal/runtime/contract-runtime-invocations` | The deterministic Contract Runtime, offered as a controlled tool. |

A capability is built only when the manifest names the path it needs, so a
Manager — released without the artifact path — has no artifact writer at all,
and the difference between "this release does not write artifacts" and "this
write failed" stays visible in the result.

### The governed model path

The invocation carries the attempt's identity, the definition and model policy
Agent Service pinned, and the **digests** of the compiled context and prompt —
never the context or prompt themselves. A runtime that could send prompt text
could send text nobody compiled, and the gateway would have no way to tell.
Usage comes back metered per invocation and is recorded against the attempt
whether the invocation succeeded or was refused, because a refused invocation
still spent what the gateway metered for it.

Two failures are kept apart, because the scheduler acts differently on them: a
governed **refusal** is the model path working and declining, and retrying it
would buy the same answer twice; an **unavailability** is the path not
answering, and the attempt may reasonably be replaced.

### The controlled artifact interface

One submission per attempt, deduplicated by the attempt and the operation. The
runtime hands over the canonical bytes of what it produced and receives an
immutable reference back — it never reaches storage, never holds a storage
credential, never chooses a bucket or key, and never mints an artifact identity.
The returned reference is believed only when its digest and size are about the
bytes that were sent; anything else would be a pointer to a document this unit
never produced.

## The supplied context

Everything an attempt may see arrives in the task's own `parameters`, and a unit
compiles only that. It reads no database, calls no context service, and carries
nothing from a previous turn — which is what makes an attempt reproducible from
its dispatched document alone.

Values are bounded because the canonical `AgentTask` bounds them. A document
longer than one bound arrives as indexed continuations — `page.componentSchema`,
or `page.componentSchema.0`, `.1`, … concatenated in index order — and a gap in
the sequence stops the read rather than splicing across it.

| Key | Read by | What it is |
|---|---|---|
| `model.contextDigest`, `model.promptDigest` | both | The compiled context and prompt this attempt is pinned to. |
| `model.policyId`, `model.policyVersion`, `model.policyDigest` | both | The model policy the definition pins. |
| `delegation.state` | Manager | `pending`, `completed`, `failed`, or `refused`. Its presence is what makes a turn a concluding one. |
| `delegation.delegate` | Manager | The definition the outcome is attributed to. |
| `delegation.reasonCode` | Manager | The governed reason a failed or refused delegation carries. |
| `delegation.candidate.*` | Manager | The produced candidate's reference: `artifactId`, `digest`, `mediaType`, `sizeBytes`. It must also be one of the task's pinned `artifactInputs`. |
| `candidate.target.*` | Specialist | `type`, `id`, `workspaceId`, `projectId`. |
| `candidate.baseRevision` | Specialist | The revision the change is against. |
| `candidate.digests.target`, `.catalog`, `.policy` | Specialist | Three of the candidate's five binding digests; the definition and contract-BOM digests come from the task itself. |
| `candidate.preview.taskId`, `candidate.preview.resultArtifact.*` | Specialist | The preview task and the accepted preview result, which must be one of the task's pinned `artifactInputs`. |
| `page.componentSchema` | Specialist | The components a page may use and the properties each declares. |
| `page.defaultProperties`, `page.defaultData` | Specialist | Supplied defaults, applied before the model's proposal. |
| `page.styleConstraints`, `page.animationConstraints` | Specialist | The rules the page as a whole and any motion on it must satisfy. |

## What the two units do

**Page Change Manager.** Two shapes of turn and no others. Before a Specialist
has run it compiles the supplied context, asks the governed gateway for a
bounded plan, and returns the one governed decision that plan resolves to. After
one has run, the task carries the outcome, and the Manager validates it and
terminates the turn *without asking the model anything* — there is nothing left
to decide, and a model call on a settled outcome would spend budget re-deriving
a fact the control plane already holds.

That split is also what bounds P0 delegation to one. The concluding turn never
reaches a plan, so no model proposal can produce a second delegation; and the
first turn refuses a plan that queues two, that buries one behind other steps,
or that names any delegate other than `definition.platform.page-candidate-specialist`.

Plan decoding is strict. The interesting way for a model to reach past its
authority is an extra member — a budget, a credential, an endpoint, a capability
— so an unknown member is a refusal rather than a field to skip: a skipped field
is an intent nobody answered.

**Page Candidate Specialist.** Produces one schema-valid `PageCandidate`. The
model proposes which components the page uses and what goes in them; the
Specialist decides whether that proposal is expressible under the supplied
schema, defaults, style rules, and animation constraints. Everything the model
can influence passes a check written against a supplied constraint; everything
else — ordering, block identity, structure — is derived, so the same task and
the same governed output always produce the same bytes and the same digest.

A violating proposal is refused, never repaired. Truncating an overlong string
or substituting an allowed theme would make the runtime the author of the part
it changed, and the candidate would then attribute to the model content the
model did not propose. Reduced motion is the one constraint that changes the
outcome rather than refusing it, and it says so in a candidate warning.

The candidate pins what produced it: the target and base revision, five binding
digests, the accepted preview, and the governed invocations the turn actually
made. It is submitted through the controlled artifact interface *before* it is
named, so the reference a final decision carries is one the control plane
recorded rather than one this process asserted.

**Known P0 boundary.** The canonical runtime boundary offers exactly one
artifact submission per attempt — the candidate. The page document the
candidate's `pageData` pins is therefore carried as a content-addressed
reference over the exact canonical bytes the composition produced, not as a
second recorded artifact. The digest is exact and recomputable from the
composition the candidate describes; giving that pin a stored object behind it
is a control-plane change, and not something a runtime can assert its way out
of.

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

The units are implementation-complete and covered — the Manager reasons through
the governed gateway and returns bounded plans, and the Specialist composes real
page candidates and writes them through the controlled artifact interface — but
**nothing has been released**: no `AgentRuntimeManifest` exists yet, and a unit
refuses to start without one (`ANVILKIT_RUNTIME_MANIFEST`). Manifests are release
material, produced by the release pipeline with the image, provenance, and
protocol digests of the artifact actually being deployed — they are deliberately
not committed here.

The Agent Service side of the runtime boundary (`/v1/internal/runtime/*`) is
described by `contracts/agent/openapi/agent-runtime.openapi.json` and is not yet
served. Until it is, these units are exercised against contract-conformant test
doubles of that surface rather than against a running control plane.
