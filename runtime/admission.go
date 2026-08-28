package runtime

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
)

// The admission boundary of an Agent Runtime Unit.
//
// Everything here refuses. A unit's execution surface is one endpoint, and the
// only interesting question about that endpoint is what it will not accept: a
// body it cannot bound, a document it cannot validate, a credential it cannot
// verify, work addressed to another release, work whose admission window has
// closed, or work it has already answered. What reaches an Agent is what
// survives all of it.
//
// Every refusal is a stable code and a status the canonical runtime boundary
// description already names. None of them says which check failed in prose
// that a caller could use to search for one that does not: the codes are
// coarse on purpose, and the detail belongs in this unit's own telemetry.

const (
	// maximumTaskBytes bounds the request body. The canonical AgentTask is a
	// bounded document; anything larger is not one.
	maximumTaskBytes = 1 << 20
	// maximumHeaderBytes bounds what a client may send before the body. A
	// runtime that read unbounded headers could be exhausted without ever
	// sending a task.
	maximumHeaderBytes = 1 << 16
	// maximumIdempotencyKeyBytes matches the canonical Idempotency-Key bound.
	maximumIdempotencyKeyBytes = 128
	// replayRegisterSize bounds what one unit remembers about attempts it has
	// answered. It is a bounded cache, not a durable record: Agent Service owns
	// idempotency durably, and this only stops a network retry from executing
	// the same attempt twice inside one process lifetime.
	replayRegisterSize = 1024
)

// The problem codes a refusal carries.
//
// They are the control plane's own vocabulary, not a second one invented here.
// Agent Service branches on these codes, and its in-process stand-in already
// answers an inadmissible task with the same values — a runtime that spelled the
// same meaning differently would split one condition across two vocabularies
// and make the two halves of the boundary disagree about what happened.
const (
	reasonMalformedRequest  = "REQUEST_INVALID"
	reasonUnauthenticated   = "AUTHENTICATION_INVALID"
	reasonNotAuthorized     = "AUTHORIZATION_DENIED"
	reasonContractInvalid   = "CONTRACT_INVALID"
	reasonIdempotencyReuse  = "IDEMPOTENCY_KEY_REUSED"
	reasonAdmissionWindow   = "TASK_DISPATCH_DENIED"
	reasonCapacityExhausted = "ADMISSION_OVERLOADED"
	reasonInternalRefusal   = "INTERNAL_ERROR"
)

// The headers and media type the canonical runtime boundary description names.
const (
	requestDigestHeaderName  = "X-AnvilKit-Request-Digest"
	idempotencyHeaderName    = "Idempotency-Key"
	replayedHeaderName       = "Idempotency-Replayed"
	traceparentHeaderName    = "traceparent"
	problemContentTypeHeader = "application/problem+json"
)

var (
	digestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	traceparentPattern = regexp.MustCompile(`^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)
)

// refusal is one admission decision that ended the request. Status and Code are
// both stable: the status is what the canonical description says this class of
// refusal answers with, and the code is what a caller branches on.
type refusal struct {
	Status int
	Code   string
	// Retryability tells the caller whether the same request could ever
	// succeed. A refusal that did not say would leave a control plane to guess
	// between retrying a transient rejection and replaying a permanent one.
	Retryability string
}

func (r refusal) Error() string { return r.Code }

var (
	malformedRequest  = refusal{Status: http.StatusBadRequest, Code: reasonMalformedRequest, Retryability: "never"}
	invalidCredential = refusal{Status: http.StatusUnauthorized, Code: reasonUnauthenticated, Retryability: "never"}
	notAdmissible     = refusal{Status: http.StatusForbidden, Code: reasonNotAuthorized, Retryability: "never"}
	contractInvalid   = refusal{Status: http.StatusUnprocessableEntity, Code: reasonContractInvalid, Retryability: "never"}
	idempotencyReused = refusal{Status: http.StatusConflict, Code: reasonIdempotencyReuse, Retryability: "never"}
	admissionClosed   = refusal{Status: http.StatusGone, Code: reasonAdmissionWindow, Retryability: "never"}
	capacityExhausted = refusal{Status: http.StatusTooManyRequests, Code: reasonCapacityExhausted, Retryability: "safe-after-backoff"}
	internalRefusal   = refusal{Status: http.StatusInternalServerError, Code: reasonInternalRefusal, Retryability: "safe-after-backoff"}
)

// Admission holds one unit's admission boundary: the release it serves, the
// credential trust it admits against, and what it has already answered.
type Admission struct {
	unit      *Unit
	verifier  *CredentialVerifier
	now       func() time.Time
	replays   *replayRegister
	manifestD string
}

// NewAdmission binds the boundary to the unit it protects.
func NewAdmission(unit *Unit, verifier *CredentialVerifier, now func() time.Time) (*Admission, error) {
	if unit == nil || verifier == nil || now == nil {
		return nil, fmt.Errorf("agent runtime admission: a unit, a credential verifier, and a clock are all required")
	}
	return &Admission{
		unit:      unit,
		verifier:  verifier,
		now:       now,
		replays:   newReplayRegister(replayRegisterSize),
		manifestD: unit.ManifestDigest(),
	}, nil
}

// admitted is a request that survived every check: the task itself, the
// identity of the attempt it belongs to, and the digest of the bytes it arrived
// as.
type admitted struct {
	task          schema.AgentTask
	attemptID     string
	requestDigest string
	// credential is the verified task-scoped credential this attempt arrived
	// with. It is carried forward because it is also the authority for every
	// governed call the turn will make: the same short-lived credential opens
	// the model path and the controlled artifact interface, and a unit that
	// used anything else would be acting with authority nobody issued it.
	credential string
}

// Admit runs the whole boundary for one request and returns the task an Agent
// may be given, or the refusal that ended it.
//
// The order is mostly increasing cost — transport shape, then bytes, then the
// contract, then cryptography, then the release binding — so a request that
// fails cheaply cannot make this unit do the expensive part first.
//
// It is not purely that, and the exception is the point: replaying a recorded
// answer is the cheapest check here and runs almost last, because a recorded
// answer is the product of real work and handing one to a caller that has not
// proved it may ask is disclosure rather than caching. Only the admission
// window comes after it, so work that was done and answered is answered again
// rather than reported as expired to the caller still waiting for it.
func (a *Admission) Admit(w http.ResponseWriter, r *http.Request) (admitted, error) {
	if r.Method != http.MethodPost {
		return admitted{}, refusal{Status: http.StatusMethodNotAllowed, Code: reasonMalformedRequest, Retryability: "never"}
	}
	// A wrong content type and oversized headers are both answered as an
	// invalid request rather than with their own HTTP statuses. The canonical
	// runtime boundary description enumerates what this endpoint answers with,
	// and inventing statuses outside that list would be an undocumented surface
	// a caller has no contract for.
	if mediaTypeOf(r.Header.Get("Content-Type")) != "application/json" {
		return admitted{}, malformedRequest
	}
	if headerBytes(r.Header) > maximumHeaderBytes {
		return admitted{}, malformedRequest
	}
	// The canonical description makes all three of these required parameters.
	// They are validated before the body is read: a request that cannot be
	// correlated, deduplicated, or traced is not one worth decoding.
	idempotencyKey := r.Header.Get(idempotencyHeaderName)
	if idempotencyKey == "" || len(idempotencyKey) > maximumIdempotencyKeyBytes {
		return admitted{}, malformedRequest
	}
	declaredDigest := r.Header.Get(requestDigestHeaderName)
	if !digestPattern.MatchString(declaredDigest) {
		return admitted{}, malformedRequest
	}
	if !traceparentPattern.MatchString(r.Header.Get(traceparentHeaderName)) {
		return admitted{}, malformedRequest
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maximumTaskBytes+1))
	if err != nil || len(body) > maximumTaskBytes {
		return admitted{}, malformedRequest
	}
	// The digest is over the bytes that arrived, and is compared to the one the
	// caller declared. It is what makes a retry of the same attempt
	// distinguishable from a second, different request reusing its key.
	observedDigest := digestOf(body)
	if observedDigest != declaredDigest {
		return admitted{}, malformedRequest
	}

	// Strict decoding against the generated canonical bindings: unknown fields,
	// duplicate members, missing required fields, and out-of-pattern values are
	// all refused, and so is anything after the document. The bindings are
	// generated from the canonical AgentTask schema, so this is the canonical
	// contract and not a second reading of it.
	var task schema.AgentTask
	if err := decodeStrictJSON(body, &task); err != nil {
		return admitted{}, contractInvalid
	}
	if string(task.PhysicalAttemptId) != idempotencyKey {
		// The idempotency identity of a dispatched task is the attempt itself.
		// A key naming something else would deduplicate a different thing from
		// the one being executed.
		return admitted{}, malformedRequest
	}

	token, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		return admitted{}, invalidCredential
	}
	binding, err := a.verifier.Verify(token, a.now())
	if err != nil {
		return admitted{}, invalidCredential
	}
	if mismatch := bindsTask(binding, task, a.unit.Manifest().Workload.Audience); mismatch != "" {
		return admitted{}, notAdmissible
	}
	// The task must be addressed to the release this process actually is. The
	// credential proves Agent Service issued the work; this proves the work was
	// issued to us. A unit that executed a task bound to another release would
	// produce a result nobody could attribute correctly.
	if err := a.bindsRelease(task); err != nil {
		return admitted{}, err
	}

	// Only now is a recorded answer replayed. It would be cheaper to look one
	// up before verifying anything — the register is a map read and the
	// signature is not — but a recorded answer is the result of real work, and
	// handing one back to a caller that has not proved it may ask is
	// disclosure, not caching. The retry that legitimately reaches this point
	// carries the same credential the original did.
	//
	// It is checked before the admission window on purpose: work that was done
	// and answered should be answered again, even if the window has closed
	// since, rather than reported as expired to the caller waiting for it.
	if recorded, replayed, reused := a.replays.lookup(idempotencyKey, observedDigest); reused {
		return admitted{}, idempotencyReused
	} else if replayed {
		writeRecorded(w, recorded, observedDigest)
		return admitted{}, errReplayed
	}

	// The admission window is last because it is the only check whose answer
	// depends on when it is asked.
	if err := a.withinAdmissionWindow(task); err != nil {
		return admitted{}, err
	}
	// The attempt is claimed before it executes. Two deliveries of the same
	// attempt arriving together would both pass every check above — nothing
	// is recorded until the first answers — and both would execute, spending
	// two governed invocations on one attempt. The second is told to come
	// back: by then the first has answered, and the register replays it.
	switch recorded, replayed, reused, inFlight := a.replays.reserve(idempotencyKey, observedDigest); {
	case reused:
		return admitted{}, idempotencyReused
	case replayed:
		writeRecorded(w, recorded, observedDigest)
		return admitted{}, errReplayed
	case inFlight:
		return admitted{}, capacityExhausted
	}
	return admitted{task: task, attemptID: idempotencyKey, requestDigest: observedDigest, credential: token}, nil
}

// Release gives up the claim on an attempt whose execution produced no answer
// to record, so the delivery that follows executes it rather than being told
// it is in flight for ever.
func (a *Admission) Release(attemptID string) {
	a.replays.release(attemptID)
}

// errReplayed reports that the response has already been written from a
// recorded outcome. It is not a refusal: the caller got the answer it asked
// for, and there is nothing further for the handler to do.
var errReplayed = fmt.Errorf("agent runtime admission: a recorded outcome was replayed")

// bindsRelease proves the task was dispatched to this release and no other.
func (a *Admission) bindsRelease(task schema.AgentTask) error {
	manifest := a.unit.Manifest()
	for _, comparison := range [][2]string{
		{string(task.RuntimeBinding.RuntimeUnitId), string(manifest.RuntimeUnitId)},
		{string(task.RuntimeBinding.RuntimeManifestDigest), a.manifestD},
		{string(task.RuntimeBinding.RuntimeImageDigest), string(manifest.Image.ImageDigest)},
		{string(task.RuntimeBinding.InvocationProtocolDigest), string(manifest.Protocol.InvocationProtocolDigest)},
		{task.RuntimeBinding.RuntimeAudience, manifest.Workload.Audience},
		{task.AuthorizationAudience, manifest.Workload.Audience},
		{string(task.Definition.DefinitionId), string(manifest.Definition.DefinitionId)},
	} {
		if comparison[0] != comparison[1] {
			return notAdmissible
		}
	}
	return nil
}

// withinAdmissionWindow proves the work still has a window to be admitted in
// and carries an attempt identity that could be fenced.
//
// A task with no attempt number, lease epoch, or fence is not executable: its
// result could never be committed, so executing it would spend a model call to
// produce something the control plane must throw away.
func (a *Admission) withinAdmissionWindow(task schema.AgentTask) error {
	if task.FenceToken == "" || task.AttemptNumber < 1 || task.LeaseEpoch < 1 || task.ExecutionGeneration < 1 {
		return notAdmissible
	}
	deadline := time.Time(task.ExpiresAt)
	if deadline.IsZero() || !a.now().Before(deadline) {
		return admissionClosed
	}
	return nil
}

// Record remembers the answer this unit gave for one attempt, so a network
// retry of the same attempt is answered rather than executed.
//
// It takes the encoded answer rather than the result, because what a retry must
// receive is the bytes the first caller received and not a second encoding of
// the same value.
func (a *Admission) Record(attemptID, requestDigest string, encoded []byte) {
	a.replays.record(attemptID, requestDigest, encoded)
}

// replayRegister is the bounded memory of what this unit has already answered.
//
// It is deliberately not durable. Agent Service owns idempotency across process
// lifetimes through the logical task and its committed result; what this
// prevents is narrower and real: one attempt executed twice because a response
// was lost in transit and the same request arrived again.
type replayRegister struct {
	lock     sync.Mutex
	limit    int
	order    []string
	outcomes map[string]recordedOutcome
	// pending holds the attempts admitted and not yet answered, by the digest
	// of the request that claimed them. It is what makes a concurrent second
	// delivery of one attempt wait for the first rather than execute beside
	// it.
	pending map[string]string
}

type recordedOutcome struct {
	requestDigest string
	result        []byte
}

func newReplayRegister(limit int) *replayRegister {
	return &replayRegister{limit: limit, outcomes: make(map[string]recordedOutcome, limit), pending: map[string]string{}}
}

// reserve claims one attempt for the caller about to execute it. It answers
// exactly one of: the recorded outcome to replay, a reuse of the attempt
// identity with different bytes, an execution already in flight, or the claim
// itself — in which case the caller executes and must record or release.
func (r *replayRegister) reserve(attemptID, requestDigest string) (result []byte, replayed, reused, inFlight bool) {
	r.lock.Lock()
	defer r.lock.Unlock()
	if recorded, known := r.outcomes[attemptID]; known {
		if recorded.requestDigest != requestDigest {
			return nil, false, true, false
		}
		return recorded.result, true, false, false
	}
	if digest, executing := r.pending[attemptID]; executing {
		if digest != requestDigest {
			return nil, false, true, false
		}
		return nil, false, false, true
	}
	r.pending[attemptID] = requestDigest
	return nil, false, false, false
}

// release withdraws a claim that produced nothing to record.
func (r *replayRegister) release(attemptID string) {
	r.lock.Lock()
	defer r.lock.Unlock()
	delete(r.pending, attemptID)
}

// lookup answers what is known about one attempt: whether a recorded outcome
// may be replayed, and whether the key was reused with different bytes.
func (r *replayRegister) lookup(attemptID, requestDigest string) (result []byte, replayed, reused bool) {
	r.lock.Lock()
	defer r.lock.Unlock()
	recorded, known := r.outcomes[attemptID]
	if !known {
		return nil, false, false
	}
	if recorded.requestDigest != requestDigest {
		return nil, false, true
	}
	return recorded.result, true, false
}

func (r *replayRegister) record(attemptID, requestDigest string, result []byte) {
	r.lock.Lock()
	defer r.lock.Unlock()
	delete(r.pending, attemptID)
	if _, known := r.outcomes[attemptID]; !known {
		if len(r.order) >= r.limit {
			// The oldest entry is evicted rather than the register growing
			// without bound. Losing the memory of an old attempt costs one
			// re-execution in an unlikely case; growing without bound costs the
			// process.
			delete(r.outcomes, r.order[0])
			r.order = r.order[1:]
		}
		r.order = append(r.order, attemptID)
	}
	r.outcomes[attemptID] = recordedOutcome{requestDigest: requestDigest, result: result}
}

// writeRefusal answers one refused request in the governed problem shape.
//
// The message never names the check that failed. A caller that could tell an
// expired credential from one issued for another attempt could search for the
// difference; a control plane that legitimately needs to know reads its own
// evidence, which it has and an attacker does not.
func writeRefusal(w http.ResponseWriter, denied refusal) {
	w.Header().Set("Content-Type", problemContentTypeHeader)
	w.WriteHeader(denied.Status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"kind":         "ProblemDetails",
		"code":         denied.Code,
		"retryability": denied.Retryability,
		"message":      "the dispatched task was not admitted",
		"fieldErrors":  []any{},
	})
}

// writeRecorded replays the outcome this unit already produced for an attempt.
func writeRecorded(w http.ResponseWriter, result []byte, requestDigest string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(replayedHeaderName, "true")
	w.Header().Set(requestDigestHeaderName, requestDigest)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(result)
}

func digestOf(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// mediaTypeOf reads the media type without its parameters, so a charset does
// not turn an acceptable content type into an unacceptable one.
func mediaTypeOf(header string) string {
	if index := bytes.IndexByte([]byte(header), ';'); index >= 0 {
		header = header[:index]
	}
	return trimSpace(lower(header))
}

// bearerToken extracts the credential from an Authorization header. The scheme
// is matched exactly: a unit that accepted any scheme would be accepting
// whatever the caller decided to call its secret.
func bearerToken(header string) (string, bool) {
	const scheme = "Bearer "
	if len(header) <= len(scheme) || header[:len(scheme)] != scheme {
		return "", false
	}
	token := trimSpace(header[len(scheme):])
	if token == "" {
		return "", false
	}
	return token, true
}

// headerBytes measures what the client sent before the body.
func headerBytes(header http.Header) int {
	total := 0
	for name, values := range header {
		for _, value := range values {
			total += len(name) + len(value) + 4
		}
	}
	return total
}

func lower(value string) string {
	out := []byte(value)
	for index, character := range out {
		if character >= 'A' && character <= 'Z' {
			out[index] = character + ('a' - 'A')
		}
	}
	return string(out)
}

func trimSpace(value string) string {
	start, end := 0, len(value)
	for start < end && (value[start] == ' ' || value[start] == '\t') {
		start++
	}
	for end > start && (value[end-1] == ' ' || value[end-1] == '\t') {
		end--
	}
	return value[start:end]
}
