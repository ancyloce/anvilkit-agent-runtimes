package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
)

// ModelGateway is the only destination an Agent may send a prompt to.
//
// It is not a provider client. The runtime never learns which provider serves a
// request, never holds a provider key, and never chooses where a prompt goes:
// the control plane governs the model path, and the runtime's whole share of it
// is one call to one released path.
//
// What travels is deliberately thin. The canonical ModelInvocationRequest
// carries the attempt's identity, the definition and model policy Agent Service
// pinned, and the digests of the compiled context and prompt — never the
// context or prompt themselves. A runtime that could send prompt text could
// send text nobody compiled, and the gateway would have no way to tell the
// difference.
type ModelGateway struct {
	boundary *Boundary
	endpoint string
	client   *http.Client
	// token is the task-scoped credential the control plane issued for this
	// attempt. It is not a provider key and is not durable — it arrives with
	// the task and dies with it.
	token string
}

// NewModelGateway binds a gateway client to one boundary.
//
// The destination is resolved from the boundary here rather than at call time,
// so a unit that was not released with the governed model path fails at
// construction instead of on its first real turn.
func NewModelGateway(boundary *Boundary, taskScopedToken string, timeout time.Duration) (*ModelGateway, error) {
	if boundary == nil {
		return nil, fmt.Errorf("model gateway: a boundary is required")
	}
	endpoint, err := boundary.Resolve(PathModelInvocations)
	if err != nil {
		return nil, err
	}
	if taskScopedToken == "" {
		return nil, fmt.Errorf("model gateway: a task-scoped credential is required")
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("model gateway: a positive timeout is required")
	}
	return &ModelGateway{
		boundary: boundary,
		endpoint: endpoint,
		token:    taskScopedToken,
		client:   boundedClient(timeout),
	}, nil
}

// Prompt is what a runtime may ask for: the governed inputs, named by digest,
// under the policy the control plane already pinned.
//
// Operation distinguishes several invocations inside one physical attempt. It
// is part of the idempotency identity, which is what makes a retried turn
// replay the answer it already bought instead of buying a second one.
type Prompt struct {
	Operation     string
	ContextDigest string
	PromptDigest  string
	ModelPolicy   schema.SharedPrimitivesPolicyReference
}

// Completion is what comes back: the bounded governed output, the invocation
// the control plane recorded it under, and what it cost. The gateway meters
// usage so the control plane can settle it; the runtime only passes it along.
type Completion struct {
	InvocationID string
	Outcome      string
	ReasonCode   string
	Output       map[string]string
	InputTokens  int
	OutputTokens int
	// DurationMilliseconds and Cost are what the gateway attributed to this
	// invocation, not what the runtime observed. A runtime that timed its own
	// call would be reporting the network as if it were the model.
	DurationMilliseconds int
	CostAmount           string
	CostCurrency         string
}

// ModelRefusedError reports a governed model outcome that is not usable output.
// It is separate from a transport failure because the two are different facts:
// a refusal is the governed path working and saying no, and a turn that treated
// it as a failure would ask the scheduler to retry a decision that was made.
type ModelRefusedError struct {
	Outcome    string
	ReasonCode string
}

func (e ModelRefusedError) Error() string {
	return "model gateway: the governed model path answered " + e.Outcome + " (" + e.ReasonCode + ")"
}

// ModelUnavailableError reports that the governed model path could not serve
// the invocation at all: it did not answer, answered with a status, or answered
// with something that is not a governed result.
//
// It is the other half of the distinction ModelRefusedError draws. A refusal is
// an answer and must not be retried; this is the absence of one, and the
// scheduler may reasonably replace the attempt. The detail is deliberately
// coarse and never carries the transport error, which can name internal hosts.
type ModelUnavailableError struct{ Detail string }

func (e ModelUnavailableError) Error() string {
	return "model gateway: the governed model path could not serve this invocation: " + e.Detail
}

// Invoke sends one bounded, governed invocation for one physical attempt.
//
// Every failure is returned as an error rather than retried here. Retry,
// backoff, and replacement dispatch are the scheduler's decisions: a runtime
// that retried on its own would spend budget the control plane did not agree to
// and could outlive the attempt it belongs to.
func (g *ModelGateway) Invoke(ctx context.Context, task schema.AgentTask, prompt Prompt) (Completion, error) {
	if err := g.boundary.AllowControlPlane(PathModelInvocations); err != nil {
		return Completion{}, err
	}
	if prompt.Operation == "" {
		return Completion{}, fmt.Errorf("model gateway: an invocation must name the operation it is")
	}
	if !digestPattern.MatchString(prompt.ContextDigest) || !digestPattern.MatchString(prompt.PromptDigest) {
		// A runtime that invoked without both digests would be asking the
		// gateway to choose the context or the prompt, which is the one thing
		// naming them by digest exists to prevent.
		return Completion{}, fmt.Errorf("model gateway: an invocation must name the compiled context and prompt it was pinned to")
	}
	if prompt.ModelPolicy.PolicyId == "" || prompt.ModelPolicy.Version == "" || !digestPattern.MatchString(string(prompt.ModelPolicy.Digest)) {
		return Completion{}, fmt.Errorf("model gateway: an invocation must carry the model policy the control plane pinned")
	}

	key := idempotencyIdentity(string(task.PhysicalAttemptId), prompt.Operation)
	request := schema.ModelInvocationRequest{
		Kind:                "ModelInvocationRequest",
		RunId:               task.RunId,
		RootRunId:           task.RootRunId,
		TaskId:              task.TaskId,
		PhysicalAttemptId:   task.PhysicalAttemptId,
		AttemptNumber:       task.AttemptNumber,
		ExecutionGeneration: task.ExecutionGeneration,
		Definition:          task.Definition,
		ModelPolicy:         prompt.ModelPolicy,
		ContextDigest:       schema.SharedPrimitivesDigest(prompt.ContextDigest),
		PromptDigest:        schema.SharedPrimitivesDigest(prompt.PromptDigest),
		Limits:              task.Limits,
		TraceContext:        task.TraceContext,
		// The BOM the attempt was dispatched under travels unchanged. A runtime
		// that named a different one would be asking the gateway to resolve the
		// policy against contracts other than the ones the run is pinned to.
		ContractBomReference: task.ContractBomReference,
		Idempotency: schema.SharedPrimitivesIdempotency{
			Scope: modelInvocationScope,
			Key:   key,
		},
	}
	// The canonical request digest covers the request without the digest field
	// it will carry: a document cannot contain the hash of itself. It is the
	// same construction the result statement uses, for the same reason.
	digest, err := canonicalDigestExcluding(request, "idempotency")
	if err != nil {
		return Completion{}, err
	}
	request.Idempotency.CanonicalRequestDigest = schema.SharedPrimitivesDigest(digest)

	body, err := json.Marshal(request)
	if err != nil {
		return Completion{}, fmt.Errorf("model gateway: encode invocation: %w", err)
	}
	response, err := g.send(ctx, body, key, task.TraceContext.Traceparent)
	if err != nil {
		return Completion{}, err
	}

	var result schema.ModelInvocationResult
	if err := decodeStrictJSON(response, &result); err != nil {
		return Completion{}, ModelUnavailableError{Detail: "the answer was not a governed model result"}
	}
	if err := boundsResult(result, task); err != nil {
		return Completion{}, err
	}
	// The usage is read before the outcome is judged. A refused invocation
	// still spent whatever the gateway metered for it, and an attempt that
	// reported only its successful calls would understate what the control
	// plane has to settle.
	completion := Completion{
		InvocationID:         string(result.InvocationId),
		Outcome:              string(result.Outcome),
		ReasonCode:           result.ReasonCode,
		InputTokens:          result.Usage.InputTokens,
		OutputTokens:         result.Usage.OutputTokens,
		DurationMilliseconds: result.Usage.DurationMilliseconds,
		CostAmount:           string(result.Usage.Cost.Amount),
		CostCurrency:         result.Usage.Cost.Currency,
	}
	if result.Outcome != schema.ModelInvocationResultOutcomeOk {
		return completion, ModelRefusedError{Outcome: string(result.Outcome), ReasonCode: result.ReasonCode}
	}
	// The output digest is checked, not trusted. It is the gateway's own
	// statement about the bytes it metered, and a runtime that composed a page
	// from output the gateway did not attest to would be reasoning over
	// something no invocation record covers.
	observed, err := canonicalDigest(result.Output)
	if err != nil {
		return Completion{}, err
	}
	if observed != string(result.OutputDigest) {
		// The tokens were spent, so the completion still carries them, but the
		// output is not usable: nothing the gateway attested covers these bytes.
		return completion, ModelUnavailableError{Detail: "the governed output does not match the digest the gateway attested"}
	}
	completion.Output = map[string]string(result.Output)
	return completion, nil
}

// boundsResult proves the answer belongs to the invocation that was made. A
// gateway answering with another attempt's result would attribute its tokens,
// and its output, to work that did not ask for it.
func boundsResult(result schema.ModelInvocationResult, task schema.AgentTask) error {
	if result.TaskId != task.TaskId ||
		result.PhysicalAttemptId != task.PhysicalAttemptId ||
		result.AttemptNumber != task.AttemptNumber ||
		result.ExecutionGeneration != task.ExecutionGeneration {
		return ModelUnavailableError{Detail: "the governed result does not belong to this attempt"}
	}
	if result.InvocationId == "" {
		return ModelUnavailableError{Detail: "the governed result records no invocation identity"}
	}
	return nil
}

// send performs the one request this client makes and returns the bounded body.
func (g *ModelGateway) send(ctx context.Context, body []byte, idempotencyKey, traceparent string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, g.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("model gateway: build request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+g.token)
	request.Header.Set(idempotencyHeaderName, idempotencyKey)
	request.Header.Set(requestDigestHeaderName, digestOf(body))
	request.Header.Set(traceparentHeaderName, traceparent)

	response, err := g.client.Do(request)
	if err != nil {
		// The transport error is not echoed: it can name internal hosts, and a
		// runtime's diagnostics travel back to the control plane in a result.
		return nil, ModelUnavailableError{Detail: "the governed model path did not answer"}
	}
	// The close error is deliberately dropped: the body has already been read
	// or abandoned, and failing a completed call on a close would report a
	// failure the caller cannot act on.
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return nil, ModelUnavailableError{Detail: "the governed model path answered with status " + strconv.Itoa(response.StatusCode)}
	}
	// Bounded read: a gateway answering with an unbounded body must not be able
	// to exhaust a runtime's memory.
	decoded, err := io.ReadAll(io.LimitReader(response.Body, maximumGovernedResponseBytes))
	if err != nil {
		return nil, ModelUnavailableError{Detail: "the governed model path answer could not be read within its bound"}
	}
	return decoded, nil
}

// Value reads one governed output value, following the same indexed
// continuation convention the supplied context uses: `key` alone, or `key.0`,
// `key.1`, … concatenated in index order. Model output is bounded by the same
// map bound the task's parameters are, so a composition longer than one bound
// arrives the same way a supplied constraint does.
func (c Completion) Value(key string) (string, bool) {
	return boundedOutput(c.Output, key)
}

// Document reads one governed output value and decodes it as JSON.
//
// Output that does not parse is a refusal, not a repair: a runtime that
// salvaged a malformed answer would be authoring the part it salvaged, and the
// invocation record would attribute that part to the model.
func (c Completion) Document(key string, target any) error {
	value, present := c.Value(key)
	if !present {
		return &ModelOutputError{Key: key}
	}
	if err := json.Unmarshal([]byte(value), target); err != nil {
		return &ModelOutputError{Key: key}
	}
	return nil
}

// ModelOutputError reports governed output that is missing or unusable. It
// names the key the turn expected and never the output itself: model output is
// untrusted content, and a diagnostic that echoed it would carry that content
// out to the control plane's evidence.
type ModelOutputError struct{ Key string }

func (e *ModelOutputError) Error() string {
	return "model gateway: the governed output carries no usable " + e.Key
}
