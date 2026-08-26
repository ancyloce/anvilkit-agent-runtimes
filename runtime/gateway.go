package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ModelGateway is the only destination an Agent may send a prompt to.
//
// It is not a provider client. The runtime never learns which provider serves a
// request, never holds a provider key, and never chooses where a prompt goes:
// the control plane governs the model path, and the runtime's whole share of it
// is one call to one endpoint its manifest released it with.
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
// The endpoint is checked against the boundary here rather than at call time,
// so a unit configured to talk somewhere it was not released to talk fails at
// construction instead of on its first real turn.
func NewModelGateway(boundary *Boundary, endpoint, taskScopedToken string, timeout time.Duration) (*ModelGateway, error) {
	if boundary == nil {
		return nil, fmt.Errorf("model gateway: a boundary is required")
	}
	if err := boundary.AllowModelGateway(endpoint); err != nil {
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
		client:   &http.Client{Timeout: timeout},
	}, nil
}

// Prompt is what a runtime may ask for: bounded input under a capability the
// control plane already granted. It carries no model name, no provider, and no
// routing hint — choosing those is the gateway's job.
type Prompt struct {
	Capability string            `json:"capability"`
	Input      string            `json:"input"`
	Parameters map[string]string `json:"parameters,omitempty"`
}

// Completion is what comes back: text and what it cost. The gateway reports
// usage so the control plane can settle it; the runtime only passes it along.
type Completion struct {
	Output       string `json:"output"`
	InputTokens  int    `json:"inputTokens"`
	OutputTokens int    `json:"outputTokens"`
}

// Invoke sends one bounded prompt through the governed gateway.
//
// Every failure is returned as an error rather than retried here. Retry,
// backoff, and replacement dispatch are the scheduler's decisions: a runtime
// that retried on its own would spend budget the control plane did not agree to
// and could outlive the attempt it belongs to.
func (g *ModelGateway) Invoke(ctx context.Context, prompt Prompt) (Completion, error) {
	if err := g.boundary.AllowModelGateway(g.endpoint); err != nil {
		return Completion{}, err
	}
	body, err := json.Marshal(prompt)
	if err != nil {
		return Completion{}, fmt.Errorf("model gateway: encode prompt: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, g.endpoint, bytes.NewReader(body))
	if err != nil {
		return Completion{}, fmt.Errorf("model gateway: build request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+g.token)

	response, err := g.client.Do(request)
	if err != nil {
		// The transport error is not echoed: it can name internal hosts, and a
		// runtime's diagnostics travel back to the control plane in a result.
		return Completion{}, fmt.Errorf("model gateway: the governed model path did not answer")
	}
	// The close error is deliberately dropped: the body has already been read
	// or abandoned, and failing a completed call on a close would report a
	// failure the caller cannot act on.
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return Completion{}, fmt.Errorf("model gateway: refused with status %d", response.StatusCode)
	}
	// Bounded read: a gateway answering with an unbounded body must not be able
	// to exhaust a runtime's memory.
	const maximumBody = 1 << 20
	decoded, err := io.ReadAll(io.LimitReader(response.Body, maximumBody))
	if err != nil {
		return Completion{}, fmt.Errorf("model gateway: read response: %w", err)
	}
	var completion Completion
	if err := json.Unmarshal(decoded, &completion); err != nil {
		return Completion{}, fmt.Errorf("model gateway: response was not a completion")
	}
	return completion, nil
}
