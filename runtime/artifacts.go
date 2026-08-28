package runtime

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
)

// Artifacts is the controlled interface a runtime writes what it produced
// through.
//
// It is the whole of a unit's write authority, and it is deliberately narrow:
// one governed submission that hands over a document and receives an immutable
// reference back. A runtime never reaches storage, never holds a storage
// credential, never chooses a bucket or key, and never mints an artifact
// identity — the control plane decides all of that, which is what makes the
// reference something a reviewer can trust rather than something the producer
// asserted about itself.
//
// The interface is defined next to its consumer so an Agent can be given a
// controlled test double without the host having to know one exists.
type Artifacts interface {
	// SubmitCandidate writes one PageCandidate and returns the immutable
	// reference the control plane recorded for it.
	SubmitCandidate(ctx context.Context, task schema.AgentTask, candidate schema.PageCandidate) (schema.SharedPrimitivesArtifactReference, error)
}

// artifactClient is the P0 adapter for the controlled artifact interface. It
// speaks the canonical runtime boundary and nothing else.
type artifactClient struct {
	boundary *Boundary
	endpoint string
	client   *http.Client
	// token is the task-scoped credential this attempt was dispatched with. It
	// is the same short-lived credential the model path uses: a unit holds no
	// durable authority to write anything.
	token string
}

// NewArtifacts binds a controlled artifact client to one boundary.
//
// The destination is resolved at construction, so a unit that was not released
// with the artifact path — a Manager, which produces no artifacts — fails to
// build a writer rather than discovering at the end of a turn that it cannot
// write one. That is the difference between a release that cannot write and a
// release that tries.
func NewArtifacts(boundary *Boundary, taskScopedToken string, timeout time.Duration) (Artifacts, error) {
	if boundary == nil {
		return nil, fmt.Errorf("controlled artifacts: a boundary is required")
	}
	endpoint, err := boundary.Resolve(PathRuntimeArtifacts)
	if err != nil {
		return nil, err
	}
	if taskScopedToken == "" {
		return nil, fmt.Errorf("controlled artifacts: a task-scoped credential is required")
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("controlled artifacts: a positive timeout is required")
	}
	return &artifactClient{
		boundary: boundary,
		endpoint: endpoint,
		token:    taskScopedToken,
		client:   boundedClient(timeout),
	}, nil
}

// SubmitCandidate writes one produced candidate through the controlled
// interface and returns what the control plane recorded.
//
// The bytes submitted are the canonical bytes of the document, and the returned
// digest is checked against them. A reference whose digest names something
// other than what was sent is not a reference to this candidate, and returning
// it would hand the control plane a pointer to a document the runtime never
// produced.
func (a *artifactClient) SubmitCandidate(
	ctx context.Context,
	task schema.AgentTask,
	candidate schema.PageCandidate,
) (schema.SharedPrimitivesArtifactReference, error) {
	if err := a.boundary.AllowControlPlane(PathRuntimeArtifacts); err != nil {
		return schema.SharedPrimitivesArtifactReference{}, err
	}
	body, err := canonicalBytes(candidate)
	if err != nil {
		return schema.SharedPrimitivesArtifactReference{}, err
	}
	if len(body) > maximumCandidateBytes {
		// The canonical contract bounds a candidate at 256 KiB. Refusing here
		// rather than letting the control plane refuse keeps a runtime from
		// spending a submission on a document that cannot be recorded.
		return schema.SharedPrimitivesArtifactReference{}, ArtifactWriteError{Detail: "the candidate exceeds the bound the contract records"}
	}
	submitted := digestOf(body)

	key := idempotencyIdentity(string(task.PhysicalAttemptId), artifactSubmissionOperation)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(body))
	if err != nil {
		return schema.SharedPrimitivesArtifactReference{}, ArtifactWriteError{Detail: "the submission could not be built"}
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+a.token)
	request.Header.Set(idempotencyHeaderName, key)
	request.Header.Set(requestDigestHeaderName, submitted)
	request.Header.Set(traceparentHeaderName, task.TraceContext.Traceparent)

	response, err := a.client.Do(request)
	if err != nil {
		// The transport error is not echoed: it can name internal hosts, and a
		// runtime's diagnostics travel back to the control plane in a result.
		return schema.SharedPrimitivesArtifactReference{}, ArtifactWriteError{Detail: "the controlled artifact path did not answer"}
	}
	defer func() { _ = response.Body.Close() }()

	// A submission answers 201 for a new record and, on a retry of the same
	// attempt and the same bytes, replays the recorded outcome. Both are the
	// same fact for a runtime: the artifact exists and this is its reference.
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		return schema.SharedPrimitivesArtifactReference{}, ArtifactWriteError{Detail: "the submission was refused with status " + strconv.Itoa(response.StatusCode)}
	}
	decoded, err := io.ReadAll(io.LimitReader(response.Body, maximumGovernedResponseBytes))
	if err != nil {
		return schema.SharedPrimitivesArtifactReference{}, ArtifactWriteError{Detail: "the answer could not be read within its bound"}
	}
	var recorded schema.AgentArtifact
	if err := decodeStrictJSON(decoded, &recorded); err != nil {
		return schema.SharedPrimitivesArtifactReference{}, ArtifactWriteError{Detail: "the answer was not a recorded artifact"}
	}
	if string(recorded.Digest) != submitted {
		return schema.SharedPrimitivesArtifactReference{}, ArtifactWriteError{Detail: "the recorded artifact does not carry the digest of the document that was submitted"}
	}
	if recorded.ArtifactId == "" || recorded.Reference.MediaType == "" {
		return schema.SharedPrimitivesArtifactReference{}, ArtifactWriteError{Detail: "the recorded artifact carries no reference"}
	}
	if recorded.Reference.SizeBytes != len(body) {
		return schema.SharedPrimitivesArtifactReference{}, ArtifactWriteError{Detail: "the recorded artifact is not the size of the document that was submitted"}
	}
	return schema.SharedPrimitivesArtifactReference{
		ArtifactId: recorded.ArtifactId,
		Digest:     recorded.Digest,
		MediaType:  recorded.Reference.MediaType,
		SizeBytes:  recorded.Reference.SizeBytes,
	}, nil
}

// ArtifactWriteError reports that the controlled artifact interface did not
// record what the turn produced.
//
// It is a typed failure rather than a generic one because the scheduler acts on
// it: a candidate that was composed but not recorded is work that can be
// attempted again, and it is not the same as a turn that declined to produce
// one. The detail names what went wrong at the interface and never the
// destination or the document.
type ArtifactWriteError struct{ Detail string }

func (e ArtifactWriteError) Error() string {
	return "controlled artifacts: " + e.Detail
}

const (
	// artifactSubmissionOperation names the one artifact write a turn makes, so
	// a retried attempt replays the recorded submission instead of producing a
	// second immutable record of the same work.
	artifactSubmissionOperation = "artifact.candidate"
	// maximumCandidateBytes is the candidate bound the canonical contract
	// records (x-anvilkit-contract maximumSerializedBytes).
	maximumCandidateBytes = 262144
)
