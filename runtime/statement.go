package runtime

import (
	"encoding/json"
	"errors"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
)

// canonicalStatement is the byte sequence a result's provenance is taken over.
//
// It is built from the result with its own provenance cleared, because a
// signature cannot cover itself. Serialization goes through the generated
// contract type, so the signed bytes are the contract's shape rather than a
// second representation that could drift from it.
func canonicalStatement(result schema.AgentRuntimeResult) ([]byte, error) {
	result.Provenance = schema.AgentRuntimeResultProvenance{}
	return json.Marshal(result)
}

// asBoundary reports whether an error is a boundary refusal, so the host can
// name the rule that stopped a turn instead of reporting a generic failure.
func asBoundary(err error, target **BoundaryError) bool {
	return errors.As(err, target)
}
