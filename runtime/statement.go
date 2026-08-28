package runtime

import (
	"encoding/json"
	"fmt"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
	"github.com/lattice-substrate/json-canon/jcs"
)

// statementPayloadType is the DSSE payload type the canonical profile assigns
// to a signed AgentRuntimeResult statement.
const statementPayloadType = "application/vnd.anvilkit.agent-runtime-result+json"

// canonicalStatement is the byte sequence a result's signature is taken over.
//
// The canonical profile defines it as the result document with the signature
// envelope removed — an envelope cannot be inside the bytes it signs — encoded
// as RFC 8785 (JCS) canonical bytes. Language-native serialization is not an
// option: Agent Service verifies these bytes with a different implementation in
// a different language, and only a canonical form makes those two agree.
func canonicalStatement(result schema.AgentRuntimeResult) ([]byte, error) {
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("agent runtime statement: encode result: %w", err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &document); err != nil {
		return nil, fmt.Errorf("agent runtime statement: decode result: %w", err)
	}
	delete(document, "signature")
	withoutEnvelope, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("agent runtime statement: encode statement: %w", err)
	}
	canonical, err := jcs.Canonicalize(withoutEnvelope)
	if err != nil {
		return nil, fmt.Errorf("agent runtime statement: canonicalize statement: %w", err)
	}
	return canonical, nil
}
