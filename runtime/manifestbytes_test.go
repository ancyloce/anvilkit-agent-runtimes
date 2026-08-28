package runtime

import (
	"encoding/json"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
)

// mustManifestBytes renders one manifest as the released bytes a unit would be
// deployed with, so a test's unit reports the digest of exactly those bytes.
func mustManifestBytes(manifest schema.AgentRuntimeManifest) []byte {
	encoded, err := json.Marshal(manifest)
	if err != nil {
		panic(err)
	}
	return encoded
}
