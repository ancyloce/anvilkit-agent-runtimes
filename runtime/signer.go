package runtime

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
)

// environmentSigner signs results with the key the deployment mounted for this
// unit.
//
// The key signs results and nothing else. It is not a provider credential and
// carries no authority beyond attesting that a particular runtime unit produced
// a particular statement.
type environmentSigner struct{ key ed25519.PrivateKey }

// SignerFromEnvironment reads the unit's result-signing key.
//
// A unit with no key refuses to start. An unsigned result cannot be attributed
// to a release, and a control plane that accepted one would have no way to tell
// a genuine turn from a forged one.
func SignerFromEnvironment() (Signer, error) {
	encoded := os.Getenv("ANVILKIT_RESULT_SIGNING_KEY")
	if encoded == "" {
		return nil, fmt.Errorf("ANVILKIT_RESULT_SIGNING_KEY is required: a runtime unit will not emit unsigned results")
	}
	seed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("ANVILKIT_RESULT_SIGNING_KEY must be a base64url Ed25519 seed")
	}
	return &environmentSigner{key: ed25519.NewKeyFromSeed(seed)}, nil
}

func (s *environmentSigner) Sign(statement []byte) (string, string, string, error) {
	statementSum := sha256.Sum256(statement)
	signature := ed25519.Sign(s.key, statement)
	signatureSum := sha256.Sum256(signature)
	return "jws-eddsa-v1",
		"sha256:" + hex.EncodeToString(signatureSum[:]),
		"sha256:" + hex.EncodeToString(statementSum[:]),
		nil
}
