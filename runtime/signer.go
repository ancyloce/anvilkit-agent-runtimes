package runtime

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
)

// keyIdentity is the governed shape of a signing key reference. A verifier
// resolves the key by this name against its trust snapshot, so a result that
// named no key, or named one in a shape no registry uses, could not be
// verified at all.
var keyIdentity = regexp.MustCompile(`^urn:anvilkit:key:[a-z0-9][a-z0-9:-]{14,255}$`)

// environmentSigner signs results with the key the deployment mounted for this
// unit.
//
// The key signs results and nothing else. It is not a provider credential and
// carries no authority beyond attesting that a particular runtime unit produced
// a particular statement.
type environmentSigner struct {
	key   ed25519.PrivateKey
	keyID string
}

// SignerFromEnvironment reads the unit's result-signing key and its identity.
//
// A unit with no key, or no name for its key, refuses to start. An unsigned
// result cannot be attributed to a release, and a signature whose key cannot be
// resolved is not verifiable, so neither is worth returning.
func SignerFromEnvironment() (Signer, error) {
	encoded := os.Getenv("ANVILKIT_RESULT_SIGNING_KEY")
	if encoded == "" {
		return nil, fmt.Errorf("ANVILKIT_RESULT_SIGNING_KEY is required: a runtime unit will not emit unsigned results")
	}
	seed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("ANVILKIT_RESULT_SIGNING_KEY must be a base64url Ed25519 seed")
	}
	keyID := os.Getenv("ANVILKIT_RESULT_SIGNING_KEY_ID")
	if !keyIdentity.MatchString(keyID) {
		return nil, fmt.Errorf("ANVILKIT_RESULT_SIGNING_KEY_ID must be a governed urn:anvilkit:key identity")
	}
	return &environmentSigner{key: ed25519.NewKeyFromSeed(seed), keyID: keyID}, nil
}

// preAuthEncoding is the DSSE pre-authentication encoding: the signed bytes
// bind the payload type to the payload, so a statement cannot be replayed as a
// different kind of document.
func preAuthEncoding(payloadType string, payload []byte) []byte {
	prefix := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	return append([]byte(prefix), payload...)
}

func (s *environmentSigner) Sign(statement []byte) (SignedStatement, error) {
	statementSum := sha256.Sum256(statement)
	signature := ed25519.Sign(s.key, preAuthEncoding(statementPayloadType, statement))
	return SignedStatement{
		Algorithm: "dsse-ed25519-v1",
		KeyID:     s.keyID,
		// The signature travels as bytes, not as a digest of bytes: a digest
		// proves nothing to a verifier who does not already hold the signature
		// it was taken over.
		Signature:       base64.RawURLEncoding.EncodeToString(signature),
		StatementDigest: "sha256:" + hex.EncodeToString(statementSum[:]),
	}, nil
}
