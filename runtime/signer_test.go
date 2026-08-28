package runtime

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"sync"
	"testing"
)

// A unit that emitted unsigned results would produce work nobody could attribute
// to a release, so the key is a start-up precondition rather than a runtime
// option.

func TestAUnitWithoutAUsableSigningKeyRefusesToStart(t *testing.T) {
	usableSeed := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SeedSize))
	for name, environment := range map[string]struct{ key, keyID string }{
		"no key at all":     {"", governedKeyID},
		"not base64url":     {"!!!not-base64!!!", governedKeyID},
		"wrong seed length": {base64.RawURLEncoding.EncodeToString([]byte("too short")), governedKeyID},
		// A signature nobody can resolve a key for is not verifiable, so a key
		// with no governed identity is as unusable as no key at all.
		"no key identity":     {usableSeed, ""},
		"ungoverned identity": {usableSeed, "some-key"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("ANVILKIT_RESULT_SIGNING_KEY", environment.key)
			t.Setenv("ANVILKIT_RESULT_SIGNING_KEY_ID", environment.keyID)
			if _, err := SignerFromEnvironment(); err == nil {
				t.Fatal("a unit was allowed to start without a usable signing key")
			}
		})
	}
}

const governedKeyID = "urn:anvilkit:key:agent-runtime:synthetic"

func TestSignerReturnsVerifiableBytesAndNotADigestLabel(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	t.Setenv("ANVILKIT_RESULT_SIGNING_KEY", base64.RawURLEncoding.EncodeToString(seed))
	t.Setenv("ANVILKIT_RESULT_SIGNING_KEY_ID", governedKeyID)
	signer, err := SignerFromEnvironment()
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}
	statement := []byte(`{"kind":"AgentRuntimeResult"}`)
	envelope, err := signer.Sign(statement)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if envelope.Algorithm != "dsse-ed25519-v1" || envelope.KeyID != governedKeyID {
		t.Fatalf("envelope identity = %+v", envelope)
	}
	if !strings.HasPrefix(envelope.StatementDigest, "sha256:") || len(envelope.StatementDigest) != len("sha256:")+64 {
		t.Fatalf("statement digest is not a sha256 digest: %q", envelope.StatementDigest)
	}
	// The whole point of the envelope: a verifier that holds only the public
	// key, the statement, and these bytes can decide for itself. A digest of
	// the signature would leave it with nothing to check.
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		t.Fatalf("signature is not raw Ed25519 bytes: %q (%v)", envelope.Signature, err)
	}
	public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if !ed25519.Verify(public, preAuthEncoding(statementPayloadType, statement), signature) {
		t.Fatal("the returned signature does not verify against the statement it was taken over")
	}
	// The bytes signed are bound to what they are: a statement replayed as a
	// different payload type must not verify.
	if ed25519.Verify(public, preAuthEncoding("application/json", statement), signature) {
		t.Fatal("the signature is not bound to its payload type")
	}
}

func TestSigningIsSafeFromEveryConcurrentTurn(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	t.Setenv("ANVILKIT_RESULT_SIGNING_KEY", base64.RawURLEncoding.EncodeToString(seed))
	t.Setenv("ANVILKIT_RESULT_SIGNING_KEY_ID", governedKeyID)
	signer, err := SignerFromEnvironment()
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}
	// A unit serves up to its manifest's concurrency and every turn ends in a
	// signature, so Sign is called from several goroutines at once. Identical
	// statements must produce identical signatures regardless of interleaving.
	const parallel = 16
	results := make([]string, parallel)
	var group sync.WaitGroup
	for i := 0; i < parallel; i++ {
		group.Add(1)
		go func(slot int) {
			defer group.Done()
			envelope, signErr := signer.Sign([]byte(`{"kind":"AgentRuntimeResult"}`))
			if signErr != nil {
				t.Error(signErr)
				return
			}
			results[slot] = envelope.Signature
		}(i)
	}
	group.Wait()
	for _, signature := range results {
		if signature != results[0] || signature == "" {
			t.Fatal("concurrent signing produced inconsistent signatures")
		}
	}
}
