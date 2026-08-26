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
	for name, key := range map[string]string{
		"no key at all":     "",
		"not base64url":     "!!!not-base64!!!",
		"wrong seed length": base64.RawURLEncoding.EncodeToString([]byte("too short")),
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("ANVILKIT_RESULT_SIGNING_KEY", key)
			if _, err := SignerFromEnvironment(); err == nil {
				t.Fatal("a unit was allowed to start without a usable signing key")
			}
		})
	}
}

func TestSignerReportsTheGovernedAlgorithmAndBothDigests(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	t.Setenv("ANVILKIT_RESULT_SIGNING_KEY", base64.RawURLEncoding.EncodeToString(seed))
	signer, err := SignerFromEnvironment()
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}
	algorithm, signature, statement, err := signer.Sign([]byte(`{"kind":"AgentRuntimeResult"}`))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if algorithm != "jws-eddsa-v1" {
		t.Fatalf("algorithm = %q", algorithm)
	}
	// Both are digests, and they are different things: one attests the
	// signature, the other the bytes that were signed.
	for name, digest := range map[string]string{"signature": signature, "statement": statement} {
		if !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+64 {
			t.Fatalf("%s digest is not a sha256 digest: %q", name, digest)
		}
	}
	if signature == statement {
		t.Fatal("the signature digest and the statement digest are the same value")
	}
}

func TestSigningIsSafeFromEveryConcurrentTurn(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	t.Setenv("ANVILKIT_RESULT_SIGNING_KEY", base64.RawURLEncoding.EncodeToString(seed))
	signer, err := SignerFromEnvironment()
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}
	// A unit serves up to its manifest's concurrency and every turn ends in a
	// signature, so Sign is called from several goroutines at once. Identical
	// statements must produce identical digests regardless of interleaving.
	const parallel = 16
	results := make([]string, parallel)
	var group sync.WaitGroup
	for i := 0; i < parallel; i++ {
		group.Add(1)
		go func(slot int) {
			defer group.Done()
			_, signature, _, signErr := signer.Sign([]byte(`{"kind":"AgentRuntimeResult"}`))
			if signErr != nil {
				t.Error(signErr)
				return
			}
			results[slot] = signature
		}(i)
	}
	group.Wait()
	for _, signature := range results {
		if signature != results[0] || signature == "" {
			t.Fatal("concurrent signing produced inconsistent digests")
		}
	}
}
