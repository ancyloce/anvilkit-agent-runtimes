package runtime

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
)

// The task credential is minted by Agent Service and verified here, from two
// implementations in two repositories that share no code. This vector is the
// only thing holding them to one format: Agent Service asserts it reproduces
// these exact bytes, and this asserts they verify and bind what they claim.
//
// A change to the format fails on both sides at once, which is the point. The
// alternative is a runtime that stops admitting real work in production because
// something about the encoding moved and nothing said so.

type credentialVector struct {
	IssuerSeed    string            `json:"issuerSeed"`
	KeyID         string            `json:"keyId"`
	Issuer        string            `json:"issuer"`
	Audience      string            `json:"audience"`
	IssuedAtUnix  int64             `json:"issuedAtUnix"`
	ExpiresAtUnix int64             `json:"expiresAtUnix"`
	Task          schema.AgentTask  `json:"task"`
	Subject       map[string]string `json:"subject"`
	Credential    string            `json:"credential"`
}

func loadCredentialVector(t *testing.T) credentialVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "task-credential.vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector credentialVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

// vectorVerifier builds the operator trust root that approves the vector's
// issuing key, from the public half of the seed the vector carries.
func vectorVerifier(t *testing.T, vector credentialVector, audience string, now time.Time) *CredentialVerifier {
	t.Helper()
	seed, err := base64.RawURLEncoding.DecodeString(vector.IssuerSeed)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("the vector's issuing seed is not an Ed25519 seed")
	}
	public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	document, err := json.Marshal(map[string]any{
		"kind":                    trustRootKind,
		"snapshotId":              "task-credential-vector",
		"issuedAt":                now.Add(-time.Hour).Format(trustTimestamp),
		"nextUpdate":              now.Add(time.Hour).Format(trustTimestamp),
		"maximumClockSkewSeconds": 0,
		"keys": []any{map[string]any{
			"keyId":        vector.KeyID,
			"issuer":       vector.Issuer,
			"audiences":    []string{vector.Audience},
			"algorithms":   []string{credentialAlgorithm},
			"publicKeyJwk": map[string]string{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(public)},
			"status":       "active",
			"notBefore":    now.Add(-time.Hour).Format(trustTimestamp),
			"notAfter":     now.Add(time.Hour).Format(trustTimestamp),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "trust-root.json")
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	verifier, err := NewCredentialVerifier(path, audience)
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

// The credential Agent Service minted verifies here, and binds exactly the task
// it was minted for. Nothing about this file was produced by this package.
func TestTheKnownAnswerCredentialVerifiesAndBindsItsTask(t *testing.T) {
	vector := loadCredentialVector(t)
	at := time.Unix(vector.IssuedAtUnix, 0).UTC()
	binding, err := vectorVerifier(t, vector, vector.Audience, at).Verify(vector.Credential, at)
	if err != nil {
		t.Fatalf("the credential Agent Service minted did not verify here: %v", err)
	}
	if mismatch := bindsTask(binding, vector.Task, vector.Audience); mismatch != "" {
		t.Fatalf("the credential did not bind the task it was minted for: %s", mismatch)
	}
	if binding.WorkspaceID != vector.Subject["workspaceId"] || binding.ProjectID != vector.Subject["projectId"] {
		t.Fatalf("the verified tenant is %+v, not the one the credential was issued inside", binding)
	}
	if binding.Operation != operationExecute {
		t.Fatalf("the credential authorizes %q, not execution", binding.Operation)
	}
}

// The same credential, presented at a release it was not minted for, is
// refused. A unit's audience is its own and is never read from the token.
func TestTheKnownAnswerCredentialIsRefusedAtAnotherRelease(t *testing.T) {
	vector := loadCredentialVector(t)
	at := time.Unix(vector.IssuedAtUnix, 0).UTC()
	const elsewhere = "urn:anvilkit:audience:runtime-page-candidate-specialist"
	if _, err := vectorVerifier(t, vector, elsewhere, at).Verify(vector.Credential, at); err == nil {
		t.Fatal("a credential minted for one release verified at another")
	}
}

// The same credential, after its window closed, is refused. An expired
// credential is what a captured one becomes.
func TestTheKnownAnswerCredentialIsRefusedAfterItsWindow(t *testing.T) {
	vector := loadCredentialVector(t)
	expiry := time.Unix(vector.ExpiresAtUnix, 0).UTC()
	if _, err := vectorVerifier(t, vector, vector.Audience, expiry).Verify(vector.Credential, expiry); err == nil {
		t.Fatal("an expired credential verified")
	}
}
