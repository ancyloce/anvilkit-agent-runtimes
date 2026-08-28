package runtime

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// The trust root is the operator's statement of which keys may issue task
// credentials to this unit. It is distributed independently of Agent Service,
// so the service that mints credentials cannot also decide which keys are
// trusted to mint them.
//
// This is deliberately a second implementation of the document Agent Service
// reads. The two processes are separate deployments in separate repositories
// and share no code; what holds them to one format is the format itself and the
// known-answer credential vector both sides verify against.
const (
	// trustRootKind is the only document kind accepted.
	trustRootKind = "ContractTrustRoot"
	// trustTimestamp is the layout every timestamp in the trust material uses.
	trustTimestamp = "2006-01-02T15:04:05.000Z"
	// maximumTrustRootBytes bounds what is read from the operator's material.
	maximumTrustRootBytes = 262144
)

// trustKey is one operator-approved verification key.
type trustKey struct {
	KeyID        string   `json:"keyId"`
	Issuer       string   `json:"issuer"`
	Audiences    []string `json:"audiences"`
	Algorithms   []string `json:"algorithms"`
	PublicKeyJwk struct {
		KeyType string `json:"kty"`
		Curve   string `json:"crv"`
		X       string `json:"x"`
	} `json:"publicKeyJwk"`
	Status    string `json:"status"`
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
}

// trustRoot is the pinned public trust snapshot.
type trustRoot struct {
	Kind                    string     `json:"kind"`
	SnapshotID              string     `json:"snapshotId"`
	IssuedAt                string     `json:"issuedAt"`
	NextUpdate              string     `json:"nextUpdate"`
	MaximumClockSkewSeconds int        `json:"maximumClockSkewSeconds"`
	Keys                    []trustKey `json:"keys"`
}

// parseTrustRoot decodes and freshness-checks one trust root, returning it and
// the clock skew the operator declared.
//
// A root past its own freshness bound is refused rather than used with a
// warning. A trust root that outlives its declared life is exactly how a
// revoked key keeps working.
func parseTrustRoot(raw []byte, now time.Time) (trustRoot, time.Duration, error) {
	if len(raw) == 0 || len(raw) > maximumTrustRootBytes {
		return trustRoot{}, 0, fmt.Errorf("task credential trust: the trust root is empty or unbounded")
	}
	var root trustRoot
	if err := decodeStrictJSON(raw, &root); err != nil {
		return trustRoot{}, 0, fmt.Errorf("task credential trust: decode trust root: %w", err)
	}
	if root.Kind != trustRootKind || root.SnapshotID == "" || len(root.Keys) == 0 || len(root.Keys) > 32 {
		return trustRoot{}, 0, fmt.Errorf("task credential trust: the trust root is incomplete")
	}
	if root.MaximumClockSkewSeconds < 0 || root.MaximumClockSkewSeconds > 300 {
		return trustRoot{}, 0, fmt.Errorf("task credential trust: the declared clock skew is outside the accepted bound")
	}
	nextUpdate, err := time.Parse(trustTimestamp, root.NextUpdate)
	if err != nil {
		return trustRoot{}, 0, fmt.Errorf("task credential trust: the freshness bound is malformed")
	}
	skew := time.Duration(root.MaximumClockSkewSeconds) * time.Second
	if now.After(nextUpdate.Add(skew)) {
		return trustRoot{}, 0, fmt.Errorf("task credential trust: the trust root is past its declared freshness bound")
	}
	return root, skew, nil
}

// resolveTrustKey answers the verification key for one credential, or refuses.
//
// Every field is matched: a key is usable for the issuer, audience, and
// algorithm the operator approved it for and for nothing else. The audience the
// caller passes is this unit's own — never the one the token claims — so a
// credential minted for another release cannot select the key that verifies it.
func resolveTrustKey(root trustRoot, keyID, issuer, audience, algorithm string, now time.Time, skew time.Duration) (ed25519.PublicKey, error) {
	for _, candidate := range root.Keys {
		if candidate.KeyID != keyID {
			continue
		}
		if candidate.Status != "active" && candidate.Status != "overlap" {
			return nil, fmt.Errorf("task credential trust: the issuing key is not usable")
		}
		if candidate.Issuer != issuer {
			return nil, fmt.Errorf("task credential trust: the issuing key does not belong to the credential issuer")
		}
		if !containsValue(candidate.Audiences, audience) || !containsValue(candidate.Algorithms, algorithm) {
			return nil, fmt.Errorf("task credential trust: the issuing key is not approved for this audience and algorithm")
		}
		notBefore, err := time.Parse(trustTimestamp, candidate.NotBefore)
		if err != nil {
			return nil, fmt.Errorf("task credential trust: the key validity start is malformed")
		}
		notAfter, err := time.Parse(trustTimestamp, candidate.NotAfter)
		if err != nil {
			return nil, fmt.Errorf("task credential trust: the key validity end is malformed")
		}
		if now.Add(skew).Before(notBefore) || now.After(notAfter.Add(skew)) {
			return nil, fmt.Errorf("task credential trust: the issuing key is outside its validity interval")
		}
		if candidate.PublicKeyJwk.KeyType != "OKP" || candidate.PublicKeyJwk.Curve != "Ed25519" {
			return nil, fmt.Errorf("task credential trust: the issuing key is not an Ed25519 key")
		}
		material, err := base64.RawURLEncoding.DecodeString(candidate.PublicKeyJwk.X)
		if err != nil || len(material) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("task credential trust: the issuing key material is malformed")
		}
		return ed25519.PublicKey(material), nil
	}
	return nil, fmt.Errorf("task credential trust: the credential key is not in the pinned trust root")
}

// decodeStrictJSON decodes exactly one JSON value with no unknown fields and no
// trailing content. Material with a member this process does not understand is
// material it cannot claim to have verified.
func decodeStrictJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("the document must contain exactly one JSON value")
	}
	return nil
}

func containsValue(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
