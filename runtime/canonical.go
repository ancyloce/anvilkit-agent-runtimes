package runtime

import (
	"encoding/json"
	"fmt"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
	"github.com/lattice-substrate/json-canon/jcs"
)

const (
	// modelInvocationScope and artifactSubmissionScope are the idempotency
	// scopes the canonical runtime boundary declares for these operations:
	// "attempt-and-operation". Two different governed calls inside one attempt
	// are two operations, and a scope that did not say so would make the second
	// call look like a retry of the first.
	modelInvocationScope    = "attempt-and-operation"
	artifactSubmissionScope = "attempt-and-operation"

	// maximumGovernedResponseBytes bounds every answer read from the control
	// plane. The canonical documents on this boundary are bounded; a response
	// larger than this is not one of them, and reading it would let a
	// compromised or confused control plane exhaust a runtime's memory.
	maximumGovernedResponseBytes = 1 << 20
)

// idempotencyIdentity is the identity one governed call is deduplicated by:
// the physical attempt that is making it, and the operation it is. It is the
// scope the canonical boundary declares, spelled as one bounded key.
//
// The attempt comes first so that every key a single attempt produces shares a
// prefix, which is what lets a control plane retire them together when the
// attempt is superseded.
func idempotencyIdentity(physicalAttemptID, operation string) string {
	return physicalAttemptID + ":" + operation
}

// canonicalDigest is the digest of a value's canonical bytes.
//
// Canonical means RFC 8785 (JCS), not language-native serialization: the
// control plane verifies these digests with a different implementation, and
// only a canonical form makes two implementations agree about what was hashed.
func canonicalDigest(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("canonical digest: encode value: %w", err)
	}
	canonical, err := jcs.Canonicalize(encoded)
	if err != nil {
		return "", fmt.Errorf("canonical digest: canonicalize value: %w", err)
	}
	return digestOf(canonical), nil
}

// canonicalDigestExcluding is the digest of a document with named top-level
// members removed.
//
// It exists for the self-referential case: a document that carries the digest
// of itself cannot include that field in what is hashed. Removing the whole
// member rather than blanking it keeps the definition unambiguous — there is no
// placeholder value two implementations could spell differently.
func canonicalDigestExcluding(value any, members ...string) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("canonical digest: encode value: %w", err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &document); err != nil {
		return "", fmt.Errorf("canonical digest: decode value: %w", err)
	}
	for _, member := range members {
		delete(document, member)
	}
	reduced, err := json.Marshal(document)
	if err != nil {
		return "", fmt.Errorf("canonical digest: encode reduced value: %w", err)
	}
	canonical, err := jcs.Canonicalize(reduced)
	if err != nil {
		return "", fmt.Errorf("canonical digest: canonicalize reduced value: %w", err)
	}
	return digestOf(canonical), nil
}

// canonicalBytes is the exact byte sequence a document is submitted and
// digested as. Submitting the same bytes that were hashed is what makes an
// immutable reference verifiable by whoever reads it back.
func canonicalBytes(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("canonical bytes: encode value: %w", err)
	}
	canonical, err := jcs.Canonicalize(encoded)
	if err != nil {
		return nil, fmt.Errorf("canonical bytes: canonicalize value: %w", err)
	}
	return canonical, nil
}

// SelfDigest is the digest a document carries about itself: taken over the
// document with that one member removed, because a document cannot contain the
// hash of itself.
func SelfDigest(value any, member string) (string, error) {
	return canonicalDigestExcluding(value, member)
}

// PinDocument content-addresses a document a runtime produced.
//
// It returns a reference whose digest is taken over the document's canonical
// bytes, whose size is those bytes' length, and whose identity is derived from
// that digest. Deriving the identity rather than allocating one is deliberate:
// two attempts that composed the same document must produce the same reference,
// and an identity a runtime chose freely could not be checked by anyone.
//
// This is how the page document a candidate pins is named. It is distinct from
// the controlled artifact interface, which is how a document is *recorded*: the
// canonical P0 runtime boundary offers exactly one submission per attempt — the
// candidate — so the page document beneath it is carried as a content-addressed
// pin rather than as a second recorded artifact. The digest is exact and
// recomputable from the composition the candidate describes, and closing the
// gap between a pin and a stored object is a control-plane change, not
// something a runtime can assert its way out of.
func PinDocument(value any, mediaType string) (schema.SharedPrimitivesArtifactReference, error) {
	if !mediaTypePattern.MatchString(mediaType) {
		return schema.SharedPrimitivesArtifactReference{}, fmt.Errorf("pin document: %q is not a media type", mediaType)
	}
	bytes, err := canonicalBytes(value)
	if err != nil {
		return schema.SharedPrimitivesArtifactReference{}, err
	}
	digest := digestOf(bytes)
	return schema.SharedPrimitivesArtifactReference{
		ArtifactId: schema.SharedPrimitivesOpaqueId("artifact.pagedata." + digest[len("sha256:"):len("sha256:")+32]),
		Digest:     schema.SharedPrimitivesDigest(digest),
		MediaType:  mediaType,
		SizeBytes:  len(bytes),
	}, nil
}

// CanonicalDigest is the digest of a value's canonical bytes.
//
// It is exported because the digests on this boundary are shared facts: the
// governed gateway attests the digest of its output, the controlled artifact
// interface records the digest of what was submitted, and anything standing on
// either side of those has to compute the same value the same way.
func CanonicalDigest(value any) (string, error) { return canonicalDigest(value) }
