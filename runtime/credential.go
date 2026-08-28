package runtime

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
)

// The canonical runtime boundary description declares the task credential as a
// bearer JWT. These constants are the whole of that format; Agent Service mints
// against the same three and the known-answer vector in testdata is what holds
// the two implementations to one format.
const (
	// credentialAlgorithm is the JWS algorithm (RFC 8037 Ed25519).
	credentialAlgorithm = "EdDSA"
	// credentialType is the JOSE type header. A distinct type stops a token
	// minted to dispatch a task from being replayed as any other kind of JWT
	// the same key might sign.
	credentialType = "anvilkit-task-credential+jwt"
	// credentialIssuer is the only identity a task credential may be issued
	// under.
	credentialIssuer = "urn:anvilkit:service:agent-service"
	// credentialBindingClaim carries everything the credential binds beyond the
	// registered claims.
	credentialBindingClaim = "urn:anvilkit:claim:task-binding"
	// operationExecute is the operation a dispatched task requires. A
	// credential issued to cancel an attempt cannot execute one.
	operationExecute = "execute"
	// maximumCredentialBytes bounds what is read as a credential. The claim set
	// is fixed and small; anything larger is not a credential this format can
	// produce.
	maximumCredentialBytes = 8192
)

// taskBinding is what a credential binds. Every field is compared against the
// task the unit was handed: a credential is authority for one attempt of one
// task on one release, and a field that did not have to match would be a field
// an attacker could vary.
type taskBinding struct {
	Operation                string `json:"operation"`
	WorkspaceID              string `json:"workspaceId"`
	ProjectID                string `json:"projectId"`
	RunID                    string `json:"runId"`
	RootRunID                string `json:"rootRunId"`
	TaskID                   string `json:"taskId"`
	PhysicalAttemptID        string `json:"physicalAttemptId"`
	AttemptNumber            uint64 `json:"attemptNumber"`
	ExecutionGeneration      uint64 `json:"executionGeneration"`
	LeaseEpoch               uint64 `json:"leaseEpoch"`
	RuntimeUnitID            string `json:"runtimeUnitId"`
	RuntimeManifestDigest    string `json:"runtimeManifestDigest"`
	InvocationProtocolDigest string `json:"invocationProtocolDigest"`
}

// CredentialVerifier admits a presented task credential against the operator's
// trust root.
//
// The trust root is re-read on every admission rather than cached at start. A
// key is revoked, a snapshot passes its freshness bound, and a validity interval
// ends, all while a unit keeps serving; verifying once at startup would only
// prove the material was good when the process began.
type CredentialVerifier struct {
	path     string
	audience string

	lock sync.Mutex
}

// NewCredentialVerifier binds a unit's admission to its own audience and the
// operator's trust root.
//
// The audience is the unit's, taken from the manifest it was released with, and
// is never read from the token. A verifier that took the audience from the
// document it was verifying would accept every document for the audience it
// named itself.
func NewCredentialVerifier(trustRootPath, audience string) (*CredentialVerifier, error) {
	if trustRootPath == "" {
		return nil, fmt.Errorf("task credential: a trust root is required; a unit that cannot verify a credential must not accept one")
	}
	if audience == "" {
		return nil, fmt.Errorf("task credential: this unit's manifest names no workload audience to admit credentials for")
	}
	return &CredentialVerifier{path: trustRootPath, audience: audience}, nil
}

// VerifierFromEnvironment reads the trust root location this unit was deployed
// with. A unit with no trust root refuses to start: it could not tell a task
// Agent Service dispatched from one anybody sent it.
func VerifierFromEnvironment(manifest schema.AgentRuntimeManifest) (*CredentialVerifier, error) {
	path := os.Getenv("ANVILKIT_TASK_CREDENTIAL_TRUST_ROOT")
	if path == "" {
		return nil, fmt.Errorf("ANVILKIT_TASK_CREDENTIAL_TRUST_ROOT is required: a runtime unit will not admit unverifiable tasks")
	}
	return NewCredentialVerifier(path, manifest.Workload.Audience)
}

// Verify proves a presented credential and returns what it binds.
//
// Nothing about the token is believed before its signature verifies. The
// claimed key identity selects a candidate key from the operator's trust root,
// and only a signature that verifies under that key makes any claim readable.
func (v *CredentialVerifier) Verify(token string, now time.Time) (taskBinding, error) {
	if len(token) == 0 || len(token) > maximumCredentialBytes {
		return taskBinding{}, fmt.Errorf("task credential: the credential is empty or unbounded")
	}
	header, payload, signature, signingInput, err := splitCompactJWS(token)
	if err != nil {
		return taskBinding{}, err
	}
	var joseHeader struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
		Type      string `json:"typ"`
	}
	if err := decodeStrictJSON(header, &joseHeader); err != nil {
		return taskBinding{}, fmt.Errorf("task credential: decode header: %w", err)
	}
	// The algorithm and type are fixed by the format. Reading them from the
	// token and then honouring whatever they said is how a verifier ends up
	// accepting "alg":"none"; here they must equal the only values this format
	// has, and the key is resolved for that algorithm and no other.
	if joseHeader.Algorithm != credentialAlgorithm || joseHeader.Type != credentialType {
		return taskBinding{}, fmt.Errorf("task credential: the credential is not an %s %s", credentialAlgorithm, credentialType)
	}
	if joseHeader.KeyID == "" {
		return taskBinding{}, fmt.Errorf("task credential: the credential names no signing key")
	}

	v.lock.Lock()
	raw, err := os.ReadFile(v.path)
	v.lock.Unlock()
	if err != nil {
		return taskBinding{}, fmt.Errorf("task credential: read trust root: %w", err)
	}
	root, skew, err := parseTrustRoot(raw, now)
	if err != nil {
		return taskBinding{}, err
	}
	key, err := resolveTrustKey(root, joseHeader.KeyID, credentialIssuer, v.audience, credentialAlgorithm, now, skew)
	if err != nil {
		return taskBinding{}, err
	}
	if !ed25519.Verify(key, []byte(signingInput), signature) {
		return taskBinding{}, fmt.Errorf("task credential: the credential signature does not verify")
	}

	var claims struct {
		Issuer    string      `json:"iss"`
		Audience  string      `json:"aud"`
		Subject   string      `json:"sub"`
		TokenID   string      `json:"jti"`
		IssuedAt  int64       `json:"iat"`
		NotBefore int64       `json:"nbf"`
		Expiry    int64       `json:"exp"`
		Binding   taskBinding `json:"urn:anvilkit:claim:task-binding"`
	}
	if err := decodeStrictJSON(payload, &claims); err != nil {
		return taskBinding{}, fmt.Errorf("task credential: decode claims: %w", err)
	}
	if claims.Issuer != credentialIssuer {
		return taskBinding{}, fmt.Errorf("task credential: the credential was not issued by the control plane this unit serves")
	}
	if claims.Audience != v.audience {
		return taskBinding{}, fmt.Errorf("task credential: the credential was issued to another release")
	}
	if claims.Subject != "urn:anvilkit:attempt:"+claims.Binding.PhysicalAttemptID || claims.TokenID != claims.Binding.PhysicalAttemptID {
		return taskBinding{}, fmt.Errorf("task credential: the credential subject is not the attempt it binds")
	}
	if claims.IssuedAt <= 0 || claims.NotBefore <= 0 || claims.Expiry <= claims.NotBefore {
		return taskBinding{}, fmt.Errorf("task credential: the credential validity interval is malformed")
	}
	notBefore, expiry := time.Unix(claims.NotBefore, 0).UTC(), time.Unix(claims.Expiry, 0).UTC()
	if now.Add(skew).Before(notBefore) {
		return taskBinding{}, fmt.Errorf("task credential: the credential is not yet valid")
	}
	if !now.Add(-skew).Before(expiry) {
		return taskBinding{}, fmt.Errorf("task credential: the credential has expired")
	}
	return claims.Binding, nil
}

// bindsTask reports why a verified credential is not authority for the task it
// arrived with, or the empty string when it is.
//
// A verified signature proves only that Agent Service issued the token. It says
// nothing about whether the token was issued for the work now being asked for,
// which is why the two checks are separate: a valid credential for another
// attempt is exactly what a replay looks like.
func bindsTask(binding taskBinding, task schema.AgentTask, audience string) string {
	if binding.Operation != operationExecute {
		return "the credential does not authorize execution"
	}
	if task.AuthorizationAudience != audience {
		return "the task and the credential name different audiences"
	}
	if binding.WorkspaceID == "" || binding.ProjectID == "" {
		return "the credential names no tenant boundary to execute inside"
	}
	for _, comparison := range []struct{ credential, task string }{
		{binding.RunID, string(task.RunId)},
		{binding.RootRunID, string(task.RootRunId)},
		{binding.TaskID, string(task.TaskId)},
		{binding.PhysicalAttemptID, string(task.PhysicalAttemptId)},
		{binding.RuntimeUnitID, string(task.RuntimeBinding.RuntimeUnitId)},
		{binding.RuntimeManifestDigest, string(task.RuntimeBinding.RuntimeManifestDigest)},
		{binding.InvocationProtocolDigest, string(task.RuntimeBinding.InvocationProtocolDigest)},
	} {
		if comparison.credential != comparison.task {
			return "the credential was issued for a different attempt"
		}
	}
	for _, comparison := range []struct {
		credential uint64
		task       int
	}{
		{binding.AttemptNumber, task.AttemptNumber},
		{binding.ExecutionGeneration, task.ExecutionGeneration},
		{binding.LeaseEpoch, task.LeaseEpoch},
	} {
		if comparison.task < 0 || comparison.credential != uint64(comparison.task) {
			return "the credential was issued for a different attempt"
		}
	}
	return ""
}

// splitCompactJWS takes a compact JWS apart without believing any of it. The
// signing input is returned as it arrived: a verifier that re-encoded the header
// and payload would prove a signature over bytes it built rather than over the
// bytes it received.
func splitCompactJWS(token string) (header, payload, signature []byte, signingInput string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, nil, nil, "", fmt.Errorf("task credential: the credential is not a compact JWS")
	}
	if header, err = base64.RawURLEncoding.DecodeString(parts[0]); err != nil {
		return nil, nil, nil, "", fmt.Errorf("task credential: the credential header is not base64url")
	}
	if payload, err = base64.RawURLEncoding.DecodeString(parts[1]); err != nil {
		return nil, nil, nil, "", fmt.Errorf("task credential: the credential claims are not base64url")
	}
	if signature, err = base64.RawURLEncoding.DecodeString(parts[2]); err != nil || len(signature) != ed25519.SignatureSize {
		return nil, nil, nil, "", fmt.Errorf("task credential: the credential signature is malformed")
	}
	return header, payload, signature, parts[0] + "." + parts[1], nil
}
