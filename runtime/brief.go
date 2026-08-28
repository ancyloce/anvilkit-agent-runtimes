package runtime

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
)

// Brief is the bounded, task-scoped context Agent Service supplies with a task.
//
// An Agent compiles only this. It does not read a database, does not call a
// context service, and does not carry anything from a previous turn: whatever
// the control plane decided this attempt may see, it put in the task, and the
// task is the whole of it. That is what makes an attempt reproducible from its
// own dispatched document.
//
// Values are bounded strings because the canonical AgentTask bounds them.
// Anything longer than one bound arrives as an indexed continuation —
// `page.componentSchema.0`, `.1`, and so on — which keeps a real document
// expressible without any single value escaping the bound the contract sets.
type Brief struct {
	values map[string]string
	inputs []schema.SharedPrimitivesArtifactReference
}

// ReadBrief reads the supplied context of one task.
func ReadBrief(task schema.AgentTask) *Brief {
	values := make(map[string]string, len(task.Parameters))
	for key, value := range task.Parameters {
		values[key] = value
	}
	return &Brief{values: values, inputs: task.ArtifactInputs}
}

// ContextError reports that the supplied context does not carry something the
// turn requires.
//
// It names the key and never the value: a key is vocabulary the control plane
// and the runtime already share, whereas a value can be anything the task put
// there. Naming the key is what lets an operator fix the dispatch; echoing the
// value would put task content into a diagnostic that travels.
type ContextError struct{ Key string }

func (e *ContextError) Error() string {
	return "agent runtime context: the task supplies no usable " + e.Key
}

// Value reads one exact key.
func (b *Brief) Value(key string) (string, bool) {
	value, present := b.values[key]
	return value, present
}

// Joined reads one key, following indexed continuations when the value did not
// fit one bound. `key` alone wins if present; otherwise `key.0`, `key.1`, … are
// concatenated in index order and stop at the first gap, so a truncated
// dispatch produces a short document rather than a document with a hole in it.
func (b *Brief) Joined(key string) (string, bool) {
	if value, present := b.values[key]; present {
		return value, true
	}
	prefix := key + "."
	indexes := make([]int, 0, len(b.values))
	for candidate := range b.values {
		if !strings.HasPrefix(candidate, prefix) {
			continue
		}
		index, err := strconv.Atoi(candidate[len(prefix):])
		if err != nil || index < 0 {
			continue
		}
		indexes = append(indexes, index)
	}
	if len(indexes) == 0 {
		return "", false
	}
	sort.Ints(indexes)
	var builder strings.Builder
	for position, index := range indexes {
		if index != position {
			// A gap means the dispatch lost a chunk. Stopping here rather than
			// splicing the remaining chunks together is the point: concatenating
			// across a gap would produce a document that parses and is wrong.
			break
		}
		builder.WriteString(b.values[prefix+strconv.Itoa(index)])
	}
	if builder.Len() == 0 {
		return "", false
	}
	return builder.String(), true
}

// Required reads one key that the turn cannot proceed without.
func (b *Brief) Required(key string) (string, error) {
	value, present := b.Joined(key)
	if !present || strings.TrimSpace(value) == "" {
		return "", &ContextError{Key: key}
	}
	return value, nil
}

// Digest reads one required key that must be a canonical digest.
func (b *Brief) Digest(key string) (schema.SharedPrimitivesDigest, error) {
	value, err := b.Required(key)
	if err != nil {
		return "", err
	}
	if !digestPattern.MatchString(value) {
		return "", &ContextError{Key: key}
	}
	return schema.SharedPrimitivesDigest(value), nil
}

// Identifier reads one required key that must be a canonical opaque identity.
func (b *Brief) Identifier(key string) (schema.SharedPrimitivesOpaqueId, error) {
	value, err := b.Required(key)
	if err != nil {
		return "", err
	}
	if !opaqueIDPattern.MatchString(value) {
		return "", &ContextError{Key: key}
	}
	return schema.SharedPrimitivesOpaqueId(value), nil
}

// Number reads one required key that must be a non-negative bounded integer.
func (b *Brief) Number(key string) (int, error) {
	value, err := b.Required(key)
	if err != nil {
		return 0, err
	}
	number, convertErr := strconv.Atoi(value)
	if convertErr != nil || number < 0 {
		return 0, &ContextError{Key: key}
	}
	return number, nil
}

// Document reads one required key that must be a JSON document, and decodes it
// into target. A supplied constraint that is not a document is not a constraint
// this turn can honour, and guessing at it would let malformed dispatch become
// invented page content.
func (b *Brief) Document(key string, target any) error {
	value, err := b.Required(key)
	if err != nil {
		return err
	}
	if decodeErr := json.Unmarshal([]byte(value), target); decodeErr != nil {
		return &ContextError{Key: key}
	}
	return nil
}

// ArtifactInput resolves one of the task's pinned artifact inputs by identity.
// A runtime never reaches for an artifact the task did not name.
func (b *Brief) ArtifactInput(artifactID string) (schema.SharedPrimitivesArtifactReference, bool) {
	for _, input := range b.inputs {
		if string(input.ArtifactId) == artifactID {
			return input, true
		}
	}
	return schema.SharedPrimitivesArtifactReference{}, false
}

// ArtifactReference reads one artifact reference the context pins under a key
// prefix: `<prefix>.artifactId`, `.digest`, `.mediaType`, and `.sizeBytes`.
func (b *Brief) ArtifactReference(prefix string) (schema.SharedPrimitivesArtifactReference, error) {
	artifactID, err := b.Identifier(prefix + ".artifactId")
	if err != nil {
		return schema.SharedPrimitivesArtifactReference{}, err
	}
	digest, err := b.Digest(prefix + ".digest")
	if err != nil {
		return schema.SharedPrimitivesArtifactReference{}, err
	}
	mediaType, err := b.Required(prefix + ".mediaType")
	if err != nil {
		return schema.SharedPrimitivesArtifactReference{}, err
	}
	if !mediaTypePattern.MatchString(mediaType) {
		return schema.SharedPrimitivesArtifactReference{}, &ContextError{Key: prefix + ".mediaType"}
	}
	size, err := b.Number(prefix + ".sizeBytes")
	if err != nil {
		return schema.SharedPrimitivesArtifactReference{}, err
	}
	return schema.SharedPrimitivesArtifactReference{
		ArtifactId: artifactID,
		Digest:     digest,
		MediaType:  mediaType,
		SizeBytes:  size,
	}, nil
}

// GovernedPrompt reads the model inputs the control plane pinned for this
// attempt: the compiled context, the prompt the definition pins, and the model
// policy. A runtime supplies none of the three — it names what it was given.
func (b *Brief) GovernedPrompt(operation string) (Prompt, error) {
	contextDigest, err := b.Digest(keyModelContextDigest)
	if err != nil {
		return Prompt{}, err
	}
	promptDigest, err := b.Digest(keyModelPromptDigest)
	if err != nil {
		return Prompt{}, err
	}
	policyID, err := b.Identifier(keyModelPolicyID)
	if err != nil {
		return Prompt{}, err
	}
	policyVersion, err := b.Required(keyModelPolicyVersion)
	if err != nil {
		return Prompt{}, err
	}
	policyDigest, err := b.Digest(keyModelPolicyDigest)
	if err != nil {
		return Prompt{}, err
	}
	return Prompt{
		Operation:     operation,
		ContextDigest: string(contextDigest),
		PromptDigest:  string(promptDigest),
		ModelPolicy: schema.SharedPrimitivesPolicyReference{
			PolicyId: policyID,
			Version:  policyVersion,
			Digest:   policyDigest,
		},
	}, nil
}

// The governed context vocabulary both units read. These names are the
// runtime's half of the dispatch contract: Agent Service writes them into the
// task's parameters, and a unit reads exactly these and nothing else.
const (
	keyModelContextDigest = "model.contextDigest"
	keyModelPromptDigest  = "model.promptDigest"
	keyModelPolicyID      = "model.policyId"
	keyModelPolicyVersion = "model.policyVersion"
	keyModelPolicyDigest  = "model.policyDigest"
)

// boundedOutput reads one governed model output value, following the same
// indexed continuation convention the supplied context uses. Model output is
// bounded by the same map bound, and a composition longer than one value is
// read the same way a supplied constraint is.
func boundedOutput(output map[string]string, key string) (string, bool) {
	return (&Brief{values: output}).Joined(key)
}

var (
	// opaqueIDPattern and mediaTypePattern are the canonical shared-primitive
	// bounds for the values the supplied context carries. Checking them here
	// means a malformed dispatch is refused with a coded reason instead of
	// travelling into a document that will fail validation somewhere later.
	opaqueIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	mediaTypePattern = regexp.MustCompile(`^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$`)
)
