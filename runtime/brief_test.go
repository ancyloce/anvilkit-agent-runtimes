package runtime

import (
	"errors"
	"strings"
	"testing"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
)

// The supplied context is the whole of what an attempt may see. What these
// prove is that reading it is strict — a malformed dispatch is refused with a
// coded reason rather than travelling into a document — and that a value too
// long for one bound can still arrive intact.

func briefOf(values map[string]string, inputs ...schema.SharedPrimitivesArtifactReference) *Brief {
	task := testTask()
	task.Parameters = schema.SharedPrimitivesBoundedStringMap(values)
	task.ArtifactInputs = inputs
	return ReadBrief(task)
}

func TestAValueTooLongForOneBoundArrivesInIndexOrder(t *testing.T) {
	brief := briefOf(map[string]string{
		"page.componentSchema.1": `nents":[]}`,
		"page.componentSchema.0": `{"compo`,
		"page.componentSchema.2": ``,
	})
	// The canonical AgentTask bounds every parameter value. A document longer
	// than one bound arrives as indexed continuations, which keeps a real
	// schema expressible without any single value escaping the contract.
	value, present := brief.Joined("page.componentSchema")
	if !present || value != `{"components":[]}` {
		t.Fatalf("joined = %q present = %v", value, present)
	}
}

func TestAGapInAContinuationStopsRatherThanSplices(t *testing.T) {
	brief := briefOf(map[string]string{
		"page.componentSchema.0": `{"a":1`,
		"page.componentSchema.2": `,"c":3}`,
	})
	// Concatenating across a gap produces a document that might parse and is
	// wrong. Stopping short produces one that does not parse, which is what a
	// truncated dispatch should look like.
	value, _ := brief.Joined("page.componentSchema")
	if value != `{"a":1` {
		t.Fatalf("a gap was spliced over: %q", value)
	}
}

func TestAnExactKeyWinsOverContinuations(t *testing.T) {
	brief := briefOf(map[string]string{
		"key":   "whole",
		"key.0": "part",
	})
	if value, _ := brief.Joined("key"); value != "whole" {
		t.Fatalf("joined = %q", value)
	}
}

func TestMissingOrMalformedContextNamesTheKeyAndNotTheValue(t *testing.T) {
	brief := briefOf(map[string]string{
		"a.digest":     "not-a-digest",
		"a.identifier": "not a valid identity!",
		"a.number":     "-3",
		"a.document":   "{",
		"a.blank":      "   ",
	})
	for name, read := range map[string]func() error{
		"a missing key":      func() error { _, err := brief.Required("a.absent"); return err },
		"a blank value":      func() error { _, err := brief.Required("a.blank"); return err },
		"a malformed digest": func() error { _, err := brief.Digest("a.digest"); return err },
		"a malformed id":     func() error { _, err := brief.Identifier("a.identifier"); return err },
		"a negative number":  func() error { _, err := brief.Number("a.number"); return err },
		"a malformed document": func() error {
			var target map[string]any
			return brief.Document("a.document", &target)
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := read()
			var missing *ContextError
			if !errors.As(err, &missing) {
				t.Fatalf("expected a context error, got %v", err)
			}
			// The key is shared vocabulary an operator can act on; the value can
			// be anything the task put there, and a diagnostic that echoed it
			// would carry task content out of the process.
			if strings.Contains(err.Error(), "not-a-digest") || strings.Contains(err.Error(), "not a valid identity") {
				t.Fatalf("the refusal echoed the value: %q", err.Error())
			}
		})
	}
}

func TestAPinnedArtifactReferenceIsReadWholeOrNotAtAll(t *testing.T) {
	complete := map[string]string{
		"preview.artifactId": "artifact.preview.001",
		"preview.digest":     "sha256:" + strings.Repeat("a", 64),
		"preview.mediaType":  "application/json",
		"preview.sizeBytes":  "128",
	}
	reference, err := briefOf(complete).ArtifactReference("preview")
	if err != nil {
		t.Fatalf("read reference: %v", err)
	}
	if reference.ArtifactId != "artifact.preview.001" || reference.SizeBytes != 128 {
		t.Fatalf("reference = %+v", reference)
	}
	for missing := range complete {
		partial := map[string]string{}
		for key, value := range complete {
			if key != missing {
				partial[key] = value
			}
		}
		if _, err := briefOf(partial).ArtifactReference("preview"); err == nil {
			t.Fatalf("a reference missing %q was read", missing)
		}
	}
}

func TestOnlyArtifactsTheTaskPinnedCanBeResolved(t *testing.T) {
	pinned := schema.SharedPrimitivesArtifactReference{
		ArtifactId: "artifact.preview.001",
		Digest:     schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("a", 64)),
		MediaType:  "application/json",
		SizeBytes:  128,
	}
	brief := briefOf(nil, pinned)
	if _, present := brief.ArtifactInput("artifact.preview.001"); !present {
		t.Fatal("a pinned input could not be resolved")
	}
	// A runtime never reaches for an artifact the task did not name.
	if _, present := brief.ArtifactInput("artifact.elsewhere.001"); present {
		t.Fatal("an artifact the task did not pin was resolved")
	}
}

func TestTheGovernedPromptIsReadWholeOrNotAtAll(t *testing.T) {
	complete := map[string]string{
		keyModelContextDigest: "sha256:" + strings.Repeat("c", 64),
		keyModelPromptDigest:  "sha256:" + strings.Repeat("d", 64),
		keyModelPolicyID:      "policy.model.default",
		keyModelPolicyVersion: "v1",
		keyModelPolicyDigest:  "sha256:" + strings.Repeat("e", 64),
	}
	prompt, err := briefOf(complete).GovernedPrompt("model.plan")
	if err != nil {
		t.Fatalf("read prompt: %v", err)
	}
	if prompt.Operation != "model.plan" || prompt.ModelPolicy.PolicyId != "policy.model.default" {
		t.Fatalf("prompt = %+v", prompt)
	}
	// A runtime supplies none of these. A dispatch missing any one of them
	// would have the runtime choosing the context, the prompt, or the policy.
	for missing := range complete {
		partial := map[string]string{}
		for key, value := range complete {
			if key != missing {
				partial[key] = value
			}
		}
		if _, err := briefOf(partial).GovernedPrompt("model.plan"); err == nil {
			t.Fatalf("a prompt missing %q was read", missing)
		}
	}
}
