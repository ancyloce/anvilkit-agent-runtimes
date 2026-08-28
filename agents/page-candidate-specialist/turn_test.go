package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-runtimes/runtime"
)

// A successful Specialist turn has to end in something a reviewer can resolve:
// a candidate the control plane recorded, whose digest is about the bytes that
// were sent, pinned to inputs the run actually holds. These prove that, and
// then prove that nothing a model proposes can move any of it.

func compose(t *testing.T, plane *governedPlane, task schema.AgentTask) (schema.AgentRuntimeResultTurnDecision, *runtime.Session, error) {
	t.Helper()
	session := plane.session(t)
	decision, err := (&specialistTurn{}).Decide(context.Background(), task, session)
	return decision, session, err
}

func composingPlane(t *testing.T) *governedPlane {
	t.Helper()
	return planeServing(t, map[string]string{"composition": compositionJSON})
}

// submittedCandidate reads back the exact document the turn submitted, decoded
// through the generated canonical bindings. Decoding is the contract check:
// the bindings enforce every required member, pattern, and bound the canonical
// PageCandidate schema declares, so a document that decodes is one the contract
// admits.
func submittedCandidate(t *testing.T, plane *governedPlane) schema.PageCandidate {
	t.Helper()
	body := plane.lastSubmission(t)
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var candidate schema.PageCandidate
	if err := decoder.Decode(&candidate); err != nil {
		t.Fatalf("the submitted candidate is not a canonical PageCandidate: %v\n%s", err, body)
	}
	return candidate
}

func TestASuccessfulTurnEndsInARecordedVerifiableArtifact(t *testing.T) {
	plane := composingPlane(t)
	decision, session, err := compose(t, plane, specialistTask(nil))
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Decision != schema.AgentRuntimeResultTurnDecisionDecisionFinal {
		t.Fatalf("decision = %q", decision.Decision)
	}
	if len(decision.ArtifactOutputs) != 1 {
		t.Fatalf("a final decision must name exactly one candidate: %+v", decision.ArtifactOutputs)
	}
	reference := decision.ArtifactOutputs[0]
	body := plane.lastSubmission(t)
	// The reference is the control plane's, and it is about the bytes that were
	// submitted. That is what makes it verifiable rather than asserted: whoever
	// reads it back can recompute this digest.
	if reference.ArtifactId != "artifact.candidate.0001" || string(reference.Digest) != sha256Of(body) {
		t.Fatalf("reference = %+v", reference)
	}
	if reference.SizeBytes != len(body) {
		t.Fatalf("reference size = %d, submitted %d bytes", reference.SizeBytes, len(body))
	}
	// One model decision, one controlled write, and the tokens the gateway
	// metered for the attempt.
	usage := session.Usage()
	if usage.ModelCalls != 1 || usage.ToolCalls != 1 || usage.InputTokens != 11 || usage.CostAmount != "0.002" {
		t.Fatalf("usage = %+v", usage)
	}
}

func TestTheCandidatePinsTheInputsThatProducedIt(t *testing.T) {
	plane := composingPlane(t)
	if _, _, err := compose(t, plane, specialistTask(nil)); err != nil {
		t.Fatalf("decide: %v", err)
	}
	candidate := submittedCandidate(t, plane)

	if candidate.Target.TargetId != "page.0001" || candidate.BaseRevision != "revision.0001" {
		t.Fatalf("target = %+v base = %q", candidate.Target, candidate.BaseRevision)
	}
	// Three digests come from the supplied context and two from the task
	// itself. Reading the definition and BOM from anywhere but the dispatch
	// would let a candidate claim contracts the run is not pinned to.
	if string(candidate.Digests.TargetDigest) != "sha256:"+strings.Repeat("5", 64) ||
		string(candidate.Digests.CatalogDigest) != "sha256:"+strings.Repeat("6", 64) ||
		string(candidate.Digests.PolicyDigest) != "sha256:"+strings.Repeat("7", 64) ||
		string(candidate.Digests.DefinitionDigest) != "sha256:"+strings.Repeat("1", 64) ||
		string(candidate.Digests.ContractBomDigest) != "sha256:"+strings.Repeat("2", 64) {
		t.Fatalf("digests = %+v", candidate.Digests)
	}
	// The accepted preview is the task's own pinned input, not one the
	// Specialist named.
	if candidate.Preview.TaskId != "task.preview.0001" || candidate.Preview.ResultArtifact.ArtifactId != "artifact.preview.0001" {
		t.Fatalf("preview = %+v", candidate.Preview)
	}
	// The candidate records the model decisions that went into it, so a
	// reviewer can resolve every one of them.
	if len(candidate.References.ModelInvocations) != 1 || candidate.References.ModelInvocations[0] != "invocation.0001" {
		t.Fatalf("model invocations = %+v", candidate.References.ModelInvocations)
	}
	// A Specialist executes no tools, creates no child runs, records no
	// evidence of its own, and runs no validator whose receipt it could carry.
	if len(candidate.References.ToolInvocations) != 0 || len(candidate.References.Delegations) != 0 ||
		len(candidate.References.Evidence) != 0 || len(candidate.ValidationReceipts) != 0 {
		t.Fatalf("a Specialist claimed work it did not do: %+v", candidate.References)
	}
	if candidate.Generation.Summary != "refreshed the hero" ||
		len(candidate.Generation.Assumptions) != 1 {
		t.Fatalf("generation = %+v", candidate.Generation)
	}
}

func TestTheCandidatesOwnDigestsAreAboutTheDocumentsTheyName(t *testing.T) {
	plane := composingPlane(t)
	if _, _, err := compose(t, plane, specialistTask(nil)); err != nil {
		t.Fatalf("decide: %v", err)
	}
	candidate := submittedCandidate(t, plane)

	// pageData names the composed page document by content digest. Recomputing
	// it here from the same inputs is what proves the pin is about the page the
	// candidate describes rather than a value carried along.
	supplied, err := readConstraints(runtime.ReadBrief(specialistTask(nil)))
	if err != nil {
		t.Fatalf("read constraints: %v", err)
	}
	var proposal composition
	if err := json.Unmarshal([]byte(compositionJSON), &proposal); err != nil {
		t.Fatalf("read composition: %v", err)
	}
	document, _, err := composePage(supplied, proposal)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	expected, err := runtime.PinDocument(document, "application/json")
	if err != nil {
		t.Fatalf("pin document: %v", err)
	}
	if candidate.PageData != expected {
		t.Fatalf("pageData = %+v, want %+v", candidate.PageData, expected)
	}
	if candidate.PageData.SizeBytes == 0 {
		t.Fatal("the candidate pins an empty page document")
	}

	// The candidate's own digest covers everything else about it, and is taken
	// over the document without itself.
	self, err := runtime.SelfDigest(candidate, "candidateDigest")
	if err != nil {
		t.Fatalf("self digest: %v", err)
	}
	if string(candidate.CandidateDigest) != self {
		t.Fatalf("candidateDigest = %q, want %q", candidate.CandidateDigest, self)
	}
}

func TestTheSameTaskAndTheSameProposalProduceTheSameBytes(t *testing.T) {
	first := composingPlane(t)
	if _, _, err := compose(t, first, specialistTask(nil)); err != nil {
		t.Fatalf("first: %v", err)
	}
	second := composingPlane(t)
	if _, _, err := compose(t, second, specialistTask(nil)); err != nil {
		t.Fatalf("second: %v", err)
	}
	// A replacement attempt that repeats the same work must produce the same
	// document, or the control plane sees two candidates where there is one.
	if string(first.lastSubmission(t)) != string(second.lastSubmission(t)) {
		t.Fatalf("two runs of the same work produced different documents:\n%s\n%s",
			first.lastSubmission(t), second.lastSubmission(t))
	}
}

func TestSuppliedDefaultsFillWhatTheProposalDidNotName(t *testing.T) {
	plane := composingPlane(t)
	if _, _, err := compose(t, plane, specialistTask(nil)); err != nil {
		t.Fatalf("decide: %v", err)
	}
	candidate := submittedCandidate(t, plane)
	supplied, err := readConstraints(runtime.ReadBrief(specialistTask(nil)))
	if err != nil {
		t.Fatalf("read constraints: %v", err)
	}
	var proposal composition
	if err := json.Unmarshal([]byte(compositionJSON), &proposal); err != nil {
		t.Fatalf("read composition: %v", err)
	}
	document, warnings, err := composePage(supplied, proposal)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	props := document.Content[0].Props
	// Merge order is fixed: default data, then default properties, then the
	// proposal. The model filled the title over the default; the subtitle and
	// the configuration came from the brief.
	if props["title"] != "Ship faster" {
		t.Fatalf("title = %v, the proposal did not override the default", props["title"])
	}
	if props["subtitle"] != "a default subtitle" || props["align"] != "center" || props["columns"] != float64(2) {
		t.Fatalf("defaults were not applied: %+v", props)
	}
	// Identity is derived, never proposed: two blocks with one identity is a
	// page nobody can review.
	if props["id"] != "hero-0" {
		t.Fatalf("id = %v", props["id"])
	}
	if !hasWarning(warnings, "DEFAULTS_APPLIED") || !hasWarning(candidate.Warnings, "DEFAULTS_APPLIED") {
		t.Fatalf("a reviewer was not told defaults were applied: %+v", candidate.Warnings)
	}
}

func TestModelOutputCannotProposeContentTheSchemaDoesNotDeclare(t *testing.T) {
	for name, testCase := range map[string]struct {
		composition string
		want        runtime.ProposalReason
	}{
		"a component the catalog does not declare": {
			`{"sections":[{"component":"Carousel","properties":{}}],"summary":"s","assumptions":[]}`,
			runtime.ProposalOutsideSchema,
		},
		"a property no component declares": {
			`{"sections":[{"component":"Hero","properties":{"title":"t","onClick":"alert(1)"}}],"summary":"s","assumptions":[]}`,
			runtime.ProposalOutsideSchema,
		},
		"a string past the declared bound": {
			`{"sections":[{"component":"Hero","properties":{"title":"` + strings.Repeat("x", 41) + `"}}],"summary":"s","assumptions":[]}`,
			runtime.ProposalOutsideSchema,
		},
		"a value outside a declared enum": {
			`{"sections":[{"component":"Hero","properties":{"title":"t","align":"diagonal"}}],"summary":"s","assumptions":[]}`,
			runtime.ProposalOutsideSchema,
		},
		"a number past the declared maximum": {
			`{"sections":[{"component":"Hero","properties":{"title":"t","columns":9}}],"summary":"s","assumptions":[]}`,
			runtime.ProposalOutsideSchema,
		},
		"a value of the wrong declared type": {
			`{"sections":[{"component":"Hero","properties":{"title":"t","boxed":"yes"}}],"summary":"s","assumptions":[]}`,
			runtime.ProposalOutsideSchema,
		},
		"a null where a value was declared": {
			`{"sections":[{"component":"Hero","properties":{"title":null}}],"summary":"s","assumptions":[]}`,
			runtime.ProposalOutsideSchema,
		},
	} {
		t.Run(name, func(t *testing.T) {
			plane := planeServing(t, map[string]string{"composition": testCase.composition})
			_, _, err := compose(t, plane, specialistTask(nil))
			var refused *runtime.ProposalError
			if !errors.As(err, &refused) || refused.Reason != testCase.want {
				t.Fatalf("reason = %v, want %q", err, testCase.want)
			}
			// A refused proposal is never partly written: nothing reached the
			// controlled artifact interface.
			if len(plane.submitted) != 0 {
				t.Fatal("a refused composition was still submitted")
			}
		})
	}
}

func TestAnOverlongValueIsRefusedRatherThanTruncated(t *testing.T) {
	overlong := strings.Repeat("x", 41)
	plane := planeServing(t, map[string]string{
		"composition": `{"sections":[{"component":"Hero","properties":{"title":"` + overlong + `"}}],"summary":"s","assumptions":[]}`,
	})
	_, _, err := compose(t, plane, specialistTask(nil))
	if err == nil {
		t.Fatal("an overlong value was accepted")
	}
	// Truncating would make the runtime the author of the part it changed, and
	// the candidate would attribute to the model content the model did not
	// propose.
	if len(plane.submitted) != 0 {
		t.Fatal("an overlong value was truncated and submitted")
	}
}

func TestModelOutputCannotProposeContentTheConstraintsDoNotAdmit(t *testing.T) {
	for name, proposal := range map[string]string{
		"more sections than the style allows": `{"sections":[` +
			`{"component":"Hero","properties":{"title":"a"}},` +
			`{"component":"Hero","properties":{"title":"b"}},` +
			`{"component":"Hero","properties":{"title":"c"}},` +
			`{"component":"Hero","properties":{"title":"d"}}],"summary":"s","assumptions":[]}`,
		"an effect the constraints do not allow": `{"sections":[{"component":"Hero","properties":{"title":"a"},` +
			`"animation":{"effect":"explode","durationMilliseconds":100}}],"summary":"s","assumptions":[]}`,
		"a duration past the constrained maximum": `{"sections":[{"component":"Hero","properties":{"title":"a"},` +
			`"animation":{"effect":"fade","durationMilliseconds":5000}}],"summary":"s","assumptions":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			plane := planeServing(t, map[string]string{"composition": proposal})
			_, _, err := compose(t, plane, specialistTask(nil))
			var refused *runtime.ProposalError
			if !errors.As(err, &refused) || refused.Reason != runtime.ProposalOutsideConstraints {
				t.Fatalf("reason = %v", err)
			}
		})
	}
}

func TestReducedMotionRemovesEveryEffectAndSaysSo(t *testing.T) {
	task := specialistTask(map[string]string{
		"page.animationConstraints": `{"allowedEffects":["none","fade"],"maximumDurationMilliseconds":600,"reducedMotion":true}`,
	})
	plane := composingPlane(t)
	if _, _, err := compose(t, plane, task); err != nil {
		t.Fatalf("decide: %v", err)
	}
	candidate := submittedCandidate(t, plane)
	// Reduced motion is a constraint, not a refusal: the page is still the page
	// the model proposed, with the motion the constraints removed. A reviewer
	// looking at a still page should see why rather than conclude the agent
	// chose stillness.
	if !hasWarning(candidate.Warnings, "REDUCED_MOTION_APPLIED") {
		t.Fatalf("warnings = %+v", candidate.Warnings)
	}
	supplied, err := readConstraints(runtime.ReadBrief(task))
	if err != nil {
		t.Fatalf("read constraints: %v", err)
	}
	var proposal composition
	if err := json.Unmarshal([]byte(compositionJSON), &proposal); err != nil {
		t.Fatalf("read composition: %v", err)
	}
	document, _, err := composePage(supplied, proposal)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	motion, _ := document.Content[0].Props["animation"].(map[string]any)
	if motion["effect"] != "none" || motion["durationMilliseconds"] != 0 {
		t.Fatalf("motion survived reduced motion: %+v", motion)
	}
}

func TestModelOutputCannotExpandAuthorityThroughAnExtraMember(t *testing.T) {
	for name, proposal := range map[string]string{
		"a budget":                     `{"sections":[{"component":"Hero","properties":{"title":"a"}}],"summary":"s","assumptions":[],"budget":{"tokens":1000000}}`,
		"a credential":                 `{"sections":[{"component":"Hero","credential":"key","properties":{"title":"a"}}],"summary":"s","assumptions":[]}`,
		"a delegation":                 `{"sections":[{"component":"Hero","properties":{"title":"a"}}],"summary":"s","assumptions":[],"delegate":"definition.anything"}`,
		"an artifact it did not write": `{"sections":[{"component":"Hero","properties":{"title":"a"}}],"summary":"s","assumptions":[],"artifactOutputs":[{"artifactId":"artifact.elsewhere"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			plane := planeServing(t, map[string]string{"composition": proposal})
			_, _, err := compose(t, plane, specialistTask(nil))
			var refused *runtime.ProposalError
			if !errors.As(err, &refused) || refused.Reason != runtime.ProposalExpandsAuthority {
				t.Fatalf("reason = %v", err)
			}
		})
	}
}

func TestAProposalWithNothingToCompose(t *testing.T) {
	for name, proposal := range map[string]string{
		"no sections": `{"sections":[],"summary":"s","assumptions":[]}`,
		"no summary":  `{"sections":[{"component":"Hero","properties":{"title":"a"}}],"summary":"  ","assumptions":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			plane := planeServing(t, map[string]string{"composition": proposal})
			_, _, err := compose(t, plane, specialistTask(nil))
			var refused *runtime.ProposalError
			if !errors.As(err, &refused) || refused.Reason != runtime.ProposalIncomplete {
				t.Fatalf("reason = %v", err)
			}
		})
	}
}

func TestARequiredPropertyNothingSuppliedIsRefused(t *testing.T) {
	// With no default data for Hero, nothing supplies its declared-required
	// title, and the proposal does not either. A page missing a property the
	// catalog requires is not a page the catalog admits.
	task := specialistTask(map[string]string{"page.defaultData": `{}`})
	plane := planeServing(t, map[string]string{
		"composition": `{"sections":[{"component":"Hero","properties":{"align":"left"}}],"summary":"s","assumptions":[]}`,
	})
	_, _, err := compose(t, plane, task)
	var refused *runtime.ProposalError
	if !errors.As(err, &refused) || refused.Reason != runtime.ProposalIncomplete {
		t.Fatalf("reason = %v", err)
	}
	if len(plane.submitted) != 0 {
		t.Fatal("an incomplete page was submitted")
	}
}

func TestADispatchMissingItsPinsProducesNothing(t *testing.T) {
	for _, key := range []string{
		"candidate.target.id",
		"candidate.baseRevision",
		"candidate.digests.catalog",
		"candidate.preview.taskId",
		"candidate.preview.resultArtifact.digest",
		"page.componentSchema",
		"page.styleConstraints",
		"page.animationConstraints",
		"page.defaultProperties",
		"model.policyDigest",
	} {
		t.Run(key, func(t *testing.T) {
			plane := composingPlane(t)
			_, _, err := compose(t, plane, specialistTask(map[string]string{key: ""}))
			var missing *runtime.ContextError
			if !errors.As(err, &missing) {
				t.Fatalf("expected a context refusal for %q, got %v", key, err)
			}
			if len(plane.submitted) != 0 {
				t.Fatal("an incomplete dispatch still produced a candidate")
			}
		})
	}
}

func TestAPreviewTheTaskDidNotPinIsNotAttestedTo(t *testing.T) {
	// A preview a Specialist could name freely would be a render nobody
	// performed, attested to by the candidate that names it.
	task := specialistTask(nil, schema.SharedPrimitivesArtifactReference{
		ArtifactId: "artifact.somethingelse.0001",
		Digest:     schema.SharedPrimitivesDigest("sha256:" + strings.Repeat("b", 64)),
		MediaType:  "application/json",
		SizeBytes:  16,
	})
	plane := composingPlane(t)
	_, _, err := compose(t, plane, task)
	var missing *runtime.ContextError
	if !errors.As(err, &missing) {
		t.Fatalf("expected a context refusal, got %v", err)
	}
}

func TestASpecialistCannotDelegate(t *testing.T) {
	plane := composingPlane(t)
	_, _, err := compose(t, plane, specialistTask(map[string]string{"delegate": "definition.platform.page-change-manager"}))
	var boundary *runtime.BoundaryError
	if !errors.As(err, &boundary) || boundary.Refusal != runtime.RefusePeerCall {
		t.Fatalf("a Specialist delegated: %v", err)
	}
	if plane.asked != 0 {
		t.Fatal("a refused delegation still spent a model invocation")
	}
}

func TestACandidateThatCouldNotBeRecordedIsNotClaimedAsProduced(t *testing.T) {
	plane := composingPlane(t)
	plane.refuseWith = 503
	_, _, err := compose(t, plane, specialistTask(nil))
	var write runtime.ArtifactWriteError
	if !errors.As(err, &write) {
		t.Fatalf("expected an artifact write failure, got %v", err)
	}
	// The turn does not return a final decision naming a reference the control
	// plane never recorded. A dangling reference is exactly what makes a final
	// decision unverifiable.
}

func hasWarning(warnings []schema.PageCandidateWarningsElem, code string) bool {
	for _, warning := range warnings {
		if warning.Code == code {
			return true
		}
	}
	return false
}
