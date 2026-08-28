package main

import (
	"context"
	"strings"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-runtimes/runtime"
)

// specialistTurn resolves one Page Candidate Specialist turn.
//
// It produces the one thing a page-change run finally reviews: a schema-valid
// PageCandidate pinned to the exact inputs that produced it. It cannot delegate
// — a Specialist that could delegate would be a Manager — and it cannot
// finalize, approve, or commit what it produced: the candidate is a proposal,
// written through the controlled artifact interface so the reference it returns
// is one the control plane recorded rather than one this process asserted.
type specialistTurn struct{}

const (
	// The supplied context keys that pin a candidate to its run. None of them
	// is derivable inside a runtime: the target, the revision the change is
	// against, the digests a reviewer resolves the same bytes through, and the
	// preview that was accepted are all facts the control plane holds. A
	// Specialist that invented any of them would be attesting to provenance it
	// has no knowledge of.
	keyTargetType     = "candidate.target.type"
	keyTargetID       = "candidate.target.id"
	keyWorkspaceID    = "candidate.target.workspaceId"
	keyProjectID      = "candidate.target.projectId"
	keyBaseRevision   = "candidate.baseRevision"
	keyTargetDigest   = "candidate.digests.target"
	keyCatalogDigest  = "candidate.digests.catalog"
	keyPolicyDigest   = "candidate.digests.policy"
	keyPreviewTaskID  = "candidate.preview.taskId"
	keyPreviewArtifac = "candidate.preview.resultArtifact"

	// pageDocumentMediaType is what a canonical Puck Data document is.
	pageDocumentMediaType = "application/json"

	// maximumAssumptions and maximumAssumptionBytes are the bounds the
	// canonical candidate records for declared assumptions.
	maximumAssumptions     = 32
	maximumAssumptionBytes = 512
	maximumSummaryBytes    = 2048
)

func (t *specialistTurn) Decide(
	ctx context.Context,
	task schema.AgentTask,
	session *runtime.Session,
) (schema.AgentRuntimeResultTurnDecision, error) {
	brief := runtime.ReadBrief(task)

	// A Specialist is a bounded reasoning unit. Delegation is the Manager's,
	// and only through Agent Service.
	if _, forbidden := brief.Value("delegate"); forbidden {
		return schema.AgentRuntimeResultTurnDecision{}, session.Boundary().Peer("delegation is not a Specialist decision")
	}

	supplied, err := readConstraints(brief)
	if err != nil {
		return schema.AgentRuntimeResultTurnDecision{}, err
	}
	pins, err := readPins(brief, task)
	if err != nil {
		return schema.AgentRuntimeResultTurnDecision{}, err
	}

	prompt, err := brief.GovernedPrompt("model.compose")
	if err != nil {
		return schema.AgentRuntimeResultTurnDecision{}, err
	}
	completion, err := session.Model(ctx, task, prompt)
	if err != nil {
		return schema.AgentRuntimeResultTurnDecision{}, err
	}
	proposed, err := readComposition(completion)
	if err != nil {
		return schema.AgentRuntimeResultTurnDecision{}, err
	}

	document, warnings, err := composePage(supplied, proposed)
	if err != nil {
		return schema.AgentRuntimeResultTurnDecision{}, err
	}
	candidate, err := buildCandidate(pins, document, warnings, proposed, session.ModelInvocations())
	if err != nil {
		return schema.AgentRuntimeResultTurnDecision{}, err
	}

	// The candidate is written before it is named. A reference to a document
	// nothing recorded is what makes a final decision unverifiable, and it is
	// the one thing the controlled artifact write establishes that a payload
	// value never could.
	reference, err := session.SubmitCandidate(ctx, task, candidate)
	if err != nil {
		return schema.AgentRuntimeResultTurnDecision{}, err
	}
	return schema.AgentRuntimeResultTurnDecision{
		Decision: schema.AgentRuntimeResultTurnDecisionDecisionFinal,
		Payload: schema.SharedPrimitivesBoundedStringMap{
			"summary":         payloadSummary(candidate.Generation.Summary),
			"candidateDigest": string(candidate.CandidateDigest),
		},
		ArtifactOutputs: []schema.SharedPrimitivesArtifactReference{reference},
	}, nil
}

// maximumPayloadSummaryRunes is what one bounded decision payload value
// carries. The candidate document keeps its summary in full under its own
// bound; the payload carries a copy beside the reference, and a copy that
// exceeded the payload's bound would make the unit sign a document the
// contract calls invalid.
const maximumPayloadSummaryRunes = 1024

// payloadSummary bounds the summary copy the decision payload carries, on a
// rune boundary so the copy stays valid text.
func payloadSummary(summary string) string {
	runes := []rune(summary)
	if len(runes) <= maximumPayloadSummaryRunes {
		return summary
	}
	return string(runes[:maximumPayloadSummaryRunes])
}

// pins is everything about a candidate that a runtime is told rather than
// decides.
type pins struct {
	target       schema.SharedPrimitivesTargetReference
	baseRevision schema.SharedPrimitivesOpaqueId
	digests      schema.PageCandidateDigests
	preview      schema.PageCandidatePreview
}

// readPins reads the candidate's provenance out of the supplied context and the
// task itself.
//
// Two of the five digests come from the task rather than the parameters: the
// definition digest and the contract BOM are what this attempt was dispatched
// under, and reading them from anywhere else would let a candidate claim to
// have been produced under contracts the dispatch did not pin.
func readPins(brief *runtime.Brief, task schema.AgentTask) (pins, error) {
	targetType, err := brief.Required(keyTargetType)
	if err != nil {
		return pins{}, err
	}
	targetID, err := brief.Identifier(keyTargetID)
	if err != nil {
		return pins{}, err
	}
	workspaceID, err := brief.Identifier(keyWorkspaceID)
	if err != nil {
		return pins{}, err
	}
	projectID, err := brief.Identifier(keyProjectID)
	if err != nil {
		return pins{}, err
	}
	baseRevision, err := brief.Identifier(keyBaseRevision)
	if err != nil {
		return pins{}, err
	}
	targetDigest, err := brief.Digest(keyTargetDigest)
	if err != nil {
		return pins{}, err
	}
	catalogDigest, err := brief.Digest(keyCatalogDigest)
	if err != nil {
		return pins{}, err
	}
	policyDigest, err := brief.Digest(keyPolicyDigest)
	if err != nil {
		return pins{}, err
	}
	previewTaskID, err := brief.Identifier(keyPreviewTaskID)
	if err != nil {
		return pins{}, err
	}
	previewArtifact, err := brief.ArtifactReference(keyPreviewArtifac)
	if err != nil {
		return pins{}, err
	}
	// The accepted preview result must be one of the task's own pinned inputs.
	// A preview a Specialist could name freely would be a render nobody
	// performed, attested to by the candidate that names it.
	pinned, present := brief.ArtifactInput(string(previewArtifact.ArtifactId))
	if !present || pinned.Digest != previewArtifact.Digest {
		return pins{}, &runtime.ContextError{Key: keyPreviewArtifac}
	}
	return pins{
		target: schema.SharedPrimitivesTargetReference{
			TargetType:  targetType,
			TargetId:    targetID,
			WorkspaceId: workspaceID,
			ProjectId:   projectID,
		},
		baseRevision: baseRevision,
		digests: schema.PageCandidateDigests{
			TargetDigest:      targetDigest,
			CatalogDigest:     catalogDigest,
			PolicyDigest:      policyDigest,
			DefinitionDigest:  task.Definition.DefinitionDigest,
			ContractBomDigest: task.ContractBomReference.BomDigest,
		},
		preview: schema.PageCandidatePreview{
			TaskId:         previewTaskID,
			ResultArtifact: pinned,
		},
	}, nil
}

// buildCandidate assembles the canonical candidate around the composed page.
func buildCandidate(
	supplied pins,
	document pageDocument,
	warnings []schema.PageCandidateWarningsElem,
	proposed composition,
	invocations []string,
) (schema.PageCandidate, error) {
	pageData, err := runtime.PinDocument(document, pageDocumentMediaType)
	if err != nil {
		return schema.PageCandidate{}, err
	}
	summary := bound(proposed.Summary, maximumSummaryBytes)
	assumptions := make([]string, 0, len(proposed.Assumptions))
	for _, assumption := range proposed.Assumptions {
		trimmed := strings.TrimSpace(assumption)
		if trimmed == "" {
			continue
		}
		if len(assumptions) == maximumAssumptions {
			break
		}
		assumptions = append(assumptions, bound(trimmed, maximumAssumptionBytes))
	}
	references := schema.PageCandidateReferences{
		ModelInvocations: identifiers(invocations),
		// A Specialist executes no tools, creates no child runs, and records no
		// evidence of its own. Empty lists are the honest statement of that;
		// omitting them would be a different document.
		ToolInvocations: []schema.SharedPrimitivesOpaqueId{},
		Delegations:     []schema.SharedPrimitivesOpaqueId{},
		Evidence:        []schema.SharedPrimitivesOpaqueId{},
	}
	if warnings == nil {
		warnings = []schema.PageCandidateWarningsElem{}
	}
	candidate := schema.PageCandidate{
		Kind:         "PageCandidate",
		Target:       supplied.target,
		BaseRevision: supplied.baseRevision,
		PageData:     pageData,
		Digests:      supplied.digests,
		// validationReceipts stays empty here. A receipt is what a validator
		// produced, and this runtime runs none: a Specialist that wrote its own
		// receipt would be attesting to a check it also performed.
		ValidationReceipts: []schema.SharedPrimitivesArtifactReference{},
		Preview:            supplied.preview,
		Generation: schema.PageCandidateGeneration{
			Summary:     summary,
			Assumptions: assumptions,
		},
		References: references,
		Warnings:   warnings,
	}
	// The candidate's own digest covers everything else about it. It is taken
	// last and over the document without it, because a document cannot contain
	// the hash of itself.
	digest, err := runtime.SelfDigest(candidate, "candidateDigest")
	if err != nil {
		return schema.PageCandidate{}, err
	}
	candidate.CandidateDigest = schema.SharedPrimitivesDigest(digest)
	return candidate, nil
}

// identifiers renders the governed invocations a candidate records.
func identifiers(values []string) []schema.SharedPrimitivesOpaqueId {
	out := make([]schema.SharedPrimitivesOpaqueId, 0, len(values))
	for _, value := range values {
		out = append(out, schema.SharedPrimitivesOpaqueId(value))
	}
	return out
}

// bound keeps supplied prose inside the bound the contract records. Prose is
// the one place truncation is right: a summary is descriptive, and a candidate
// lost because its summary ran long would lose the page with it.
func bound(value string, maximum int) string {
	value = strings.TrimSpace(value)
	if len(value) <= maximum {
		return value
	}
	return value[:maximum]
}
