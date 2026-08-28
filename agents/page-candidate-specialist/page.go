package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/ancyloce/anvilkit-agent-runtimes/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-runtimes/runtime"
)

// This is where a page is actually made.
//
// The division of labour is the whole design: the model proposes which
// components a page uses and what goes in them, and this code decides whether
// that proposal is expressible under the supplied component schema, default
// properties, default data, style rules, and animation constraints. Everything
// the model can influence passes through a check written against a supplied
// constraint; everything else — ordering, identity, structure, the shape of the
// document — is derived deterministically, so the same task and the same
// governed output always produce the same bytes and therefore the same digest.
//
// A proposal that violates a constraint is refused, never repaired. Truncating
// an overlong string or substituting an allowed theme for a disallowed one
// would make the runtime the author of the part it changed, and the candidate
// would then attribute to the model content the model did not propose.

// The supplied context keys the Specialist composes from.
const (
	keyComponentSchema      = "page.componentSchema"
	keyDefaultProperties    = "page.defaultProperties"
	keyDefaultData          = "page.defaultData"
	keyStyleConstraints     = "page.styleConstraints"
	keyAnimationConstraints = "page.animationConstraints"
)

// componentSchema is the supplied catalog: the only components a page may use
// and the only properties each of them declares.
type componentSchema struct {
	Components []componentDefinition `json:"components"`
}

type componentDefinition struct {
	Name       string                        `json:"name"`
	Properties map[string]propertyDefinition `json:"properties"`
}

// propertyDefinition is one declared property. The vocabulary is deliberately
// small: a schema this runtime cannot fully check is a schema it would have to
// partly trust, and a partly trusted schema admits whatever it does not cover.
type propertyDefinition struct {
	Type      string   `json:"type"`
	Values    []string `json:"values,omitempty"`
	MaxLength int      `json:"maxLength,omitempty"`
	Minimum   *float64 `json:"minimum,omitempty"`
	Maximum   *float64 `json:"maximum,omitempty"`
	Required  bool     `json:"required,omitempty"`
}

// styleConstraints is what the page as a whole must satisfy.
type styleConstraints struct {
	AllowedThemes   []string `json:"allowedThemes"`
	Theme           string   `json:"theme"`
	AllowedSpacing  []string `json:"allowedSpacing"`
	Spacing         string   `json:"spacing"`
	MaximumSections int      `json:"maximumSections"`
}

// animationConstraints is what any motion on the page must satisfy. Reduced
// motion is a constraint rather than a preference: when the supplied rules
// declare it, no effect survives composition.
type animationConstraints struct {
	AllowedEffects              []string `json:"allowedEffects"`
	MaximumDurationMilliseconds int      `json:"maximumDurationMilliseconds"`
	ReducedMotion               bool     `json:"reducedMotion"`
}

// constraints is the whole supplied brief for one composition.
type constraints struct {
	schema     componentSchema
	properties map[string]map[string]json.RawMessage
	data       map[string]map[string]json.RawMessage
	style      styleConstraints
	animation  animationConstraints
}

// readConstraints reads the supplied composition brief off the task.
//
// Every failure here is a ContextError, not a proposal refusal: the model has
// not been asked anything yet, and a task dispatched without its constraints is
// a dispatch problem an operator fixes, not a decision an agent made.
func readConstraints(brief *runtime.Brief) (constraints, error) {
	var read constraints
	if err := brief.Document(keyComponentSchema, &read.schema); err != nil {
		return constraints{}, err
	}
	if len(read.schema.Components) == 0 {
		return constraints{}, &runtime.ContextError{Key: keyComponentSchema}
	}
	for _, component := range read.schema.Components {
		if component.Name == "" || len(component.Properties) == 0 {
			return constraints{}, &runtime.ContextError{Key: keyComponentSchema}
		}
		for _, property := range component.Properties {
			switch property.Type {
			case "string", "number", "boolean":
			case "enum":
				if len(property.Values) == 0 {
					return constraints{}, &runtime.ContextError{Key: keyComponentSchema}
				}
			default:
				// A declared type this runtime cannot check is not a constraint
				// it can honour, and composing against it would be composing
				// against nothing.
				return constraints{}, &runtime.ContextError{Key: keyComponentSchema}
			}
		}
	}
	if err := brief.Document(keyDefaultProperties, &read.properties); err != nil {
		return constraints{}, err
	}
	if err := brief.Document(keyDefaultData, &read.data); err != nil {
		return constraints{}, err
	}
	if err := brief.Document(keyStyleConstraints, &read.style); err != nil {
		return constraints{}, err
	}
	if read.style.MaximumSections < 1 || len(read.style.AllowedThemes) == 0 || len(read.style.AllowedSpacing) == 0 {
		return constraints{}, &runtime.ContextError{Key: keyStyleConstraints}
	}
	if !contains(read.style.AllowedThemes, read.style.Theme) || !contains(read.style.AllowedSpacing, read.style.Spacing) {
		// The supplied brief contradicts itself. Composing under it would mean
		// choosing which half of the dispatch to believe.
		return constraints{}, &runtime.ContextError{Key: keyStyleConstraints}
	}
	if err := brief.Document(keyAnimationConstraints, &read.animation); err != nil {
		return constraints{}, err
	}
	if len(read.animation.AllowedEffects) == 0 || read.animation.MaximumDurationMilliseconds < 0 {
		return constraints{}, &runtime.ContextError{Key: keyAnimationConstraints}
	}
	return read, nil
}

// component resolves one declared component by name.
func (c constraints) component(name string) (componentDefinition, bool) {
	for _, definition := range c.schema.Components {
		if definition.Name == name {
			return definition, true
		}
	}
	return componentDefinition{}, false
}

// composition is what the governed model proposed for this page.
type composition struct {
	Sections    []proposedSection `json:"sections"`
	Summary     string            `json:"summary"`
	Assumptions []string          `json:"assumptions"`
}

type proposedSection struct {
	Component  string                     `json:"component"`
	Properties map[string]json.RawMessage `json:"properties,omitempty"`
	Animation  *proposedAnimation         `json:"animation,omitempty"`
}

type proposedAnimation struct {
	Effect               string `json:"effect"`
	DurationMilliseconds int    `json:"durationMilliseconds"`
}

// readComposition reads the proposal out of governed output.
//
// Decoding is strict for the same reason the Manager's plan decoding is: the
// interesting way for a model to reach past its authority is an extra member,
// and a decoder that skipped unknown members would skip exactly that.
func readComposition(completion runtime.Completion) (composition, error) {
	raw, present := completion.Value(compositionOutputKey)
	if !present {
		return composition{}, &runtime.ModelOutputError{Key: compositionOutputKey}
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var proposed composition
	if err := decoder.Decode(&proposed); err != nil {
		return composition{}, runtime.RefuseProposal(runtime.ProposalExpandsAuthority)
	}
	if len(proposed.Sections) == 0 || strings.TrimSpace(proposed.Summary) == "" {
		return composition{}, runtime.RefuseProposal(runtime.ProposalIncomplete)
	}
	return proposed, nil
}

// compositionOutputKey is where governed output carries the proposal.
const compositionOutputKey = "composition"

// pageDocument is the canonical Puck Data document that is the authoritative
// page content. It is what the candidate's pageData reference pins.
type pageDocument struct {
	Root    pageRoot               `json:"root"`
	Content []pageBlock            `json:"content"`
	Zones   map[string][]pageBlock `json:"zones"`
}

type pageRoot struct {
	Props map[string]any `json:"props"`
}

type pageBlock struct {
	Type  string         `json:"type"`
	Props map[string]any `json:"props"`
}

// composePage turns a validated proposal into the page document, or refuses.
//
// The warnings it returns are the constraints that changed the outcome. They
// travel on the candidate because a reviewer looking at a page with no motion
// should be able to see that reduced motion was in force rather than conclude
// the agent chose stillness.
func composePage(supplied constraints, proposed composition) (pageDocument, []schema.PageCandidateWarningsElem, error) {
	if len(proposed.Sections) > supplied.style.MaximumSections {
		return pageDocument{}, nil, runtime.RefuseProposal(runtime.ProposalOutsideConstraints)
	}
	warnings := make([]schema.PageCandidateWarningsElem, 0, 4)
	defaultsApplied, motionSuppressed := false, false

	blocks := make([]pageBlock, 0, len(proposed.Sections))
	for index, section := range proposed.Sections {
		definition, declared := supplied.component(section.Component)
		if !declared {
			return pageDocument{}, nil, runtime.RefuseProposal(runtime.ProposalOutsideSchema)
		}
		// Order is the merge rule and it is fixed: supplied default data first,
		// then supplied default properties, then what the model proposed. A
		// model may fill a slot the defaults left open and may override a
		// default, and it may do neither of those outside the declared schema.
		props := map[string]any{}
		applied, err := applyDefaults(props, definition, supplied.data[section.Component], keyDefaultData)
		if err != nil {
			return pageDocument{}, nil, err
		}
		defaultsApplied = defaultsApplied || applied
		applied, err = applyDefaults(props, definition, supplied.properties[section.Component], keyDefaultProperties)
		if err != nil {
			return pageDocument{}, nil, err
		}
		defaultsApplied = defaultsApplied || applied
		if err := applyProposed(props, definition, section.Properties); err != nil {
			return pageDocument{}, nil, err
		}
		for name, property := range definition.Properties {
			if !property.Required {
				continue
			}
			if _, present := props[name]; !present {
				return pageDocument{}, nil, runtime.RefuseProposal(runtime.ProposalIncomplete)
			}
		}
		motion, suppressed, err := resolveAnimation(supplied.animation, section.Animation)
		if err != nil {
			return pageDocument{}, nil, err
		}
		motionSuppressed = motionSuppressed || suppressed
		props["animation"] = motion
		// Identity is derived, never proposed. A model that could name a block
		// could name one that already exists, and two blocks with one identity
		// is a page nobody can review.
		props["id"] = blockIdentity(section.Component, index)
		blocks = append(blocks, pageBlock{Type: section.Component, Props: props})
	}

	if defaultsApplied {
		warnings = append(warnings, schema.PageCandidateWarningsElem{
			Code:   "DEFAULTS_APPLIED",
			Detail: "supplied default data and default properties filled properties the proposal did not name",
		})
	}
	if motionSuppressed {
		warnings = append(warnings, schema.PageCandidateWarningsElem{
			Code:   "REDUCED_MOTION_APPLIED",
			Detail: "the supplied animation constraints declare reduced motion, so no section carries an effect",
		})
	}
	document := pageDocument{
		Root: pageRoot{Props: map[string]any{
			"theme":   supplied.style.Theme,
			"spacing": supplied.style.Spacing,
		}},
		Content: blocks,
		Zones:   map[string][]pageBlock{},
	}
	return document, warnings, nil
}

// applyDefaults writes supplied defaults into a block's properties.
//
// A default outside the declared schema is a ContextError: the supplied brief,
// not the model, put it there, and reporting it as a model refusal would send
// an operator looking at the wrong thing.
func applyDefaults(
	props map[string]any,
	definition componentDefinition,
	defaults map[string]json.RawMessage,
	key string,
) (bool, error) {
	applied := false
	for name, raw := range defaults {
		property, declared := definition.Properties[name]
		if !declared {
			return false, &runtime.ContextError{Key: key}
		}
		value, err := readProperty(property, raw)
		if err != nil {
			return false, &runtime.ContextError{Key: key}
		}
		props[name] = value
		applied = true
	}
	return applied, nil
}

// applyProposed writes the model's own property values, checked against the
// declared schema.
func applyProposed(props map[string]any, definition componentDefinition, proposed map[string]json.RawMessage) error {
	for name, raw := range proposed {
		property, declared := definition.Properties[name]
		if !declared {
			return runtime.RefuseProposal(runtime.ProposalOutsideSchema)
		}
		value, err := readProperty(property, raw)
		if err != nil {
			return runtime.RefuseProposal(runtime.ProposalOutsideSchema)
		}
		props[name] = value
	}
	return nil
}

// readProperty reads one value against its declared type. A value outside the
// declaration is rejected rather than coerced: coercion is the runtime deciding
// what the model meant.
func readProperty(property propertyDefinition, raw json.RawMessage) (any, error) {
	if isJSONNull(raw) {
		// Decoding null into a Go string, number, or bool leaves the zero value
		// and reports no error, so a proposal of null would otherwise become an
		// empty title nobody wrote. A property is absent or it has a value.
		return nil, fmt.Errorf("property is null")
	}
	switch property.Type {
	case "string":
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, fmt.Errorf("property is not a string")
		}
		if property.MaxLength > 0 && len(value) > property.MaxLength {
			return nil, fmt.Errorf("property is longer than the schema declares")
		}
		return value, nil
	case "enum":
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, fmt.Errorf("property is not a string")
		}
		if !contains(property.Values, value) {
			return nil, fmt.Errorf("property is outside the declared values")
		}
		return value, nil
	case "number":
		var value float64
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, fmt.Errorf("property is not a number")
		}
		if property.Minimum != nil && value < *property.Minimum {
			return nil, fmt.Errorf("property is below the declared minimum")
		}
		if property.Maximum != nil && value > *property.Maximum {
			return nil, fmt.Errorf("property is above the declared maximum")
		}
		return value, nil
	case "boolean":
		var value bool
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, fmt.Errorf("property is not a boolean")
		}
		return value, nil
	default:
		return nil, fmt.Errorf("property type is not one this runtime checks")
	}
}

// resolveAnimation decides one section's motion under the supplied constraints.
func resolveAnimation(supplied animationConstraints, proposed *proposedAnimation) (map[string]any, bool, error) {
	none := map[string]any{"effect": "none", "durationMilliseconds": 0}
	if supplied.ReducedMotion {
		// Reduced motion is not negotiable and not a refusal: the page is still
		// the page the model proposed, with the motion the constraints removed.
		return none, proposed != nil && proposed.Effect != "" && proposed.Effect != "none", nil
	}
	if proposed == nil {
		return none, false, nil
	}
	if !contains(supplied.AllowedEffects, proposed.Effect) {
		return nil, false, runtime.RefuseProposal(runtime.ProposalOutsideConstraints)
	}
	if proposed.DurationMilliseconds < 0 || proposed.DurationMilliseconds > supplied.MaximumDurationMilliseconds {
		return nil, false, runtime.RefuseProposal(runtime.ProposalOutsideConstraints)
	}
	return map[string]any{
		"effect":               proposed.Effect,
		"durationMilliseconds": proposed.DurationMilliseconds,
	}, false, nil
}

// blockIdentity derives a stable identity for one block from what it is and
// where it sits. Deterministic identity is what makes the same proposal produce
// the same document digest on a replacement attempt.
func blockIdentity(component string, index int) string {
	return strings.ToLower(component) + "-" + strconv.Itoa(index)
}

// isJSONNull reports whether a raw value is the JSON literal null.
func isJSONNull(raw json.RawMessage) bool {
	return strings.TrimSpace(string(raw)) == "null"
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
