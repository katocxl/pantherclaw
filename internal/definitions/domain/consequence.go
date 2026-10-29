// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"regexp"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// ConsequenceRule is a reviewed, bounded downstream consequence of an
// operation under named conditions (F405, ConsequenceIR). It predicts a
// possible effect; it never proves one happened.
type ConsequenceRule struct {
	ID            string      `json:"id"`
	Operation     string      `json:"operation"`
	When          string      `json:"when"`
	RequiresFacts []string    `json:"requires_facts"`
	Consequence   Consequence `json:"consequence"`
	ValidUntil    string      `json:"valid_until"`
	// MaxDepth is how far down a chain the rule applies (G0 M17 D109,
	// F411): 1, the default, only to an action itself; up to
	// MaxConsequenceDepth to a consequence of a consequence.
	MaxDepth int `json:"max_depth,omitzero"`
}

// MaxConsequenceDepth is the deepest a consequence chain goes (D109).
const MaxConsequenceDepth = 4

// Depth is the deepest the rule applies: MaxDepth, or 1 without one.
func (c ConsequenceRule) Depth() int { return max(c.MaxDepth, 1) }

// Expired reports whether the rule's review has expired at now (G0 M17
// D110): its valid_until day is over, or cannot be read.
func (c ConsequenceRule) Expired(now time.Time) bool {
	exp, err := parseDay("valid_until", c.ValidUntil)
	return err != nil || !now.Before(exp)
}

// Consequence is the predicted downstream effect.
type Consequence struct {
	Operation   string `json:"operation"`
	Effect      string `json:"effect"`
	Description string `json:"description"`
	// Target is the id of the consequence's target, a template over the
	// action's target id (G0 M8): {target.id} or {target.id.<group>}
	// between literal text, such as {target.id.owner}/{target.id.repo}
	// for the repository a pull request merges into. Without one, the
	// consequence is about the action's own target.
	Target string `json:"target,omitzero"`
	// Environments is a CEL expression over the rule's facts that gives
	// the environments the consequence reaches, a list of strings,
	// evaluated when the rule predicts it (G0 M8): change windows are per
	// environment (HR-207).
	Environments string `json:"environments,omitzero"`
}

var (
	idRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	// targetTextRe is the literal text of a consequence target template.
	targetTextRe = regexp.MustCompile(`^[A-Za-z0-9._/@#:-]*$`)
)

// maxTargetTemplate bounds a consequence target template.
const maxTargetTemplate = 256

// validateConsequences checks the consequence rules against the package's
// operations.
func (p *Package) validateConsequences(ops map[string]*Definition) error {
	ids := map[string]bool{}
	for _, c := range p.Consequences {
		if err := c.validate(ops); err != nil {
			return err
		}
		if ids[c.ID] {
			return invalid("duplicate consequence rule %s", c.ID)
		}
		ids[c.ID] = true
	}
	return nil
}

func (c ConsequenceRule) validate(ops map[string]*Definition) error {
	switch {
	case !idRe.MatchString(c.ID):
		return invalid("consequence id %q", c.ID)
	case ops[c.Operation] == nil:
		return invalid("consequence %s: operation %s is not defined in this package", c.ID, c.Operation)
	case !actionir.ValidOperation(c.Consequence.Operation) || !kindRe.MatchString(c.Consequence.Effect):
		return invalid("consequence %s: needs a consequence operation and effect", c.ID)
	case ops[c.Consequence.Operation] == nil:
		// The pipeline decides a consequence by its definition in the same
		// package version (a virtual write such as github.deployment.trigger,
		// or another of its operations); without one the rule could only
		// fail when an action needs it.
		return invalid("consequence %s: consequence operation %s is not defined in this package", c.ID, c.Consequence.Operation)
	case len(c.RequiresFacts) == 0 || len(c.RequiresFacts) > maxItems:
		return invalid("consequence %s: a consequence needs 1..%d verified facts (no invented causality)", c.ID, maxItems)
	case c.MaxDepth < 0 || c.MaxDepth > MaxConsequenceDepth:
		return invalid("consequence %s: max_depth is 1..%d", c.ID, MaxConsequenceDepth)
	}
	for _, f := range c.RequiresFacts {
		if !kindRe.MatchString(f) {
			return invalid("consequence %s: fact %q", c.ID, f)
		}
	}
	if err := expr("consequence "+c.ID+".when", c.When, true); err != nil {
		return err
	}
	if err := expr("consequence "+c.ID+".environments", c.Consequence.Environments, false); err != nil {
		return err
	}
	if err := c.validateTarget(ops[c.Operation].Target); err != nil {
		return err
	}
	if err := text("consequence "+c.ID+".description", c.Consequence.Description); err != nil {
		return err
	}
	_, err := parseDay("consequence "+c.ID+".valid_until", c.ValidUntil)
	return err
}

// validateTarget checks the target template against the target of the
// rule's operation: every reference is target.id or one of its pattern's
// named groups.
func (c ConsequenceRule) validateTarget(on TargetSpec) error {
	t := c.Consequence.Target
	if t == "" {
		return nil
	}
	at := "consequence " + c.ID + ".target"
	refs := holderRe.FindAllStringSubmatch(t, -1)
	if len(t) > maxTargetTemplate || len(refs) == 0 || !targetTextRe.MatchString(holderRe.ReplaceAllString(t, "")) {
		return invalid("%s: a template of at most %d bytes with at least one reference", at, maxTargetTemplate)
	}
	for _, r := range refs {
		if r[1] == "target.id" {
			continue
		}
		group, ok := strings.CutPrefix(r[1], "target.id.")
		if !ok || !on.hasPart(group) {
			return invalid("%s: %q must be target.id or a named group of %s's target.id_pattern", at, r[1], c.Operation)
		}
	}
	return nil
}

// TargetID is the id of the consequence's target for an action whose
// target, which on describes, has the given id: the template filled from
// it, or the id itself without a template. It reports false when a group
// the template names matched nothing.
func (c ConsequenceRule) TargetID(on TargetSpec, id string) (string, bool) {
	if c.Consequence.Target == "" {
		return id, true
	}
	ok := true
	out := holderRe.ReplaceAllStringFunc(c.Consequence.Target, func(h string) string {
		ref := h[1 : len(h)-1]
		if ref == "target.id" {
			return id
		}
		part, found := on.Part(id, strings.TrimPrefix(ref, "target.id."))
		ok = ok && found
		return part
	})
	return out, ok
}
