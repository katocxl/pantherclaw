// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"regexp"
	"slices"
)

// Coverage is a package's optional coverage declaration (G0 M20 D254,
// F756): where an action's environment comes from, which target types scope
// the records its actions touch, which fact classifies who receives what it
// sends, and the channels it maps. It only describes what the package's
// definitions already do: validation refuses a declaration that names
// anything the package does not declare, and nothing that decides reads it,
// so a declaration never widens authority (HR-523).
type Coverage struct {
	Environment EnvironmentSource `json:"environment"`
	// RecordScope are the target types whose ids bound the records the
	// package's actions touch.
	RecordScope []string `json:"record_scope"`
	// RecipientFact is the fact that classifies who receives what the
	// package sends (internal or external), when it sends anything.
	RecipientFact string `json:"recipient_fact,omitzero"`
	// Channels are the channels the package maps.
	Channels []Channel `json:"channels"`
}

// EnvironmentSource says where an action's environment comes from.
type EnvironmentSource struct {
	Source EnvironmentSourceKind `json:"source"`
	// Param names the param that carries it (source param); Fact names the
	// fact that reports it (source fact).
	Param string `json:"param,omitzero"`
	Fact  string `json:"fact,omitzero"`
}

// EnvironmentSourceKind is where an environment comes from.
type EnvironmentSourceKind string

// Environment sources. None: the package's actions have no environment.
const (
	EnvironmentNone  EnvironmentSourceKind = "none"
	EnvironmentParam EnvironmentSourceKind = "param"
	EnvironmentFact  EnvironmentSourceKind = "fact"
)

const maxCoverageItems = 16

var coverageNameRe = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,127}$`)

// validateCoverage checks the declaration against the package: every name
// it uses is declared by the package's definitions, consequence rules or
// mappings (HR-523).
func (p *Package) validateCoverage() error {
	c := p.Coverage
	if c == nil {
		return nil
	}
	params, facts, targets, channels := map[string]ParamType{}, map[string]bool{}, map[string]bool{}, map[Channel]bool{}
	for _, d := range p.Definitions {
		for name, ps := range d.Params {
			params[name] = ps.Type
		}
		for _, pr := range d.Prerequisites {
			facts[pr.Fact] = true
		}
		if d.Target.Type != ConnectionTarget {
			targets[d.Target.Type] = true
		}
		for _, m := range d.Mappings {
			channels[m.Channel] = true
		}
	}
	for _, r := range p.Consequences {
		for _, f := range r.RequiresFacts {
			facts[f] = true
		}
	}
	e := c.Environment
	switch e.Source {
	case EnvironmentNone:
		if e.Param != "" || e.Fact != "" {
			return invalid("coverage.environment: source none names no param or fact")
		}
	case EnvironmentParam:
		if t, ok := params[e.Param]; e.Fact != "" || !ok || (t != TypeIdentifier && t != TypeEnum) {
			return invalid("coverage.environment: param %q must be an identifier or enum param a definition declares", e.Param)
		}
	case EnvironmentFact:
		if e.Param != "" || !facts[e.Fact] {
			return invalid("coverage.environment: fact %q must be a fact a prerequisite or consequence rule requires", e.Fact)
		}
	default:
		return invalid("coverage.environment.source must be none, param or fact")
	}
	if len(c.RecordScope) == 0 || len(c.RecordScope) > maxCoverageItems {
		return invalid("coverage.record_scope: 1..%d target types", maxCoverageItems)
	}
	for i, t := range c.RecordScope {
		if !coverageNameRe.MatchString(t) || !targets[t] || slices.Contains(c.RecordScope[:i], t) {
			return invalid("coverage.record_scope: %q must be a distinct target type a definition declares", t)
		}
	}
	if f := c.RecipientFact; f != "" && !facts[f] {
		return invalid("coverage.recipient_fact: %q must be a fact a prerequisite or consequence rule requires", f)
	}
	if len(c.Channels) == 0 || len(c.Channels) > maxCoverageItems {
		return invalid("coverage.channels: 1..%d channels", maxCoverageItems)
	}
	for i, ch := range c.Channels {
		if !channels[ch] || slices.Contains(c.Channels[:i], ch) {
			return invalid("coverage.channels: %q must be a distinct channel a mapping uses", ch)
		}
	}
	return nil
}
