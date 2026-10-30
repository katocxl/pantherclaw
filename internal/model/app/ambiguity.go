// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/model/ports"
)

// Ambiguity is a vague term of a person's text and the concrete threshold
// the model proposes for it, which the reviewer confirms (D304). It is shown,
// and it changes nothing by itself. It is stored with a draft, so a later
// reviewer sees it too (D314).
type Ambiguity struct {
	Term              string `json:"term"`
	ProposedThreshold string `json:"proposed_threshold"`
}

const (
	maxAmbiguities = 16
	maxAmbiguity   = 200
	// maxGroups bounds the operation names a call sends.
	maxGroups = 256
)

// AmbiguitySchema is the schema of a draft's ambiguities.
func AmbiguitySchema() ports.Schema {
	return ports.Array(ports.Object(map[string]ports.Schema{
		"term":               ports.Text("the vague words, exactly as the person wrote them"),
		"proposed_threshold": ports.Text("a concrete value for the reviewer to confirm"),
	}))
}

// vagueTerm finds words that name no value. A draft that settles one silently
// is refused.
var vagueTerm = regexp.MustCompile(`(?i)\b(a lot|lots of|too many|too much|large|big|recently|frequently|often|excessive|unusual|suspicious|significant|soon)\b`)

// environmentTerm finds a request about an environment. A draft cannot hold
// one: environments are ids, which a model is never sent (HR-542), so a name in
// a condition would never match and the condition would silently not apply
// (D321). The prompt asks a model to refuse what this does not catch.
var environmentTerm = regexp.MustCompile(`(?i)\b(prod|production|prd|staging|development|dev|qa|uat|environments?|envs?)\b`)

// CheckEnvironment refuses a request about an environment, before any call.
func CheckEnvironment(text string) error {
	if environmentTerm.MatchString(text) {
		return ErrEnvironmentCondition
	}
	return nil
}

// CheckAmbiguities refuses malformed ambiguities and a draft that leaves a
// vague term of text unsettled (D304).
func CheckAmbiguities(text string, as []Ambiguity) error {
	if len(as) > maxAmbiguities {
		return ports.ErrInvalidOutput
	}
	lower := strings.ToLower(text)
	for _, a := range as {
		if !shownLine(a.Term) || !shownLine(a.ProposedThreshold) || !strings.Contains(lower, strings.ToLower(a.Term)) {
			return ports.ErrInvalidOutput
		}
	}
	for _, term := range vagueTerm.FindAllString(text, -1) {
		settled := slices.ContainsFunc(as, func(a Ambiguity) bool {
			return strings.Contains(strings.ToLower(a.Term), strings.ToLower(term))
		})
		if !settled {
			return ports.ErrInvalidOutput
		}
	}
	return nil
}

// shownLine reports whether s is one line fit to show a reviewer.
func shownLine(s string) bool {
	return s != "" && len(s) <= maxAmbiguity && utf8.ValidString(s) && !strings.ContainsFunc(s, unreadable)
}

// OperationGroups reduces operations to the names a call sends: an operation
// of up to two segments as itself, a longer one as its two-segment prefix.
// Names only, sorted, and bounded.
func OperationGroups(ops []string) []string {
	var out []string
	for _, op := range ops {
		if segs := strings.Split(op, "."); len(segs) > 2 {
			op = segs[0] + "." + segs[1] + ".*"
		}
		out = append(out, op)
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) > maxGroups {
		out = out[:maxGroups]
	}
	return out
}
