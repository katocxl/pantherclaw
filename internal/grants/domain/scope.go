// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// Data scope (G0 M14 D11, F101–F103): per exact read operation, which
// records an answer may hold (by a record key such as a customer id) and
// which data classes it may show. It never denies an action: the
// Authority turns it into obligations the gateway applies to the answer.
// Scope only narrows: delegation, envelopes and revisions intersect it,
// and "secret" is never allowed.

// ScopeBound is one operation's data scope; at least one part is set.
type ScopeBound struct {
	// Records lists the exact record ids the answer may hold.
	Records *RecordScope `json:"records,omitzero"`
	// Classes are the data classes an answer may show (public, internal,
	// pii); a value of another class is redacted.
	Classes *Match `json:"classes,omitzero"`
}

// RecordScope is a record key and its allowed values.
type RecordScope struct {
	Key    string   `json:"key"`
	Values []string `json:"values"`
}

// Scope limits.
const (
	MaxScopeRecords = 100
	maxScopeOps     = 64
)

// ScopeClasses are the data classes a scope may allow: never secret.
var ScopeClasses = []string{"public", "internal", "pii"}

// scopeKeyRe is a record key: a lower-case name, as a manifest's scope
// key (D15).
var scopeKeyRe = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

func (s ScopeBound) validate(name string) error {
	if s.Records == nil && s.Classes == nil {
		return invalid("%s: a scope limits records, classes or both", name)
	}
	if r := s.Records; r != nil {
		if !scopeKeyRe.MatchString(r.Key) || len(r.Values) == 0 || len(r.Values) > MaxScopeRecords {
			return invalid("%s.records: a lower-case key and 1..%d exact values", name, MaxScopeRecords)
		}
		for i, v := range r.Values {
			if err := actionir.CheckIdentifier(name+".records", v); err != nil || slices.Contains(r.Values[:i], v) {
				return invalid("%s.records: value %q", name, v)
			}
		}
	}
	if c := s.Classes; c != nil {
		if len(c.Prefixes) > 0 || len(c.IDs) == 0 {
			return invalid("%s.classes: exact classes of %v", name, ScopeClasses)
		}
		for _, v := range c.IDs {
			if !slices.Contains(ScopeClasses, v) {
				return invalid("%s.classes: %q is not one of %v (secret is never allowed)", name, v, ScopeClasses)
			}
		}
	}
	return nil
}

// validateScope checks a bounds document's scope.
func validateScope(scope map[string]ScopeBound) error {
	if len(scope) > maxScopeOps {
		return invalid("scope: at most %d operations", maxScopeOps)
	}
	for _, op := range slices.Sorted(maps.Keys(scope)) {
		if !validOperation(op) || strings.HasSuffix(op, "*") {
			return invalid("scope: %q is not an exact operation", op)
		}
		if err := scope[op].validate("scope." + op); err != nil {
			return err
		}
	}
	return nil
}

// scopeWithin reports where b's scope is wider than p's, or nil: every
// operation and part p scopes, b scopes at least as narrowly (the same
// record key, a subset of its values and classes).
func scopeWithin(b, p map[string]ScopeBound) *WithinError {
	for _, op := range slices.Sorted(maps.Keys(p)) {
		dim := "scope." + op
		ps := p[op]
		mine, ok := b[op]
		if !ok {
			return &WithinError{dim, "unrestricted, but limited"}
		}
		if pr := ps.Records; pr != nil {
			r := mine.Records
			switch {
			case r == nil:
				return &WithinError{dim + ".records", "unrestricted, but limited to " + pr.Key + " " + strings.Join(pr.Values, ", ")}
			case r.Key != pr.Key:
				return &WithinError{dim + ".records", fmt.Sprintf("by %s, but limited by %s", r.Key, pr.Key)}
			}
			for _, v := range r.Values {
				if !slices.Contains(pr.Values, v) {
					return &WithinError{dim + ".records", fmt.Sprintf("%q is not allowed", v)}
				}
			}
		}
		if v := matchWithin(dim+".classes", mine.Classes, ps.Classes); v != nil {
			return v
		}
	}
	return nil
}

// inheritScope returns b's scope with every operation and part b leaves
// open taken from p.
func inheritScope(b, p map[string]ScopeBound) map[string]ScopeBound {
	if len(b) == 0 && len(p) == 0 {
		return nil
	}
	out := cloneScope(b)
	if out == nil {
		out = map[string]ScopeBound{}
	}
	for op, ps := range p {
		mine := out[op]
		if mine.Records == nil && ps.Records != nil {
			mine.Records = cloneRecords(ps.Records)
		}
		if mine.Classes == nil {
			mine.Classes = cloneMatch(ps.Classes)
		}
		out[op] = mine
	}
	return out
}

// intersectScope is the scope within both: per operation, the common
// values of one record key (two different keys allow no record, since one
// answer cannot be held to both) and the common classes.
func intersectScope(a, b map[string]ScopeBound) map[string]ScopeBound {
	if len(a) == 0 {
		return cloneScope(b)
	}
	out := cloneScope(a)
	for op, bs := range b {
		mine, ok := out[op]
		if !ok {
			out[op] = ScopeBound{Records: cloneRecords(bs.Records), Classes: cloneMatch(bs.Classes)}
			continue
		}
		switch {
		case mine.Records == nil:
			mine.Records = cloneRecords(bs.Records)
		case bs.Records != nil && mine.Records.Key != bs.Records.Key:
			mine.Records = &RecordScope{Key: mine.Records.Key, Values: []string{}}
		case bs.Records != nil:
			var common []string
			for _, v := range mine.Records.Values {
				if slices.Contains(bs.Records.Values, v) {
					common = append(common, v)
				}
			}
			mine.Records = &RecordScope{Key: mine.Records.Key, Values: nonNil(common)}
		}
		mine.Classes = intersectMatch(mine.Classes, bs.Classes)
		out[op] = mine
	}
	return out
}

func cloneRecords(r *RecordScope) *RecordScope {
	if r == nil {
		return nil
	}
	return &RecordScope{Key: r.Key, Values: slices.Clone(r.Values)}
}

func cloneScope(s map[string]ScopeBound) map[string]ScopeBound {
	if s == nil {
		return nil
	}
	out := make(map[string]ScopeBound, len(s))
	for op, b := range s {
		out[op] = ScopeBound{Records: cloneRecords(b.Records), Classes: cloneMatch(b.Classes)}
	}
	return out
}

// HasScope reports whether the bounds limit any operation's data scope:
// issuing or revising such a grant needs the Team edition (D11).
func (b Bounds) HasScope() bool { return len(b.Scope) > 0 }
