// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package retention removes expired evidence bodies and keeps what legal
// holds cover (G0 M7 track B slice B8, design decision 9, founder decision
// 4; HR-198, HR-055, T-075).
//
// Evidence is kept per category for a number of days: payload captures,
// normalized facts (replay inputs and observed values), receipts (receipt
// bodies and receipt ledger entries), approvals (approval ledger entries
// and approval notes) and the security audit (every other audit ledger
// entry). Each category's period is an immutable revision; the one in
// effect at a time is the newest that took effect by then and that no
// later revision cancelled (a revision recorded before an earlier one took
// effect cancels it). Lengthening applies at once; shortening is a
// weakening change that takes effect 7 days after it was recorded, so a
// hold can still be placed.
//
// The daily job (Remover) runs per org through the audited cross-org
// lister and the pc_retention role, which can only null body columns, set
// their tombstone (when, and under which policy revision) and delete
// replay inputs. It never touches an item inside an active legal hold,
// never a ledger entry that no checkpoint covers yet, and never chain
// hashes, Merkle leaves or checkpoints, so the chain, the checkpoints and
// `pclaw verify` still verify; a removed body is reported as not available.
// Each batch writes one evidence.retention_removed audit entry. Removed
// content is never rebuilt.
package retention

import (
	"slices"
	"strconv"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Category is a kind of evidence kept for one period.
type Category string

// Categories (design decision 9). Grant, policy, package and connection
// revisions ("versions") are kept while any retained receipt references
// them; M7 never removes them, so they have no category here.
const (
	Payloads        Category = "payloads"
	NormalizedFacts Category = "normalized_facts"
	Receipts        Category = "receipts"
	Approvals       Category = "approvals"
	SecurityAudit   Category = "security_audit"
)

// Bounds are a category's limits and default, in days.
type Bounds struct {
	Min, Max, Default int
}

var bounds = map[Category]Bounds{
	Payloads:        {Min: 1, Max: 30, Default: 7},
	NormalizedFacts: {Min: 7, Max: 730, Default: 90},
	Receipts:        {Min: 30, Max: 3650, Default: 365},
	Approvals:       {Min: 365, Max: 3650, Default: 365},
	SecurityAudit:   {Min: 365, Max: 3650, Default: 365},
}

// Categories returns every category, in a fixed order.
func Categories() []Category {
	return []Category{Payloads, NormalizedFacts, Receipts, Approvals, SecurityAudit}
}

// BoundsOf returns c's bounds, and false for an unknown category.
func BoundsOf(c Category) (Bounds, bool) {
	b, ok := bounds[c]
	return b, ok
}

// Allows reports whether days is within the bounds.
func (b Bounds) Allows(days int) bool { return days >= b.Min && days <= b.Max }

// ShorteningDelay is how long after it is recorded a shorter period takes
// effect (HR-198).
const ShorteningDelay = 7 * 24 * time.Hour

// Revision is one recorded revision of a category's period.
type Revision struct {
	ID       ids.UUID
	Category Category
	Number   int
	Days     int
	// SetBy is the person who set it; nil for the default the system
	// recorded.
	SetBy     *ids.UUID
	Created   time.Time
	Effective time.Time
}

// Label names the revision as reports show it, for example "receipts r2".
func (r Revision) Label() string { return Label(r.Category, r.Number) }

// Label names revision n of c.
func Label(c Category, n int) string { return string(c) + " r" + strconv.Itoa(n) }

// cancelled reports whether a later revision was recorded before r took
// effect.
func cancelled(revs []Revision, r Revision) bool {
	return slices.ContainsFunc(revs, func(n Revision) bool {
		return n.Category == r.Category && n.Number > r.Number && n.Created.Before(r.Effective)
	})
}

// Current returns the revision of c in effect at at, and false when none
// is (the category was never recorded). It matches pc.retention_current.
func Current(revs []Revision, c Category, at time.Time) (Revision, bool) {
	var best Revision
	found := false
	for _, r := range revs {
		if r.Category != c || r.Effective.After(at) || cancelled(revs, r) {
			continue
		}
		if !found || r.Number > best.Number {
			best, found = r, true
		}
	}
	return best, found
}

// Pending returns the revision of c recorded and not in effect at at: only
// the newest revision can be pending, because it cancels any earlier one
// that had not taken effect when it was recorded.
func Pending(revs []Revision, c Category, at time.Time) (Revision, bool) {
	var last Revision
	found := false
	for _, r := range revs {
		if r.Category == c && !r.Created.After(at) && (!found || r.Number > last.Number) {
			last, found = r, true
		}
	}
	if !found || !last.Effective.After(at) {
		return Revision{}, false
	}
	return last, true
}

// Next returns the number of the next revision of c.
func Next(revs []Revision, c Category) int {
	n := 0
	for _, r := range revs {
		if r.Category == c {
			n = max(n, r.Number)
		}
	}
	return n + 1
}
