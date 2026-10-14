// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundle

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"slices"
	"time"
)

// Ledger kinds of coverage (G0 M9, HR-217).
const (
	SnapshotKind     = "coverage.snapshot"
	InvalidationKind = "coverage.invalidation"
)

// scope is a coverage scope as the ledger and claims name it.
type scope struct {
	Agent      string `json:"agent"`
	Connection string `json:"connection"`
	Operation  string `json:"operation"`
}

// snapshotEntry is a verified coverage.snapshot entry of the bundle.
type snapshotEntry struct {
	seq  int64
	body struct {
		Scope      scope    `json:"scope"`
		State      string   `json:"state"`
		Snapshot   string   `json:"snapshot"`
		ComputedAt string   `json:"computed_at"`
		ExpiresAt  string   `json:"expires_at"`
		Exclusions []string `json:"exclusions"`
	}
	computed time.Time
}

// invalidationEntry is a verified coverage.invalidation entry.
type invalidationEntry struct {
	Connection string `json:"connection"`
	Agent      string `json:"agent"`
	Kind       string `json:"kind"`
	OccurredAt string `json:"occurred_at"`
	occurred   time.Time
}

// noteCoverage keeps a coverage entry whose hash verified.
func (v *verifier) noteCoverage(e *Entry, body jsontext.Value) {
	switch e.Kind {
	case SnapshotKind:
		s := snapshotEntry{seq: e.Seq}
		if json.Unmarshal(body, &s.body) != nil || s.body.Snapshot == "" {
			return
		}
		t, err := time.Parse(tsLayout, s.body.ComputedAt)
		if err != nil {
			return
		}
		s.computed = t
		v.snapshots[s.body.Snapshot] = s
	case InvalidationKind:
		var i invalidationEntry
		if json.Unmarshal(body, &i) != nil {
			return
		}
		t, err := time.Parse(tsLayout, i.OccurredAt)
		if err != nil {
			return
		}
		i.occurred = t
		v.invalidations = append(v.invalidations, i)
	}
}

// claim is a decision receipt's coverage claim (PAP-1 §9.1).
type claim struct {
	V             int      `json:"v"`
	State         string   `json:"state"`
	Snapshot      string   `json:"snapshot"`
	Scope         scope    `json:"scope"`
	SnapshotState string   `json:"snapshot_state"`
	Lapsed        bool     `json:"lapsed"`
	Reason        string   `json:"reason"`
	Exclusions    []string `json:"exclusions"`
	// Unavailable says the claim could not be read at decision time, and
	// why; such a claim states nothing else.
	Unavailable string `json:"unavailable"`
}

// unavailableReasons are why a claim may be unavailable.
var unavailableReasons = map[string]bool{"timeout": true, "error": true}

// coverage checks a decision receipt's coverage claim against the snapshot
// ledger (HR-217). The claimed snapshot's entry must be in the bundle, of
// the receipt's scope, with the claim's snapshot state and exclusions, and
// computed before the decision (iat, to the second). A claim that did not
// lapse must hold the snapshot's state, unexpired, with no invalidation of
// the scope and no newer snapshot between its computation and iat. A
// lapsed claim's reason must hold (an expiry before iat, or an
// invalidation of that kind in that interval), and its state is never
// ENFORCED. Missing entries are not available, and so is a claim the
// receipt says was unavailable (its reason, with nothing else); anything
// else fails.
func (v *verifier) coverage(subject string, payload []byte, seq int64, recorded bool) {
	var r struct {
		Iat int64 `json:"iat"`
		Pap struct {
			Connection string `json:"connection"`
			Identity   struct {
				Agent string `json:"agent"`
			} `json:"identity"`
			Coverage *claim `json:"coverage"`
		} `json:"pap"`
	}
	if json.Unmarshal(payload, &r) != nil || r.Pap.Coverage == nil {
		return
	}
	if c := r.Pap.Coverage; c.Unavailable != "" {
		switch {
		case !unavailableReasons[c.Unavailable]:
			v.r.add("receipt.coverage", subject, Failed, "the claim is unavailable for an unknown reason %q", truncate(c.Unavailable))
		case c.V != 0 || c.State != "" || c.Snapshot != "" || c.Scope != (scope{}) || c.SnapshotState != "" || c.Lapsed ||
			c.Reason != "" || c.Exclusions != nil:
			v.r.add("receipt.coverage", subject, Failed, "an unavailable claim states coverage too")
		default:
			v.r.add("receipt.coverage", subject, NotAvailable, "claim unavailable (%s)", c.Unavailable)
		}
		return
	}
	c, at := r.Pap.Coverage, time.Unix(r.Iat, 0).UTC()
	until := at.Add(time.Second) // iat is truncated to the second
	s, ok := v.snapshots[c.Snapshot]
	if !ok {
		// The scope's snapshots on both sides of the receipt's entry show which
		// one was current: a claim naming another is forged (T-089).
		if cur, ok := v.currentAt(c.Scope, seq, recorded); ok {
			v.r.add("receipt.coverage", subject, Failed, "the claimed snapshot %s is not the scope's snapshot %s current at decision time (seq %d)",
				truncate(c.Snapshot), truncate(cur.body.Snapshot), cur.seq)
			return
		}
		v.r.add("receipt.coverage", subject, NotAvailable, "the claimed snapshot %s is not in this bundle", truncate(c.Snapshot))
		return
	}
	fail := func(format string, args ...any) { v.r.add("receipt.coverage", subject, Failed, format, args...) }
	x, y := slices.Sorted(slices.Values(c.Exclusions)), slices.Sorted(slices.Values(s.body.Exclusions))
	switch {
	case c.Scope != s.body.Scope || c.Scope.Agent != r.Pap.Identity.Agent || c.Scope.Connection != r.Pap.Connection:
		fail("the claim's scope is not its snapshot's or its receipt's")
		return
	case c.SnapshotState != s.body.State:
		fail("the claim says its snapshot was %s; the entry at seq %d says %s", truncate(c.SnapshotState), s.seq, truncate(s.body.State))
		return
	case !slices.Equal(x, y):
		fail("the claim lists other exclusions than its snapshot")
		return
	case !s.computed.Before(until):
		fail("the snapshot was computed after the decision")
		return
	}
	expires, errExp := time.Parse(tsLayout, s.body.ExpiresAt)
	expired := errExp == nil && !at.Before(expires)
	changed := v.changed(s, until)
	if !c.Lapsed {
		switch {
		case c.State != s.body.State:
			fail("a claim that did not lapse says %s, its snapshot %s", truncate(c.State), truncate(s.body.State))
		case expired:
			fail("the snapshot had expired at the decision")
		case changed != "":
			fail("a %s change to the scope came between the snapshot and the decision", truncate(changed))
		case v.newer(s, at):
			fail("a newer snapshot of the scope was current at decision time")
		default:
			v.r.add("receipt.coverage", subject, Passed, "%s from the snapshot at seq %d", c.State, s.seq)
		}
		return
	}
	switch {
	case c.State == "ENFORCED" || coverageStates[c.State] == 0:
		fail("a lapsed claim says %s", truncate(c.State))
	case c.Reason == "expired" && errExp == nil && !expired:
		fail("the claim says the snapshot expired; it was valid until %s", s.body.ExpiresAt)
	case c.Reason == "expired" && errExp != nil:
		fail("the claim says the snapshot expired; it had no expiry")
	case c.Reason != "expired" && !v.changedBy(s, until, c.Reason):
		v.r.add("receipt.coverage", subject, NotAvailable, "no %s change to the scope before the decision is in this bundle",
			truncate(c.Reason))
	default:
		v.r.add("receipt.coverage", subject, Passed, "%s, lapsed (%s) from the snapshot at seq %d", c.State, truncate(c.Reason), s.seq)
	}
}

// currentAt returns the scope's snapshot current at the receipt's ledger
// entry (seq): the latest of the scope's entries before it, when the bundle
// also holds the scope's next entry after it, so that no entry of the scope
// lies between them. ok is false when the bundle cannot tell.
func (v *verifier) currentAt(sc scope, seq int64, recorded bool) (cur snapshotEntry, ok bool) {
	if !recorded {
		return cur, false
	}
	var before, after bool
	var next snapshotEntry
	for _, s := range v.snapshots {
		switch {
		case s.body.Scope != sc:
		case s.seq < seq && (!before || s.seq > cur.seq):
			cur, before = s, true
		case s.seq > seq && (!after || s.seq < next.seq):
			next, after = s, true
		}
	}
	return cur, before && after
}

// coverageStates are the states a claim may say.
var coverageStates = map[string]int{"UNKNOWN": 1, "OBSERVE_ONLY": 2, "PARTIAL": 3, "ENFORCED": 4}

// changed returns the kind of an invalidation of s's scope between its
// computation and until, or "".
func (v *verifier) changed(s snapshotEntry, until time.Time) string {
	for _, i := range v.invalidations {
		if v.ofScope(i, s) && !i.occurred.Before(s.computed) && i.occurred.Before(until) {
			return i.Kind
		}
	}
	return ""
}

// changedBy reports whether an invalidation of kind kind of s's scope came
// between its computation and until.
func (v *verifier) changedBy(s snapshotEntry, until time.Time, kind string) bool {
	return slices.ContainsFunc(v.invalidations, func(i invalidationEntry) bool {
		return i.Kind == kind && v.ofScope(i, s) && !i.occurred.Before(s.computed) && i.occurred.Before(until)
	})
}

func (v *verifier) ofScope(i invalidationEntry, s snapshotEntry) bool {
	return i.Connection == s.body.Scope.Connection && (i.Agent == "" || i.Agent == s.body.Scope.Agent)
}

// newer reports whether the bundle holds a later snapshot of s's scope
// computed before time at.
func (v *verifier) newer(s snapshotEntry, at time.Time) bool {
	for _, o := range v.snapshots {
		if o.body.Scope == s.body.Scope && o.seq > s.seq && !o.computed.After(at) {
			return true
		}
	}
	return false
}
