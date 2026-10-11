// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"time"
)

// SnapshotKind is the ledger kind of a coverage snapshot (G0 M9, HR-217).
const SnapshotKind = "coverage.snapshot"

// coverageStates orders the coverage states: a claim may be weaker than
// its snapshot, never stronger.
var coverageStates = map[string]int{"UNKNOWN": 1, "OBSERVE_ONLY": 2, "PARTIAL": 3, "ENFORCED": 4}

// snapshotEntry is a verified coverage snapshot entry of the bundle.
type snapshotEntry struct {
	seq    int64
	digest string
	body   struct {
		ID         string `json:"id"`
		Agent      string `json:"agent"`
		Connection string `json:"connection"`
		Operation  string `json:"operation"`
		State      string `json:"state"`
		ExpiresAt  string `json:"expires_at"`
		ComputedAt string `json:"computed_at"`
	}
}

// noteSnapshot keeps a coverage snapshot entry whose hash verified.
func (v *verifier) noteSnapshot(e *Entry, body jsontext.Value) {
	s := snapshotEntry{seq: e.Seq}
	if json.Unmarshal(body, &s.body) != nil || s.body.ID == "" {
		return
	}
	sum := sha256.Sum256(body)
	s.digest = "sha256:" + hex.EncodeToString(sum[:])
	v.snapshots[s.body.ID] = s
}

// coverage checks a decision receipt's coverage claim against its
// snapshot's entry: the entry is in the bundle and verified, its digest is
// the claimed one, its scope is the claim's and the receipt's, the claimed
// state is not stronger than the snapshot's, and an ENFORCED claim was
// made inside the snapshot's validity.
func (v *verifier) coverage(subject string, payload []byte) {
	var r struct {
		Iat int64 `json:"iat"`
		Pap struct {
			Connection string `json:"connection"`
			Identity   struct {
				Agent string `json:"agent"`
			} `json:"identity"`
			Coverage *struct {
				State      string `json:"state"`
				Snapshot   string `json:"snapshot"`
				Digest     string `json:"digest"`
				Agent      string `json:"agent"`
				Connection string `json:"connection"`
				Operation  string `json:"operation"`
			} `json:"coverage"`
		} `json:"pap"`
	}
	if json.Unmarshal(payload, &r) != nil || r.Pap.Coverage == nil {
		return
	}
	c := r.Pap.Coverage
	s, ok := v.snapshots[c.Snapshot]
	at := time.Unix(r.Iat, 0).UTC()
	expires, errExp := time.Parse(tsLayout, s.body.ExpiresAt)
	computed, errComp := time.Parse(tsLayout, s.body.ComputedAt)
	switch {
	case !ok:
		v.r.add("receipt.coverage", subject, NotAvailable, "the claimed snapshot %s is not in this bundle", truncate(c.Snapshot))
	case s.digest != c.Digest:
		v.r.add("receipt.coverage", subject, Failed, "the snapshot at seq %d does not have the claimed digest", s.seq)
	case c.Agent != s.body.Agent || c.Connection != s.body.Connection || c.Operation != s.body.Operation ||
		c.Agent != r.Pap.Identity.Agent || c.Connection != r.Pap.Connection:
		v.r.add("receipt.coverage", subject, Failed, "the claim's scope is not its snapshot's or its receipt's")
	case coverageStates[c.State] == 0 || coverageStates[c.State] > coverageStates[s.body.State]:
		v.r.add("receipt.coverage", subject, Failed, "the claim says %s, its snapshot %s", truncate(c.State), truncate(s.body.State))
	case errComp != nil || computed.After(at.Add(time.Second)):
		v.r.add("receipt.coverage", subject, Failed, "the snapshot was computed after the decision")
	case c.State == "ENFORCED" && (errExp != nil || !at.Before(expires)):
		v.r.add("receipt.coverage", subject, Failed, "ENFORCED claimed after the snapshot expired")
	case v.newer(s, at):
		v.r.add("receipt.coverage", subject, Failed, "a newer snapshot of the scope was current at decision time")
	default:
		v.r.add("receipt.coverage", subject, Passed, "%s from the snapshot at seq %d", c.State, s.seq)
	}
}

// newer reports whether the bundle holds a later snapshot of s's scope
// computed before time at.
func (v *verifier) newer(s snapshotEntry, at time.Time) bool {
	for _, o := range v.snapshots {
		if o.body.Agent != s.body.Agent || o.body.Connection != s.body.Connection || o.body.Operation != s.body.Operation ||
			o.seq <= s.seq {
			continue
		}
		if t, err := time.Parse(tsLayout, o.body.ComputedAt); err == nil && !t.After(at) {
			return true
		}
	}
	return false
}
