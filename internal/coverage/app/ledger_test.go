// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle/bundletest"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func mustID(t *testing.T, s string) ids.UUID {
	t.Helper()
	id, err := ids.ParseUUID(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestHR217_CoverageLedgerBodiesNameIdsAsUUIDStrings: a snapshot's and an
// invalidation's ledger bodies name every id as its canonical UUID string
// (golden bodies), so that pclaw verify matches them with the receipts'
// claims: an ENFORCED claim on the snapshot passes, and so does a lapsed
// claim naming the invalidation.
func TestHR217_CoverageLedgerBodiesNameIdsAsUUIDStrings(t *testing.T) {
	agent, conn := mustID(t, "0199e2a4-1111-7000-8000-00000000000a"), mustID(t, "0199e2a4-1111-7000-8000-00000000000c")
	snap, excl := mustID(t, "0199e2a4-1111-7000-8000-000000000005"), mustID(t, "0199e2a4-1111-7000-8000-0000000000e1")
	closure, inv := mustID(t, "0199e2a4-1111-7000-8000-0000000000c1"), mustID(t, "0199e2a4-1111-7000-8000-0000000000f1")
	at := func(d time.Duration) string { return evdomain.Timestamp(bundletest.IssuedAt.Add(d)) }
	s := Snapshot{
		V: 1, ID: snap.String(), Agent: agent.String(), Connection: conn.String(), Operation: "github.pulls.merge", State: "ENFORCED",
		Routes: []SnapshotRoute{{Kind: "sandbox", Status: "closed", Closure: closure.String()}}, Closure: closure.String(),
		ExpiresAt: at(time.Hour), Exclusions: []string{excl.String()}, ComputedAt: at(-time.Hour),
	}
	entry, err := entryOf(s)
	if err != nil {
		t.Fatal(err)
	}
	// routes_digest is the SHA-256 of the canonical routes of the record,
	// ids as UUID strings, so anyone holding them recomputes it.
	const routes = `{"routes":[{"closure":"0199e2a4-1111-7000-8000-0000000000c1","kind":"sandbox","status":"closed"}]}`
	sum := sha256.Sum256([]byte(routes))
	golden := `{"closure":"0199e2a4-1111-7000-8000-0000000000c1","computed_at":"2026-10-10T07:30:00.000000Z",` +
		`"exclusions":["0199e2a4-1111-7000-8000-0000000000e1"],"expires_at":"2026-10-10T09:30:00.000000Z",` +
		`"routes_digest":"sha256:` + hex.EncodeToString(sum[:]) + `","scope":{"agent":"0199e2a4-1111-7000-8000-00000000000a",` +
		`"connection":"0199e2a4-1111-7000-8000-00000000000c","operation":"github.pulls.merge"},` +
		`"snapshot":"0199e2a4-1111-7000-8000-000000000005","state":"ENFORCED","v":1}`
	if string(entry) != golden {
		t.Fatalf("snapshot entry\n%s\nwant\n%s", entry, golden)
	}
	agentID := agent
	invalidation, err := evdomain.CanonicalBody(InvalidationEntry{
		V: 1, ID: inv.String(), Connection: conn.String(), Agent: optString(&agentID), Kind: "credential",
		OccurredAt: at(-30 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	const goldenInvalidation = `{"agent":"0199e2a4-1111-7000-8000-00000000000a","connection":"0199e2a4-1111-7000-8000-00000000000c",` +
		`"id":"0199e2a4-1111-7000-8000-0000000000f1","kind":"credential","occurred_at":"2026-10-10T08:00:00.000000Z","v":1}`
	if string(invalidation) != goldenInvalidation {
		t.Fatalf("invalidation entry\n%s\nwant\n%s", invalidation, goldenInvalidation)
	}

	sc := bundletest.Scope{Agent: agent.String(), Connection: conn.String(), Operation: s.Operation}
	claim := bundletest.Claim{
		V: 1, State: "ENFORCED", Snapshot: snap.String(), Scope: sc, SnapshotState: "ENFORCED",
		Exclusions: []string{excl.String()}, ExpiresAt: s.ExpiresAt,
	}
	for name, c := range map[string]struct {
		withInvalidation bool
		claim            bundletest.Claim
	}{
		"ENFORCED": {false, claim},
		"lapsed by a change": {true, func() bundletest.Claim {
			c := claim
			c.State, c.Lapsed, c.Reason = "PARTIAL", true, "credential"
			return c
		}()},
	} {
		t.Run(name, func(t *testing.T) {
			iss := bundletest.NewIssuer(t)
			iss.Append(1)
			iss.AppendCoverageBody(bundle.SnapshotKind, entry)
			if c.withInvalidation {
				iss.AppendCoverageBody(bundle.InvalidationKind, invalidation)
			}
			iss.AppendClaim(c.claim, agent.String(), conn.String())
			iss.Checkpoint()
			trust, err := bundle.ParseTrust(iss.Trust())
			if err != nil {
				t.Fatal(err)
			}
			r := bundle.Verify(iss.Bundle(), bundle.Options{Trust: trust})
			n := 0
			for _, ch := range r.Checks {
				if ch.Name == "receipt.coverage" {
					n++
					if ch.Status != bundle.Passed {
						t.Fatalf("receipt.coverage %s: %s\n%s", ch.Status, ch.Detail, r.Text())
					}
				}
			}
			if n != 1 || r.Failed() {
				t.Fatalf("checks:\n%s", r.Text())
			}
		})
	}
}
