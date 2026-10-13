// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundle_test

import (
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle/bundletest"
	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR217_CoverageClaimsAreCheckedAgainstTheSnapshotLedger: a receipt's
// coverage claim passes only against its snapshot's verified entry, of the
// receipt's scope, with the claimed snapshot state and exclusions. One that
// did not lapse must hold the snapshot's state, unexpired, with no change
// and no newer snapshot before the decision; a lapsed one's reason must
// hold and its state is never ENFORCED. Missing entries are not available.
func TestHR217_CoverageClaimsAreCheckedAgainstTheSnapshotLedger(t *testing.T) {
	agent, conn := ids.NewV7().String(), ids.NewV7().String()
	sc := bundletest.Scope{Agent: agent, Connection: conn, Operation: "github.pulls.merge"}
	at := func(d time.Duration) string { return domain.Timestamp(bundletest.IssuedAt.Add(d)) }
	snapshot := func(state, expires string) bundletest.Snapshot {
		return bundletest.Snapshot{
			V: 1, Scope: sc, State: state, Snapshot: ids.NewV7().String(), ComputedAt: at(-time.Hour), ExpiresAt: expires,
			Exclusions: []string{}, RoutesDigest: "sha256:00",
		}
	}
	claimOf := func(s bundletest.Snapshot) bundletest.Claim {
		return bundletest.Claim{
			V: 1, State: s.State, Snapshot: s.Snapshot, Scope: sc, SnapshotState: s.State, Exclusions: s.Exclusions,
			ExpiresAt: s.ExpiresAt,
		}
	}
	change := func(kind string, d time.Duration) bundletest.Invalidation {
		return bundletest.Invalidation{V: 1, ID: ids.NewV7().String(), Connection: conn, Kind: kind, OccurredAt: at(d)}
	}
	cases := []struct {
		name  string
		build func(i *bundletest.Issuer)
		want  bundle.Status
	}{
		{"a current ENFORCED claim", func(i *bundletest.Issuer) {
			s := snapshot("ENFORCED", at(time.Hour))
			i.AppendSnapshot(s)
			i.AppendClaim(claimOf(s), agent, conn)
		}, bundle.Passed},
		{"a current claim with an exclusion", func(i *bundletest.Issuer) {
			s := snapshot("ENFORCED", at(time.Hour))
			s.Exclusions = []string{ids.NewV7().String()}
			i.AppendSnapshot(s)
			i.AppendClaim(claimOf(s), agent, conn)
		}, bundle.Passed},
		{"other exclusions", func(i *bundletest.Issuer) {
			s := snapshot("ENFORCED", at(time.Hour))
			i.AppendSnapshot(s)
			c := claimOf(s)
			c.Exclusions = []string{ids.NewV7().String()}
			i.AppendClaim(c, agent, conn)
		}, bundle.Failed},
		{"another snapshot state", func(i *bundletest.Issuer) {
			s := snapshot("PARTIAL", "")
			i.AppendSnapshot(s)
			c := claimOf(s)
			c.State, c.SnapshotState = "ENFORCED", "ENFORCED"
			i.AppendClaim(c, agent, conn)
		}, bundle.Failed},
		{"weaker than a snapshot that held", func(i *bundletest.Issuer) {
			s := snapshot("ENFORCED", at(time.Hour))
			i.AppendSnapshot(s)
			c := claimOf(s)
			c.State = "PARTIAL"
			i.AppendClaim(c, agent, conn)
		}, bundle.Failed},
		{"not lapsed after the expiry", func(i *bundletest.Issuer) {
			s := snapshot("ENFORCED", at(-time.Minute))
			i.AppendSnapshot(s)
			i.AppendClaim(claimOf(s), agent, conn)
		}, bundle.Failed},
		{"not lapsed after a change", func(i *bundletest.Issuer) {
			s := snapshot("ENFORCED", at(time.Hour))
			i.AppendSnapshot(s)
			i.AppendInvalidation(change("credential", -time.Minute))
			i.AppendClaim(claimOf(s), agent, conn)
		}, bundle.Failed},
		{"a change after the decision", func(i *bundletest.Issuer) {
			s := snapshot("ENFORCED", at(time.Hour))
			i.AppendSnapshot(s)
			i.AppendInvalidation(change("credential", time.Minute))
			i.AppendClaim(claimOf(s), agent, conn)
		}, bundle.Passed},
		{"a newer snapshot was current", func(i *bundletest.Issuer) {
			s := snapshot("ENFORCED", at(time.Hour))
			i.AppendSnapshot(s)
			n := snapshot("PARTIAL", "")
			n.ComputedAt = at(-time.Minute)
			i.AppendSnapshot(n)
			i.AppendClaim(claimOf(s), agent, conn)
		}, bundle.Failed},
		{"lapsed on its expiry", func(i *bundletest.Issuer) {
			s := snapshot("ENFORCED", at(-time.Minute))
			i.AppendSnapshot(s)
			c := claimOf(s)
			c.State, c.Lapsed, c.Reason = "PARTIAL", true, "expired"
			i.AppendClaim(c, agent, conn)
		}, bundle.Passed},
		{"lapsed on an expiry still ahead", func(i *bundletest.Issuer) {
			s := snapshot("ENFORCED", at(time.Hour))
			i.AppendSnapshot(s)
			c := claimOf(s)
			c.State, c.Lapsed, c.Reason = "PARTIAL", true, "expired"
			i.AppendClaim(c, agent, conn)
		}, bundle.Failed},
		{"lapsed on a change", func(i *bundletest.Issuer) {
			s := snapshot("ENFORCED", at(time.Hour))
			i.AppendSnapshot(s)
			i.AppendInvalidation(change("route_mode", -time.Minute))
			c := claimOf(s)
			c.State, c.Lapsed, c.Reason = "OBSERVE_ONLY", true, "route_mode"
			i.AppendClaim(c, agent, conn)
		}, bundle.Passed},
		{"lapsed and still ENFORCED", func(i *bundletest.Issuer) {
			s := snapshot("ENFORCED", at(-time.Minute))
			i.AppendSnapshot(s)
			c := claimOf(s)
			c.Lapsed, c.Reason = true, "expired"
			i.AppendClaim(c, agent, conn)
		}, bundle.Failed},
		{"lapsed on a change not in the bundle", func(i *bundletest.Issuer) {
			s := snapshot("ENFORCED", at(time.Hour))
			i.AppendSnapshot(s)
			c := claimOf(s)
			c.State, c.Lapsed, c.Reason = "PARTIAL", true, "gateway"
			i.AppendClaim(c, agent, conn)
		}, bundle.NotAvailable},
		{"another agent's snapshot", func(i *bundletest.Issuer) {
			s := snapshot("ENFORCED", at(time.Hour))
			s.Scope.Agent = ids.NewV7().String()
			i.AppendSnapshot(s)
			i.AppendClaim(claimOf(s), agent, conn)
		}, bundle.Failed},
		{"a receipt of another connection", func(i *bundletest.Issuer) {
			s := snapshot("ENFORCED", at(time.Hour))
			i.AppendSnapshot(s)
			i.AppendClaim(claimOf(s), agent, ids.NewV7().String())
		}, bundle.Failed},
		{"computed after the decision", func(i *bundletest.Issuer) {
			s := snapshot("PARTIAL", "")
			s.ComputedAt = at(time.Minute)
			i.AppendSnapshot(s)
			i.AppendClaim(claimOf(s), agent, conn)
		}, bundle.Failed},
		{"a snapshot not in the bundle", func(i *bundletest.Issuer) {
			i.AppendClaim(claimOf(snapshot("ENFORCED", at(time.Hour))), agent, conn)
		}, bundle.NotAvailable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			iss := bundletest.NewIssuer(t)
			iss.Append(1)
			c.build(iss)
			iss.Checkpoint()
			trust, err := bundle.ParseTrust(iss.Trust())
			if err != nil {
				t.Fatal(err)
			}
			r := bundle.Verify(iss.Bundle(), bundle.Options{Trust: trust})
			expect(t, r, "receipt.coverage", c.want)
			if c.want == bundle.Passed && count(r, "entry.link", bundle.Failed) > 0 {
				t.Fatalf("a link failed:\n%s", r.Text())
			}
		})
	}
}

// TestT089_AForgedCoverageClaimIsRejected: pclaw verify fails a receipt's
// coverage claim on a snapshot of another scope, ENFORCED after a change to
// the scope that came before the decision (lapsed or not), or a snapshot id
// that is not the scope's snapshot current at decision time when the bundle
// holds the scope's snapshots on both sides of the receipt. Without the
// next one the forged id is not available; an honest claim passes (HR-217,
// coordinator decision on T-089).
func TestT089_AForgedCoverageClaimIsRejected(t *testing.T) {
	agent, conn := ids.NewV7().String(), ids.NewV7().String()
	sc := bundletest.Scope{Agent: agent, Connection: conn, Operation: "github.pulls.merge"}
	at := func(d time.Duration) string { return domain.Timestamp(bundletest.IssuedAt.Add(d)) }
	enforced := func() bundletest.Snapshot {
		return bundletest.Snapshot{
			V: 1, Scope: sc, State: "ENFORCED", Snapshot: ids.NewV7().String(), ComputedAt: at(-time.Hour),
			ExpiresAt: at(time.Hour), Exclusions: []string{}, RoutesDigest: "sha256:00",
		}
	}
	claimOf := func(s bundletest.Snapshot) bundletest.Claim {
		return bundletest.Claim{
			V: 1, State: s.State, Snapshot: s.Snapshot, Scope: sc, SnapshotState: s.State, Exclusions: s.Exclusions,
			ExpiresAt: s.ExpiresAt,
		}
	}
	changed := bundletest.Invalidation{V: 1, ID: ids.NewV7().String(), Connection: conn, Kind: "gateway", OccurredAt: at(-time.Minute)}
	for name, build := range map[string]func(i *bundletest.Issuer){
		"a forged snapshot id, the neighbours present": func(i *bundletest.Issuer) {
			s := enforced()
			i.AppendSnapshot(s)
			c := claimOf(s)
			c.Snapshot = ids.NewV7().String()
			i.AppendClaim(c, agent, conn)
			n := enforced()
			n.ComputedAt = at(time.Minute)
			i.AppendSnapshot(n)
		},
		"a forged snapshot id, a partial bundle": func(i *bundletest.Issuer) {
			s := enforced()
			i.AppendSnapshot(s)
			c := claimOf(s)
			c.Snapshot = ids.NewV7().String()
			i.AppendClaim(c, agent, conn)
		},
		"an honest claim, the neighbours present": func(i *bundletest.Issuer) {
			s := enforced()
			i.AppendSnapshot(s)
			i.AppendClaim(claimOf(s), agent, conn)
			n := enforced()
			n.ComputedAt = at(time.Minute)
			i.AppendSnapshot(n)
		},
		"another scope's snapshot": func(i *bundletest.Issuer) {
			s := enforced()
			s.Scope.Operation = "github.contents.write"
			i.AppendSnapshot(s)
			i.AppendClaim(claimOf(s), agent, conn)
		},
		"ENFORCED after an invalidation": func(i *bundletest.Issuer) {
			s := enforced()
			i.AppendSnapshot(s)
			i.AppendInvalidation(changed)
			i.AppendClaim(claimOf(s), agent, conn)
		},
		"ENFORCED after an invalidation, claimed lapsed": func(i *bundletest.Issuer) {
			s := enforced()
			i.AppendSnapshot(s)
			i.AppendInvalidation(changed)
			c := claimOf(s)
			c.Lapsed, c.Reason = true, "gateway"
			i.AppendClaim(c, agent, conn)
		},
	} {
		t.Run(name, func(t *testing.T) {
			iss := bundletest.NewIssuer(t)
			iss.Append(1)
			build(iss)
			iss.Checkpoint()
			trust, err := bundle.ParseTrust(iss.Trust())
			if err != nil {
				t.Fatal(err)
			}
			r := bundle.Verify(iss.Bundle(), bundle.Options{Trust: trust})
			switch name {
			case "a forged snapshot id, a partial bundle":
				// Without the scope's next snapshot the bundle cannot tell.
				expect(t, r, "receipt.coverage", bundle.NotAvailable)
			case "an honest claim, the neighbours present":
				expect(t, r, "receipt.coverage", bundle.Passed)
			default:
				expect(t, r, "receipt.coverage", bundle.Failed)
			}
		})
	}
}
