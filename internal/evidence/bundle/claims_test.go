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

// TestHR217_CoverageClaimsAreCheckedAgainstTheirSnapshot: a receipt's
// coverage claim passes only against its snapshot's verified entry, with
// the claimed digest and scope, a state no stronger than the snapshot's,
// an ENFORCED claim inside the snapshot's validity and no newer snapshot
// current at decision time; a claimed snapshot missing from the bundle is
// not available, and a receipt without a claim has no such check.
func TestHR217_CoverageClaimsAreCheckedAgainstTheirSnapshot(t *testing.T) {
	agent, conn, op := ids.NewV7().String(), ids.NewV7().String(), "github.pulls.merge"
	before := domain.Timestamp(bundletest.IssuedAt.Add(-time.Hour))
	snapshot := func(state, expires string) bundletest.Snapshot {
		return bundletest.Snapshot{
			ID: ids.NewV7().String(), Agent: agent, Connection: conn, Operation: op, State: state,
			ExpiresAt: expires, ComputedAt: before,
		}
	}
	later := domain.Timestamp(bundletest.IssuedAt.Add(time.Hour))
	past := domain.Timestamp(bundletest.IssuedAt.Add(-time.Minute))
	cases := []struct {
		name  string
		build func(i *bundletest.Issuer)
		want  bundle.Status
	}{
		{"an ENFORCED claim inside its snapshot's validity", func(i *bundletest.Issuer) {
			s := snapshot("ENFORCED", later)
			i.AppendClaim(bundletest.Claim{State: "ENFORCED", Snapshot: s.ID, Digest: i.AppendSnapshot(s), Agent: agent, Connection: conn, Operation: op}, agent, conn)
		}, bundle.Passed},
		{"a weaker claim than its snapshot", func(i *bundletest.Issuer) {
			s := snapshot("ENFORCED", later)
			i.AppendClaim(bundletest.Claim{State: "PARTIAL", Snapshot: s.ID, Digest: i.AppendSnapshot(s), Agent: agent, Connection: conn, Operation: op}, agent, conn)
		}, bundle.Passed},
		{"a stronger claim than its snapshot", func(i *bundletest.Issuer) {
			s := snapshot("PARTIAL", "")
			i.AppendClaim(bundletest.Claim{State: "ENFORCED", Snapshot: s.ID, Digest: i.AppendSnapshot(s), Agent: agent, Connection: conn, Operation: op}, agent, conn)
		}, bundle.Failed},
		{"ENFORCED after the snapshot expired", func(i *bundletest.Issuer) {
			s := snapshot("ENFORCED", past)
			i.AppendClaim(bundletest.Claim{State: "ENFORCED", Snapshot: s.ID, Digest: i.AppendSnapshot(s), Agent: agent, Connection: conn, Operation: op}, agent, conn)
		}, bundle.Failed},
		{"another digest", func(i *bundletest.Issuer) {
			s := snapshot("ENFORCED", later)
			i.AppendSnapshot(s)
			i.AppendClaim(bundletest.Claim{State: "ENFORCED", Snapshot: s.ID, Digest: "sha256:00", Agent: agent, Connection: conn, Operation: op}, agent, conn)
		}, bundle.Failed},
		{"another agent's snapshot", func(i *bundletest.Issuer) {
			s := snapshot("ENFORCED", later)
			s.Agent = ids.NewV7().String()
			i.AppendClaim(bundletest.Claim{State: "ENFORCED", Snapshot: s.ID, Digest: i.AppendSnapshot(s), Agent: agent, Connection: conn, Operation: op}, agent, conn)
		}, bundle.Failed},
		{"a receipt of another connection", func(i *bundletest.Issuer) {
			s := snapshot("ENFORCED", later)
			i.AppendClaim(bundletest.Claim{State: "ENFORCED", Snapshot: s.ID, Digest: i.AppendSnapshot(s), Agent: agent, Connection: conn, Operation: op}, agent, ids.NewV7().String())
		}, bundle.Failed},
		{"a newer snapshot was current", func(i *bundletest.Issuer) {
			s := snapshot("ENFORCED", later)
			digest := i.AppendSnapshot(s)
			n := snapshot("PARTIAL", "")
			n.ComputedAt = domain.Timestamp(bundletest.IssuedAt.Add(-time.Minute))
			i.AppendSnapshot(n)
			i.AppendClaim(bundletest.Claim{State: "ENFORCED", Snapshot: s.ID, Digest: digest, Agent: agent, Connection: conn, Operation: op}, agent, conn)
		}, bundle.Failed},
		{"a snapshot not in the bundle", func(i *bundletest.Issuer) {
			i.AppendClaim(bundletest.Claim{State: "ENFORCED", Snapshot: ids.NewV7().String(), Digest: "sha256:00", Agent: agent, Connection: conn, Operation: op}, agent, conn)
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
