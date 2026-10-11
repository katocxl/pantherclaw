// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package invariants_test

import (
	"testing"
	"time"

	"pgregory.net/rapid"

	coverage "github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// coverageProbes is a passing closure catalog: each probe blocked in the
// sandbox and reachable on the open control network, and the named
// controls and canary.
func coverageProbes() []coverage.ProbeResult {
	out := []coverage.ProbeResult{
		{Name: coverage.ProbeEdgeMediated, Role: coverage.RolePositiveControl, Expect: coverage.Reachable, Observed: coverage.Reachable},
		{Name: coverage.ProbeCanaryControl, Role: coverage.RolePositiveControl, Expect: coverage.Reachable, Observed: coverage.Reachable},
		{Name: coverage.ProbeEdgeUnmappedRefused, Role: coverage.RoleNegativeControl, Expect: coverage.Blocked, Observed: coverage.Blocked},
		{Name: coverage.ProbeExternalCanary, Role: coverage.RoleCanary, Expect: coverage.Blocked, Observed: coverage.Blocked},
	}
	for _, n := range []string{
		coverage.ProbeDNSExternal, coverage.ProbeDNSDockerResolver, coverage.ProbeIPv6, coverage.ProbeICMP,
		coverage.ProbeDirectHTTPS, coverage.ProbeMetadata, coverage.ProbeHostGateway, coverage.ProbeDirectSSH,
		coverage.ProbeSSHPush, coverage.ProbePATPush,
	} {
		out = append(out,
			coverage.ProbeResult{Name: n, Role: coverage.RoleProbe, Expect: coverage.Blocked, Observed: coverage.Blocked},
			coverage.ProbeResult{Name: n, Role: coverage.RolePositiveControl, Expect: coverage.Reachable, Observed: coverage.Reachable},
		)
	}
	return out
}

// TestINV10_CoverageIsScopedAndExpires (M9 part): a state belongs to one
// agent, connection and operation, and ENFORCED carries an expiry after
// which it lapses and reads at most PARTIAL. Closure evidence for another agent or connection
// never makes a scope ENFORCED, and ENFORCED never outlives its evidence.
func TestINV10_CoverageIsScopedAndExpires(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		now := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
		scope := coverage.Scope{Agent: ids.NewV7(), Connection: ids.NewV7(), Operation: "github.pulls.merge"}
		conn := coverage.Connection{
			Kind: "http", State: "ACTIVE", Revision: 1, Gateway: ids.NewV7(),
			PackageVersion: ids.NewV7(), AccessMode: coverage.AccessPantherClawHeld, RouteMode: "enforce",
		}
		closure := &coverage.ClosureRecord{
			ID: ids.NewV7(), Agent: scope.Agent, Connection: scope.Connection,
			Probes: coverageProbes(), SessionStartedAt: now.Add(-time.Hour), ObservedAt: now.Add(-time.Minute),
			ExpiresAt:    now.Add(24 * time.Hour),
			ConfigChecks: []coverage.ConfigCheck{{ID: coverage.CheckNoDockerSocket, OK: true}, {ID: coverage.CheckNoHostBind, OK: true}},
			Bound:        coverage.Bound{ConnectionRevision: 1, Gateway: conn.Gateway, PackageVersion: conn.PackageVersion},
		}
		other := rapid.IntRange(0, 2).Draw(t, "other")
		switch other {
		case 1:
			closure.Agent = ids.NewV7()
		case 2:
			closure.Connection = ids.NewV7()
		}
		r := coverage.Compute(coverage.Evidence{
			Scope: scope, Now: now, TTL: 24 * time.Hour, Connection: conn, Closure: closure,
			Routes: []coverage.Route{{ID: ids.NewV7(), Kind: coverage.KindChannel, Channel: coverage.ChannelHTTP, Observation: "observed"}},
		})
		if (other != 0) == (r.State == coverage.Enforced) {
			t.Fatalf("closure of scope %d: %v %v", other, r.State, r.Reasons)
		}
		if r.State != coverage.Enforced {
			return
		}
		later := now.Add(time.Duration(rapid.Int64Range(0, int64(72*time.Hour)).Draw(t, "later")))
		lapsed := coverage.Lapse(r.ExpiresAt, nil, later) != ""
		if later.Before(closure.ExpiresAt) == lapsed {
			t.Fatalf("read at %v: lapsed %v (expires %v)", later, lapsed, closure.ExpiresAt)
		}
	})
}
