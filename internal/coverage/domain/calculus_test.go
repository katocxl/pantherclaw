// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var t0 = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

// enforced is evidence that computes ENFORCED: HTTP traffic in enforce
// mode and a current passing closure.
func enforced() domain.Evidence {
	scope := domain.Scope{Agent: ids.NewV7(), Connection: ids.NewV7(), Operation: "github.pulls.merge"}
	conn := domain.Connection{
		Kind: "http", State: "ACTIVE", Revision: 3, Gateway: ids.NewV7(), PackageVersion: ids.NewV7(), RouteMode: "enforce",
	}
	return domain.Evidence{
		Scope: scope, Now: t0, Connection: conn,
		Traffic: []domain.Traffic{{Channel: domain.ChannelHTTP, Mode: "enforce"}},
		Closure: &domain.ClosureRecord{
			ID: ids.NewV7(), Agent: scope.Agent, Connection: scope.Connection, Probes: passingProbes(),
			SessionStartedAt: t0.Add(-2 * time.Hour), ObservedAt: t0.Add(-time.Hour), ExpiresAt: t0.Add(23 * time.Hour),
			Revision: conn.Revision, Gateway: conn.Gateway, PackageVersion: conn.PackageVersion,
		},
	}
}

func TestEnforcedNeedsAndCarriesItsClosure(t *testing.T) {
	e := enforced()
	r := domain.Compute(e)
	if r.State != domain.Enforced || len(r.Reasons) != 0 {
		t.Fatalf("baseline: %v %v", r.State, r.Reasons)
	}
	if r.Closure == nil || *r.Closure != e.Closure.ID || r.ExpiresAt == nil || !r.ExpiresAt.Equal(e.Closure.ExpiresAt) {
		t.Fatalf("ENFORCED without its closure and expiry: %+v", r)
	}
	for _, rt := range r.Routes {
		if rt.Kind != domain.KindChannel && rt.Kind != domain.KindTargetSide && rt.Status != domain.StatusClosed {
			t.Errorf("%s is %s under a passing closure", rt.Kind, rt.Status)
		}
	}
	// An exclusion or a lapse asks for a reassessment; it does not make the
	// closure stale.
	for _, k := range []domain.InvalidationKind{domain.InvExclusion, domain.InvEvidenceExpired} {
		e.Changes = append(e.Changes, domain.Change{ID: ids.NewV7(), Kind: k, OccurredAt: t0})
	}
	if r := domain.Compute(e); r.State != domain.Enforced {
		t.Errorf("after an exclusion and a lapse: %v %v", r.State, r.Reasons)
	}
}

// mutate weakens or varies the baseline evidence in one or more ways and
// reports which, so properties can name the ones that must lower the state.
type mutation struct {
	settingsOnly                 bool // only connection settings changed, no evidence
	cooperative, opaque, monitor bool
	noTraffic, failedControl     bool
	foreignClosure, expired      bool
	changed, rebound             bool
}

func drawEvidence(t *rapid.T) (domain.Evidence, mutation) {
	e, m := enforced(), mutation{}
	e.Now = e.Now.Add(time.Duration(rapid.Int64Range(-int64(time.Hour), int64(48*time.Hour)).Draw(t, "now")))
	m.expired = !e.Now.Before(e.Closure.ExpiresAt)
	switch rapid.IntRange(0, 4).Draw(t, "channel") {
	case 1:
		e.Traffic, m.cooperative = append(e.Traffic, domain.Traffic{Channel: domain.ChannelSDK, Mode: "enforce"}), true
	case 2:
		e.Traffic, m.cooperative = append(e.Traffic, domain.Traffic{Channel: domain.ChannelHook, Mode: "enforce"}), true
	case 3:
		e.Connection.Kind, m.opaque = "mcp", len(e.Traffic) > 0
	case 4:
		e.Traffic = append(e.Traffic, domain.Traffic{Channel: domain.ChannelMCP, Mode: "monitor"})
		m.monitor = true
	}
	if rapid.Bool().Draw(t, "monitorMode") {
		e.Connection.RouteMode, m.monitor = "monitor", true
	}
	if rapid.Bool().Draw(t, "failedControl") {
		i := rapid.IntRange(0, len(e.Closure.Probes)-1).Draw(t, "probe")
		e.Closure.Probes = slices.Clone(e.Closure.Probes)
		e.Closure.Probes[i].Observed = rapid.SampledFrom([]string{domain.ProbeErr, "reachable", "blocked"}).Draw(t, "observed")
		m.failedControl = !e.Closure.Probes[i].Passed()
	}
	if rapid.Bool().Draw(t, "foreign") {
		c := *e.Closure
		c.Agent = ids.NewV7()
		e.Closure, m.foreignClosure = &c, true
	}
	if rapid.Bool().Draw(t, "changed") {
		kind := rapid.SampledFrom(domain.InvalidationKinds).Draw(t, "kind")
		at := e.Closure.SessionStartedAt.Add(time.Duration(rapid.Int64Range(1, int64(4*time.Hour)).Draw(t, "after")))
		e.Changes, m.changed = append(e.Changes, domain.Change{ID: ids.NewV7(), Kind: kind, OccurredAt: at}), true
	}
	if rapid.Bool().Draw(t, "rebound") {
		e.Connection.Revision++
		m.rebound = true
	}
	if rapid.Bool().Draw(t, "noTraffic") {
		e.Traffic, m.noTraffic = nil, true
	}
	return e, m
}

// TestHR210_StatesComeOnlyFromEvidence: without observed traffic a scope is
// UNKNOWN whatever its settings (F460); ENFORCED never holds unless every
// piece of evidence is present and current.
func TestHR210_StatesComeOnlyFromEvidence(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		e, m := drawEvidence(t)
		if rapid.Bool().Draw(t, "settingsOnly") {
			e.Traffic, e.Closure, e.Routes = nil, nil, nil
			e.Connection.Kind = rapid.SampledFrom([]string{"http", "mcp", "local"}).Draw(t, "kind")
			e.Connection.RouteMode = rapid.SampledFrom([]string{"monitor", "enforce"}).Draw(t, "mode")
			m.settingsOnly = true
		}
		r := domain.Compute(e)
		if (m.settingsOnly || m.noTraffic) && r.State != domain.Unknown {
			t.Fatalf("no observed traffic gave %v", r.State)
		}
		weakened := m.settingsOnly || m.noTraffic || m.cooperative || m.opaque || m.monitor || m.failedControl ||
			m.foreignClosure || m.expired || m.changed || m.rebound
		if weakened && r.State == domain.Enforced {
			t.Fatalf("ENFORCED despite %+v", m)
		}
		if !weakened && r.State != domain.Enforced {
			t.Fatalf("complete evidence gave %v %v", r.State, r.Reasons)
		}
		if (r.State == domain.Enforced) != (r.ExpiresAt != nil && r.Closure != nil) {
			t.Fatalf("state %v with expiry %v and closure %v", r.State, r.ExpiresAt, r.Closure)
		}
	})
}

// TestHR210_MonitorModeIsObserveOnly: with traffic and the route in monitor
// mode the state is exactly OBSERVE_ONLY, whatever closure exists.
func TestHR210_MonitorModeIsObserveOnly(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		e, m := drawEvidence(t)
		e.Connection.RouteMode = "monitor"
		if r := domain.Compute(e); !m.noTraffic && r.State != domain.ObserveOnly {
			t.Fatalf("monitor mode gave %v (%+v)", r.State, m)
		}
	})
}

// TestHR024_CooperativeChannelsAreCappedAtPartial: an SDK or hook route
// keeps the scope at PARTIAL at most, unless current closure evidence shows
// the target refuses calls without an action token.
func TestHR024_CooperativeChannelsAreCappedAtPartial(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		e := enforced()
		ch := rapid.SampledFrom([]domain.Channel{domain.ChannelSDK, domain.ChannelHook}).Draw(t, "channel")
		e.Traffic = append(e.Traffic, domain.Traffic{Channel: ch, Mode: "enforce"})
		verified := rapid.Bool().Draw(t, "verified")
		if verified {
			e.Closure.Probes = append(slices.Clone(e.Closure.Probes), domain.ProbeResult{
				Name: domain.ProbeTargetRequiresToken, Role: domain.RoleProbe, Expect: domain.Blocked, Observed: domain.Blocked,
			})
		}
		r := domain.Compute(e)
		if !verified && (r.State > domain.Partial || !slices.Contains(r.Reasons, domain.ReasonCooperative)) {
			t.Fatalf("cooperative %s gave %v %v", ch, r.State, r.Reasons)
		}
		if verified && r.State != domain.Enforced {
			t.Fatalf("a target verifying action tokens gave %v %v", r.State, r.Reasons)
		}
	})
}

// TestHR086_OpaqueMCPRoutesAreCappedAtPartial: a route through an MCP
// server is PARTIAL at most unless closure evidence shows its egress goes
// only through the edge.
func TestHR086_OpaqueMCPRoutesAreCappedAtPartial(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		e := enforced()
		e.Connection.Kind = "mcp"
		e.Traffic = []domain.Traffic{{Channel: domain.ChannelMCP, Mode: "enforce"}}
		mediated := rapid.Bool().Draw(t, "mediated")
		if mediated {
			e.Closure.Probes = append(slices.Clone(e.Closure.Probes), domain.ProbeResult{
				Name: domain.ProbeConnectorEgress, Role: domain.RolePositiveControl, Expect: domain.Reachable,
				Observed: domain.Reachable,
			})
		}
		r := domain.Compute(e)
		if !mediated && (r.State > domain.Partial || !slices.Contains(r.Reasons, domain.ReasonOpaqueMCP)) {
			t.Fatalf("opaque MCP gave %v %v", r.State, r.Reasons)
		}
		if mediated && r.State != domain.Enforced {
			t.Fatalf("mediated MCP egress gave %v %v", r.State, r.Reasons)
		}
	})
}

// TestHR211_EnforcedReadsPartialOnceExpiredOrChanged: a computed ENFORCED
// reads PARTIAL from its expiry on, or after any change; other states read
// as computed.
func TestHR211_EnforcedReadsPartialOnceExpiredOrChanged(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		r := domain.Compute(enforced())
		at := t0.Add(time.Duration(rapid.Int64Range(0, int64(48*time.Hour)).Draw(t, "at")))
		changes := rapid.IntRange(0, 2).Draw(t, "changes")
		got, why := domain.ReadAt(r.State, r.ExpiresAt, changes, at)
		fresh := at.Before(*r.ExpiresAt) && changes == 0
		if fresh != (got == domain.Enforced) || (!fresh && (got != domain.Partial || why == "")) {
			t.Fatalf("at %v with %d changes: %v %q", at, changes, got, why)
		}
		s := rapid.SampledFrom([]domain.State{domain.Unknown, domain.ObserveOnly, domain.Partial}).Draw(t, "other")
		if got, _ := domain.ReadAt(s, nil, changes, at); got != s {
			t.Fatalf("%v read as %v", s, got)
		}
	})
}

// TestHR212_ExclusionsNeverRaiseAState: adding exclusions changes route
// statuses and the excluded flag, never the state.
func TestHR212_ExclusionsNeverRaiseAState(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		e, _ := drawEvidence(t)
		before := domain.Compute(e)
		kinds := append([]domain.RouteKind{""}, domain.EquivalentKinds...)
		for range rapid.IntRange(1, 4).Draw(t, "n") {
			e.Exclusions = append(e.Exclusions, domain.Exclusion{ID: ids.NewV7(), Kind: rapid.SampledFrom(kinds).Draw(t, "kind")})
		}
		after := domain.Compute(e)
		if after.State != before.State {
			t.Fatalf("exclusions moved %v to %v", before.State, after.State)
		}
		for _, rt := range after.Routes {
			if rt.Status == domain.StatusExcluded && slices.Contains(domain.ContainmentKinds, rt.Kind) && after.State == domain.Enforced {
				t.Fatalf("ENFORCED with %s excluded", rt.Kind)
			}
		}
	})
}

// TestUnobservedRoutesAreNotAbsent: every equivalent route kind appears in a
// record; one no source showed is "not observed", never left out (F450).
func TestUnobservedRoutesAreNotAbsent(t *testing.T) {
	e := enforced()
	e.Closure = nil
	e.Routes = []domain.Route{{ID: ids.NewV7(), Kind: domain.KindGitSSH, Locator: "ssh://github.com", Observation: "observed"}}
	r := domain.Compute(e)
	got := map[domain.RouteKind]domain.RouteStatus{}
	for _, rt := range r.Routes {
		got[rt.Kind] = rt.Status
	}
	for _, k := range domain.EquivalentKinds {
		want := domain.StatusNotObserved
		if k == domain.KindGitSSH {
			want = domain.StatusPossible
		}
		if got[k] != want {
			t.Errorf("%s: %q, want %q", k, got[k], want)
		}
	}
	if r.State != domain.Partial || !slices.Contains(r.Reasons, domain.ReasonNoClosure) {
		t.Errorf("no closure: %v %v", r.State, r.Reasons)
	}
}
