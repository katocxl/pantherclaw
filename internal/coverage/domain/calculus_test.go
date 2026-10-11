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

// enforced is evidence that computes ENFORCED: an HTTP channel in enforce
// mode on PantherClaw-held access, a current passing closure, and the
// agent's one instance in the closure's sandbox session.
func enforced() domain.Evidence {
	scope := domain.Scope{Agent: ids.NewV7(), Connection: ids.NewV7(), Operation: "github.pulls.merge"}
	version := int32(2)
	conn := domain.Connection{
		Kind: "http", State: "ACTIVE", Revision: 3, Gateway: ids.NewV7(), PackageVersion: ids.NewV7(),
		CredentialVersion: &version, AccessMode: domain.AccessPantherClawHeld, RouteMode: "enforce",
	}
	session := ids.NewV7()
	return domain.Evidence{
		Scope: scope, Now: t0, TTL: 24 * time.Hour, Connection: conn,
		Routes: []domain.Route{{ID: ids.NewV7(), Kind: domain.KindChannel, Channel: domain.ChannelHTTP, Observation: "observed"}},
		Closure: &domain.ClosureRecord{
			ID: ids.NewV7(), Agent: scope.Agent, Connection: scope.Connection, SandboxSession: session,
			Probes: passingProbes(), ConfigChecks: passingChecks(),
			SessionStartedAt: t0.Add(-2 * time.Hour), ObservedAt: t0.Add(-time.Hour), ExpiresAt: t0.Add(23 * time.Hour),
			Bound: domain.Bound{
				ConnectionRevision: conn.Revision, Gateway: conn.Gateway, PackageVersion: conn.PackageVersion,
				CredentialVersion: &version,
			},
		},
		Instances: []domain.Instance{{ID: ids.NewV7(), SandboxSession: &session}},
	}
}

func channel(ch domain.Channel, observation string) domain.Route {
	return domain.Route{ID: ids.NewV7(), Kind: domain.KindChannel, Channel: ch, Observation: observation}
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
	// A new route, an exclusion or a lapse makes the scope be recomputed;
	// it does not make the closure stale.
	for _, k := range []domain.InvalidationKind{domain.InvRoute, domain.InvExclusion, domain.InvEvidenceExpired} {
		e.Changes = append(e.Changes, domain.Change{ID: ids.NewV7(), Kind: k, OccurredAt: t0})
	}
	if r := domain.Compute(e); r.State != domain.Enforced {
		t.Errorf("after a route, an exclusion and a lapse: %v %v", r.State, r.Reasons)
	}
	// A change at the very start of the session already invalidates it.
	e.Changes = []domain.Change{{ID: ids.NewV7(), Kind: domain.InvCredential, OccurredAt: e.Closure.SessionStartedAt}}
	if r := domain.Compute(e); r.State != domain.Partial || !slices.Contains(r.Reasons, "invalidated:credential") {
		t.Errorf("a change at the session start: %v %v", r.State, r.Reasons)
	}
}

// TestHR210_TheCalculusIsOrdered: no known route is UNKNOWN, known routes
// without a gateway channel in enforce mode are OBSERVE_ONLY, and anything
// short of ENFORCED with one is PARTIAL.
func TestHR210_TheCalculusIsOrdered(t *testing.T) {
	cases := map[string]struct {
		change func(*domain.Evidence)
		want   domain.State
		reason string
	}{
		"no route at all":   {func(e *domain.Evidence) { e.Routes = nil }, domain.Unknown, domain.ReasonNoRoutes},
		"only a hypothesis": {func(e *domain.Evidence) { e.Routes = []domain.Route{channel(domain.ChannelHTTP, "proposed")} }, domain.Unknown, domain.ReasonNoRoutes},
		"a found credential, no channel": {func(e *domain.Evidence) {
			e.Routes = []domain.Route{{ID: ids.NewV7(), Kind: domain.KindCredential, Observation: "observed"}}
		}, domain.ObserveOnly, domain.ReasonNoChannel},
		"monitor mode":             {func(e *domain.Evidence) { e.Connection.RouteMode = "monitor" }, domain.ObserveOnly, domain.ReasonMonitorMode},
		"a quarantined connection": {func(e *domain.Evidence) { e.Connection.State = "QUARANTINED" }, domain.ObserveOnly, domain.ReasonNotActive},
		"a declared channel only":  {func(e *domain.Evidence) { e.Routes = []domain.Route{channel(domain.ChannelHTTP, "declared")} }, domain.Enforced, ""},
		"no closure":               {func(e *domain.Evidence) { e.Closure = nil }, domain.Partial, domain.ReasonNoClosure},
		"agent-held access":        {func(e *domain.Evidence) { e.Connection.AccessMode = domain.AccessAgentHeld }, domain.Partial, domain.ReasonAgentHeld},
		"an unverified target":     {func(e *domain.Evidence) { e.Connection.AccessMode = domain.AccessTargetEnforced }, domain.Partial, domain.ReasonUnverified},
		"a verified read": {func(e *domain.Evidence) {
			at := t0.Add(-time.Hour)
			e.Connection.AccessMode, e.VerifiedAt, e.ReadOnly = domain.AccessTargetEnforced, &at, true
		}, domain.Enforced, ""},
		"a verified write": {func(e *domain.Evidence) {
			at := t0.Add(-time.Hour)
			e.Connection.AccessMode, e.VerifiedAt = domain.AccessTargetEnforced, &at
		}, domain.Partial, domain.ReasonWriteCapped},
		"a proposed channel": {func(e *domain.Evidence) { e.Routes = append(e.Routes, channel(domain.ChannelHook, "proposed")) }, domain.Partial, "route_not_closed:channel"},
		"a laptop instance": {func(e *domain.Evidence) {
			e.Instances = append(e.Instances, domain.Instance{ID: ids.NewV7()})
		}, domain.Partial, domain.ReasonInstance},
		"no instance at all": {func(e *domain.Evidence) { e.Instances = nil }, domain.Enforced, ""},
	}
	for name, c := range cases {
		e := enforced()
		c.change(&e)
		r := domain.Compute(e)
		if r.State != c.want || (c.reason != "" && !slices.Contains(r.Reasons, c.reason)) {
			t.Errorf("%s: %v %v, want %v with %q", name, r.State, r.Reasons, c.want, c.reason)
		}
	}
}

// mutation records the ways drawEvidence varied the baseline, so
// properties can name the ones that must lower the state.
type mutation struct {
	noRoutes                     bool
	cooperative, opaque, monitor bool
	agentHeld, unverified        bool
	failedResult, foreignClosure bool
	expired, changed, rebound    bool
	laptop, proposedChannel      bool
}

func (m mutation) weakened() bool {
	return m.noRoutes || m.cooperative || m.opaque || m.monitor || m.agentHeld || m.unverified || m.failedResult ||
		m.foreignClosure || m.expired || m.changed || m.rebound || m.laptop || m.proposedChannel
}

func drawEvidence(t *rapid.T) (domain.Evidence, mutation) {
	e, m := enforced(), mutation{}
	e.Now = e.Now.Add(time.Duration(rapid.Int64Range(-int64(time.Hour), int64(48*time.Hour)).Draw(t, "now")))
	m.expired = !e.Now.Before(e.Closure.ExpiresAt)
	switch rapid.IntRange(0, 5).Draw(t, "channel") {
	case 1:
		e.Routes, m.cooperative = append(e.Routes, channel(domain.ChannelSDK, "observed")), true
	case 2:
		e.Routes, m.cooperative = append(e.Routes, channel(domain.ChannelHook, "declared")), true
	case 3:
		e.Connection.Kind, m.opaque = rapid.SampledFrom([]string{"mcp", "mcp_container"}).Draw(t, "mcp"), true
	case 4:
		e.Routes = append(e.Routes, channel(domain.ChannelMCP, "observed"))
		e.Connection.RouteModes, m.monitor = map[domain.Channel]string{domain.ChannelMCP: "monitor"}, true
	case 5:
		e.Routes, m.proposedChannel = append(e.Routes, channel(domain.ChannelSDK, "proposed")), true
	}
	switch rapid.IntRange(0, 2).Draw(t, "access") {
	case 1:
		e.Connection.AccessMode, m.agentHeld = domain.AccessAgentHeld, true
	case 2:
		e.Connection.AccessMode, m.unverified = domain.AccessTargetEnforced, true
	}
	if rapid.Bool().Draw(t, "monitorMode") {
		e.Connection.RouteMode, m.monitor = "monitor", true
	}
	if rapid.Bool().Draw(t, "failedResult") {
		i := rapid.IntRange(0, len(e.Closure.Probes)-1).Draw(t, "probe")
		e.Closure.Probes = slices.Clone(e.Closure.Probes)
		e.Closure.Probes[i].Observed = rapid.SampledFrom([]string{domain.ProbeErr, "reachable", "blocked"}).Draw(t, "observed")
		m.failedResult = !e.Closure.Probes[i].Passed()
	}
	if rapid.Bool().Draw(t, "foreign") {
		c := *e.Closure
		c.Agent = ids.NewV7()
		e.Closure, m.foreignClosure = &c, true
	}
	if rapid.Bool().Draw(t, "changed") {
		kind := rapid.SampledFrom(domain.InvalidationKinds).Draw(t, "kind")
		at := e.Closure.SessionStartedAt.Add(time.Duration(rapid.Int64Range(0, int64(4*time.Hour)).Draw(t, "after")))
		e.Changes = append(e.Changes, domain.Change{ID: ids.NewV7(), Kind: kind, OccurredAt: at})
		m.changed = kind.Invalidates()
	}
	switch rapid.IntRange(0, 2).Draw(t, "rebound") {
	case 1:
		e.Connection.Revision++
		m.rebound = true
	case 2:
		e.Connection.CredentialVersion, m.rebound = nil, true
	}
	if rapid.Bool().Draw(t, "laptop") {
		e.Instances, m.laptop = append(e.Instances, domain.Instance{ID: ids.NewV7()}), true
	}
	if rapid.Bool().Draw(t, "noRoutes") {
		e.Routes, m.noRoutes = nil, true
	}
	return e, m
}

// TestHR210_StatesComeOnlyFromEvidence: without a known route a scope is
// UNKNOWN whatever its settings (F460); ENFORCED holds exactly when every
// piece of evidence is present and current, and carries its closure and
// expiry.
func TestHR210_StatesComeOnlyFromEvidence(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		e, m := drawEvidence(t)
		r := domain.Compute(e)
		if m.noRoutes && r.State != domain.Unknown {
			t.Fatalf("no known route gave %v", r.State)
		}
		if m.weakened() == (r.State == domain.Enforced) {
			t.Fatalf("%v %v with %+v", r.State, r.Reasons, m)
		}
		if (r.State == domain.Enforced) != (r.ExpiresAt != nil && r.Closure != nil) {
			t.Fatalf("state %v with expiry %v and closure %v", r.State, r.ExpiresAt, r.Closure)
		}
	})
}

// TestHR210_MoreRoutesOrLessEvidenceNeverRaiseTheState: adding a route
// that is not a gateway channel in enforce mode, to a scope with a known
// route, never raises its state; nor does removing the closure or the
// verifier test, letting time pass, invalidating, or admitting an instance
// outside the sandbox, nor does excluding a route or the whole scope
// (design decision 1).
func TestHR210_MoreRoutesOrLessEvidenceNeverRaiseTheState(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		e, m := drawEvidence(t)
		if m.noRoutes {
			return
		}
		if rapid.Bool().Draw(t, "verified") {
			at := e.Now.Add(-time.Hour)
			e.VerifiedAt = &at
		}
		e.ReadOnly = rapid.Bool().Draw(t, "readOnly")
		before := domain.Compute(e).State
		kinds := append([]domain.RouteKind{domain.KindChannel}, domain.EquivalentKinds...)
		switch rapid.IntRange(0, 6).Draw(t, "weaken") {
		case 0:
			k := rapid.SampledFrom(kinds).Draw(t, "kind")
			obs := rapid.SampledFrom([]string{"observed", "declared", "proposed"}).Draw(t, "observation")
			if k == domain.KindChannel {
				obs = "proposed"
			}
			e.Routes = append(e.Routes, domain.Route{ID: ids.NewV7(), Kind: k, Channel: domain.ChannelHook, Observation: obs})
		case 1:
			e.Closure = nil
		case 2:
			e.VerifiedAt = nil
		case 3:
			e.Now = e.Now.Add(time.Duration(rapid.Int64Range(0, int64(72*time.Hour)).Draw(t, "later")))
		case 4:
			if e.Closure != nil {
				e.Changes = append(e.Changes, domain.Change{
					ID: ids.NewV7(), Kind: domain.InvGateway, OccurredAt: e.Closure.SessionStartedAt.Add(time.Minute),
				})
			}
		case 5:
			e.Instances = append(e.Instances, domain.Instance{ID: ids.NewV7()})
		case 6:
			k := rapid.SampledFrom(append([]domain.RouteKind{""}, domain.EquivalentKinds...)).Draw(t, "excluded")
			e.Exclusions = append(e.Exclusions, domain.Exclusion{ID: ids.NewV7(), Kind: k})
		}
		if after := domain.Compute(e).State; after > before {
			t.Fatalf("%v rose to %v", before, after)
		}
	})
}

// TestHR024_CooperativeChannelsAreCappedAtPartial: an SDK or hook route
// keeps the scope at PARTIAL at most, unless a target-verifier test of the
// scope's own operation passed no longer than the ENFORCED lifetime ago
// and that operation reads; ENFORCED then expires with that test. A
// target_requires_token probe in the closure lifts nothing.
func TestHR024_CooperativeChannelsAreCappedAtPartial(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		e := enforced()
		ch := rapid.SampledFrom([]domain.Channel{domain.ChannelSDK, domain.ChannelHook}).Draw(t, "channel")
		e.Routes = append(e.Routes, channel(ch, "observed"))
		e.Closure.Probes = append(slices.Clone(e.Closure.Probes), domain.ProbeResult{
			Name: "target_requires_token", Role: domain.RoleProbe, Expect: domain.Blocked, Observed: domain.Blocked,
		})
		age := time.Duration(rapid.Int64Range(0, int64(48*time.Hour)).Draw(t, "age"))
		verified := rapid.Bool().Draw(t, "verified")
		if verified {
			at := t0.Add(-age)
			e.VerifiedAt = &at
		}
		e.ReadOnly = rapid.Bool().Draw(t, "readOnly")
		fresh := verified && age < e.TTL
		lifted := fresh && e.ReadOnly
		r := domain.Compute(e)
		want := domain.ReasonCooperative
		if fresh && !e.ReadOnly {
			want = domain.ReasonWriteCapped
		}
		if !lifted && (r.State > domain.Partial || !slices.Contains(r.Reasons, want)) {
			t.Fatalf("cooperative %s (verified %v, %v ago, read %v) gave %v %v", ch, verified, age, e.ReadOnly, r.State, r.Reasons)
		}
		if lifted && (r.State != domain.Enforced || r.ExpiresAt.After(e.VerifiedAt.Add(e.TTL))) {
			t.Fatalf("a read verified %v ago gave %v %v, expiring %v", age, r.State, r.Reasons, r.ExpiresAt)
		}
	})
}

// TestHR210_AVerifierPassNeverLiftsAWrite: in M9 a passing target-verifier
// test lifts the cooperative and target-enforced caps only for the read
// it tested (founder decision N15). Whatever else the evidence shows, a
// write operation with a passing test is PARTIAL at most when its route
// rests on that test, and says why.
func TestHR210_AVerifierPassNeverLiftsAWrite(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		e, _ := drawEvidence(t)
		rests := false
		if rapid.Bool().Draw(t, "cooperative") {
			ch := rapid.SampledFrom([]domain.Channel{domain.ChannelSDK, domain.ChannelHook}).Draw(t, "channel")
			e.Routes, rests = append(e.Routes, channel(ch, "observed")), true
		}
		if rapid.Bool().Draw(t, "targetEnforced") {
			e.Connection.AccessMode, rests = domain.AccessTargetEnforced, true
		}
		at := e.Now.Add(-time.Duration(rapid.Int64Range(0, int64(e.TTL)-1).Draw(t, "age")))
		e.VerifiedAt, e.ReadOnly = &at, false
		r := domain.Compute(e)
		if rests && r.State == domain.Enforced {
			t.Fatalf("a verified write was lifted: %v %v", r.State, r.Reasons)
		}
		e.ReadOnly = true
		if read := domain.Compute(e); rests && read.State < r.State {
			t.Fatalf("the same scope reading reads lower: %v, writing %v", read.State, r.State)
		}
	})
}

// TestHR086_OpaqueMCPRoutesAreCappedAtPartial: a route through a remote
// MCP server is PARTIAL at most; one through a connector container is
// lifted only when closure evidence shows its egress goes only through the
// edge.
func TestHR086_OpaqueMCPRoutesAreCappedAtPartial(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		e := enforced()
		e.Connection.Kind = rapid.SampledFrom([]string{"mcp", "mcp_container"}).Draw(t, "kind")
		e.Routes = []domain.Route{channel(domain.ChannelMCP, "observed")}
		mediated := rapid.Bool().Draw(t, "mediated")
		if mediated {
			e.Closure.Probes = append(slices.Clone(e.Closure.Probes), domain.ProbeResult{
				Name: domain.ProbeConnectorEgress, Role: domain.RolePositiveControl, Expect: domain.Reachable,
				Observed: domain.Reachable,
			})
		}
		lifted := mediated && e.Connection.Kind == "mcp_container"
		r := domain.Compute(e)
		if !lifted && (r.State > domain.Partial || !slices.Contains(r.Reasons, domain.ReasonOpaqueMCP)) {
			t.Fatalf("opaque %s gave %v %v", e.Connection.Kind, r.State, r.Reasons)
		}
		if lifted && r.State != domain.Enforced {
			t.Fatalf("mediated connector egress gave %v %v", r.State, r.Reasons)
		}
	})
}

// TestHR211_AStoredStateLapsesAndIsCappedAtPartial: a stored state holds
// until it expires or a change it did not see arrives; then it lapses with
// the reason, and the recomputed state reads at most PARTIAL, lower when
// the evidence is.
func TestHR211_AStoredStateLapsesAndIsCappedAtPartial(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		r := domain.Compute(enforced())
		at := t0.Add(time.Duration(rapid.Int64Range(0, int64(48*time.Hour)).Draw(t, "at")))
		var unseen []domain.Change
		if rapid.Bool().Draw(t, "changed") {
			kind := rapid.SampledFrom(domain.InvalidationKinds).Draw(t, "kind")
			unseen = append(unseen, domain.Change{ID: ids.NewV7(), Kind: kind, OccurredAt: t0})
		}
		why := domain.Lapse(r.ExpiresAt, unseen, at)
		expired := !at.Before(*r.ExpiresAt)
		switch {
		case expired && why != domain.LapseExpired:
			t.Fatalf("expired at %v: %q", at, why)
		case !expired && len(unseen) > 0 && why != string(unseen[0].Kind):
			t.Fatalf("after a %s change: %q", unseen[0].Kind, why)
		case !expired && len(unseen) == 0 && why != "":
			t.Fatalf("current at %v: %q", at, why)
		}
		s := rapid.SampledFrom([]domain.State{domain.Unknown, domain.ObserveOnly, domain.Partial, domain.Enforced}).Draw(t, "s")
		if c := domain.Cap(s); c > domain.Partial || (s <= domain.Partial && c != s) {
			t.Fatalf("%v capped to %v", s, c)
		}
	})
}

// TestHR212_ExclusionsNeverRaiseTheState: an exclusion, of a route kind
// or of the whole scope, never changes the state (design decision 1 as the
// founder decided: the alternative, where excluding a kind removed it from
// what ENFORCED needs closed, is rejected). An excluded kind the closure
// left open stays open, so the scope stays PARTIAL at most with the kind
// named, and every record lists the exclusions that applied.
func TestHR212_ExclusionsNeverRaiseTheState(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		e, _ := drawEvidence(t)
		// Drop a kind's probes so the closure leaves it open.
		open := rapid.SampledFrom([]domain.RouteKind{domain.KindGitSSH, domain.KindHost}).Draw(t, "open")
		drop := map[domain.RouteKind]string{domain.KindGitSSH: domain.ProbeDirectSSH, domain.KindHost: domain.ProbeHostGateway}[open]
		dropped := e.Closure != nil && rapid.Bool().Draw(t, "dropped")
		if dropped {
			c := *e.Closure
			c.Probes = slices.DeleteFunc(slices.Clone(c.Probes), func(p domain.ProbeResult) bool { return p.Name == drop })
			e.Closure = &c
		}
		before := domain.Compute(e)
		var kinds []domain.RouteKind
		if dropped && rapid.Bool().Draw(t, "excludeOpen") {
			kinds = append(kinds, open)
		}
		for range rapid.IntRange(0, 3).Draw(t, "n") {
			kinds = append(kinds, rapid.SampledFrom(append([]domain.RouteKind{""}, domain.EquivalentKinds...)).Draw(t, "kind"))
		}
		if len(kinds) == 0 {
			kinds = append(kinds, "")
		}
		for _, k := range kinds {
			e.Exclusions = append(e.Exclusions, domain.Exclusion{ID: ids.NewV7(), Kind: k})
		}
		after := domain.Compute(e)
		if len(after.Exclusions) != len(e.Exclusions) || !slices.Contains(after.Reasons, domain.ReasonExcluded) {
			t.Fatalf("exclusions not listed: %+v", after)
		}
		if after.State != before.State {
			t.Fatalf("exclusions of %v moved %v to %v", kinds, before.State, after.State)
		}
		for _, rt := range after.Routes {
			if rt.Status == domain.StatusExcluded && !slices.Contains(kinds, rt.Kind) {
				t.Fatalf("%s excluded without an exclusion", rt.Kind)
			}
		}
		if dropped && before.State == domain.Partial &&
			!slices.Contains(after.Reasons, domain.ReasonRouteOpen+":"+string(open)) {
			t.Fatalf("the open %s is not named: %v", open, after.Reasons)
		}
	})
}

// TestHR212_AnExcludedOpenRouteKeepsTheScopePartial: the case the founder
// decided. A closure that leaves direct SSH open cannot reach ENFORCED by
// excluding direct SSH.
func TestHR212_AnExcludedOpenRouteKeepsTheScopePartial(t *testing.T) {
	e := enforced()
	e.Closure.Probes = slices.DeleteFunc(slices.Clone(e.Closure.Probes), func(p domain.ProbeResult) bool {
		return p.Name == domain.ProbeDirectSSH
	})
	e.Exclusions = []domain.Exclusion{{ID: ids.NewV7(), Kind: domain.KindGitSSH}}
	r := domain.Compute(e)
	if r.State != domain.Partial || !slices.Contains(r.Reasons, "route_not_closed:git_ssh") ||
		!slices.Contains(r.Reasons, domain.ReasonExcluded) {
		t.Fatalf("excluded open SSH: %v %v", r.State, r.Reasons)
	}
	for _, rt := range r.Routes {
		if rt.Kind == domain.KindGitSSH && rt.Status != domain.StatusExcluded {
			t.Fatalf("git_ssh is %s", rt.Status)
		}
	}
}

// TestUnobservedRoutesAreNotAbsent: every equivalent route kind appears in a
// record; one no source showed is "not observed", never left out (F450).
func TestUnobservedRoutesAreNotAbsent(t *testing.T) {
	e := enforced()
	e.Closure = nil
	e.Routes = append(e.Routes, domain.Route{ID: ids.NewV7(), Kind: domain.KindGitSSH, Locator: "ssh://github.com", Observation: "observed"})
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
