// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gateways/app"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/tenantctx"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// editions grants one edition per org; an org it does not list is
// Community.
type editions map[ids.OrgID]billing.Edition

func (e editions) Current(ctx context.Context) (billing.Entitlements, error) {
	out := billing.CommunityEntitlements()
	org, ok := tenantctx.Org(ctx)
	if !ok {
		if c, err := callerOrg(ctx); err == nil {
			org, ok = c, true
		}
	}
	if ed, found := e[org]; ok && found {
		out.Edition = ed
	}
	return out, nil
}

// notices records what the sweep enqueued.
type notices struct{ got []napp.Message }

func (n *notices) Enqueue(_ context.Context, _ db.TenantTx, m napp.Message) (napp.Enqueued, error) {
	n.got = append(n.got, m)
	return napp.Enqueued{}, nil
}

func (n *notices) take() []napp.Message { out := n.got; n.got = nil; return out }

// fleetAt returns the fleet use cases on a fake clock, with eds and a
// recording notifier.
func (e *env) fleetAt(now time.Time, eds editions) (*app.Fleet, *app.Service, *clock.Fake, *notices) {
	svc, clk := e.at(now)
	n := &notices{}
	return app.NewFleet(svc, eds, n), svc, clk, n
}

func report(t *testing.T, svc *app.Service, id app.Identity, replica, version string) {
	t.Helper()
	if err := svc.ReportStatus(context.Background(), id, app.ReplicaStatus{Replica: replica, Version: version, Build: "b"}); err != nil {
		t.Fatal(err)
	}
}

func sweep(t *testing.T, f *app.Fleet, org ids.OrgID) app.SweepResult {
	t.Helper()
	r, err := f.Sweep(context.Background(), org)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

const (
	replicaA = "AAAAAAAAAAAAAAAAAAAAAA"
	replicaB = "BBBBBBBBBBBBBBBBBBBBBB"
)

// TestHR470_BelowMinimumGatewayKeepsBeingServed: a gateway below the
// org's minimum version, or reporting one that does not parse, is flagged
// in the fleet view and alerted once per version, and it keeps
// authenticating, reporting and getting its configuration (G0 M18 D151).
// Covers: PN-010.6
func TestHR470_BelowMinimumGatewayKeepsBeingServed(t *testing.T) {
	e := newEnv(t)
	_, gw := e.enroll(t, "old")
	f, svc, _, n := e.fleetAt(time.Now(), editions{e.org: billing.Enterprise})
	if _, err := f.SetFleetPolicy(e.admin, "v2.0.0", 0); err != nil {
		t.Fatal(err)
	}
	report(t, svc, gw, replicaA, "1.4.0")
	if r := sweep(t, f, e.org); r.BelowMinimum != 1 {
		t.Fatalf("first sweep: %+v", r)
	}
	if m := n.take(); len(m) != 1 || m[0].Type != "gateway.below_minimum" || m[0].Params["version"] != "v1.4.0" ||
		m[0].Params["minimum"] != "v2.0.0" || m[0].Params["gateway"] != gw.Gateway.String() {
		t.Fatalf("notices %+v", m)
	}
	if r := sweep(t, f, e.org); r != (app.SweepResult{}) {
		t.Fatalf("the same version alerted again: %+v", r)
	}
	// Served regardless: authentication, configuration and reports.
	if err := svc.Authenticate(context.Background(), gw); err != nil {
		t.Fatalf("a gateway below the minimum is refused: %v", err)
	}
	if _, err := svc.Configuration(context.Background(), gw, 0); err != nil {
		t.Fatalf("a gateway below the minimum gets no configuration: %v", err)
	}
	report(t, svc, gw, replicaA, "dev")
	if r := sweep(t, f, e.org); r.BelowMinimum != 1 {
		t.Fatalf("a new version did not alert: %+v", r)
	}
	if m := n.take(); m[0].Params["version"] != "unknown" {
		t.Fatalf("an unparseable version shows as %q", m[0].Params["version"])
	}
	v, err := f.ListFleet(e.admin, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Gateways) != 1 || !v.Gateways[0].BelowMinimum || v.Gateways[0].Replicas[0].Compliance != app.VersionUnknown ||
		v.Gateways[0].Replicas[0].Version.String() != "unknown" {
		t.Fatalf("fleet view %+v", v.Gateways)
	}
	report(t, svc, gw, replicaA, "v2.0.1")
	if r := sweep(t, f, e.org); r != (app.SweepResult{}) {
		t.Fatalf("a compliant version alerted: %+v", r)
	}
	if v, _ := f.ListFleet(e.admin, 10, ""); v.Gateways[0].BelowMinimum || v.Gateways[0].Replicas[0].Compliance != app.VersionCompliant {
		t.Fatalf("an upgraded gateway is still flagged: %+v", v.Gateways[0])
	}
	// Downgrading again alerts again: once per version change.
	report(t, svc, gw, replicaA, "1.4.0")
	if r := sweep(t, f, e.org); r.BelowMinimum != 1 {
		t.Fatalf("a downgrade did not alert: %+v", r)
	}
	if _, err := f.SetFleetPolicy(e.admin, "2.0", 0); !errors.Is(err, app.ErrMinimumVersion) {
		t.Fatalf("an unparseable minimum: %v", err)
	}
}

// TestHR471_SilentGatewayAlertsOncePerSilenceAndOnRecovery: a gateway
// that stops reporting alerts once when its silence passes the org's
// threshold and once when it reports again; a second silence alerts again.
// Each org is swept apart and only an entitled org is alerted (G0 M18 D151).
// Covers: PN-010.6
func TestHR471_SilentGatewayAlertsOncePerSilenceAndOnRecovery(t *testing.T) {
	e := newEnv(t)
	_, gw := e.enroll(t, "edge")
	_, never := e.enroll(t, "never-reported")
	other := e.otherOrg(t)
	_, otherGW := other.enroll(t, "other")
	eds := editions{e.org: billing.Enterprise, other.org: billing.Enterprise}
	f, svc, clk, n := e.fleetAt(time.Now(), eds)
	if _, err := f.SetFleetPolicy(e.admin, "", 180*time.Second); err != nil {
		t.Fatal(err)
	}
	report(t, svc, gw, replicaA, "1.0.0")
	report(t, svc, otherGW, replicaA, "1.0.0")
	clk.Advance(179 * time.Second)
	if r := sweep(t, f, e.org); r != (app.SweepResult{}) {
		t.Fatalf("alerted before the threshold: %+v", r)
	}
	clk.Advance(time.Second)
	if r := sweep(t, f, e.org); r.Silent != 1 {
		t.Fatalf("no silent alert at the threshold: %+v", r)
	}
	m := n.take()
	if len(m) != 1 || m[0].Type != "gateway.silent" || m[0].Org != e.org || m[0].Params["gateway"] != gw.Gateway.String() ||
		m[0].Params["threshold"] != "180" {
		t.Fatalf("notices %+v", m)
	}
	_ = never // never reported: never silent
	for range 3 {
		clk.Advance(time.Minute)
		if r := sweep(t, f, e.org); r != (app.SweepResult{}) {
			t.Fatalf("the same silence alerted again: %+v", r)
		}
	}
	// The other org's gateway is silent too, but only its own sweep says so.
	if r := sweep(t, f, other.org); r.Silent != 1 {
		t.Fatalf("other org: %+v", r)
	}
	if m := n.take(); len(m) != 1 || m[0].Org != other.org || m[0].Params["threshold"] != "300" {
		t.Fatalf("other org notices %+v", m)
	}
	report(t, svc, gw, replicaB, "1.0.0")
	if r := sweep(t, f, e.org); r.Recovered != 1 || r.Silent != 0 {
		t.Fatalf("no recovery: %+v", r)
	}
	if m := n.take(); len(m) != 1 || m[0].Type != "gateway.recovered" {
		t.Fatalf("recovery notices %+v", m)
	}
	if r := sweep(t, f, e.org); r != (app.SweepResult{}) {
		t.Fatalf("recovery alerted twice: %+v", r)
	}
	clk.Advance(180 * time.Second)
	if r := sweep(t, f, e.org); r.Silent != 1 {
		t.Fatalf("a second silence did not alert: %+v", r)
	}
	// An org without the Enterprise edition is never alerted.
	community, _, cclk, cn := e.fleetAt(clk.Now(), editions{})
	cclk.Advance(time.Hour)
	if r := sweep(t, community, other.org); r != (app.SweepResult{}) || len(cn.got) != 0 {
		t.Fatalf("a Community org was alerted: %+v", r)
	}
}

// TestT212_FakedVersionOrSuppressedSilence: what a gateway reports buys it
// nothing (G0 M18 D151, T-212). Its version text never reaches a
// notification, only the parsed version or "unknown"; a report cannot set
// when it was seen, so a far-future start time does not mask a silence; a
// silence that outlives the replica prune still ends in one recovery.
// Covers: PN-010.6
func TestT212_FakedVersionOrSuppressedSilence(t *testing.T) {
	e := newEnv(t)
	_, gw := e.enroll(t, "faker")
	f, svc, clk, n := e.fleetAt(time.Now(), editions{e.org: billing.Enterprise})
	if _, err := f.SetFleetPolicy(e.admin, "v3.0.0", 0); err != nil {
		t.Fatal(err)
	}
	faked := "2.9.9 <a href=https://evil.example.test>upgrade now</a>"
	future := clk.Now().Add(365 * 24 * time.Hour)
	if err := svc.ReportStatus(context.Background(), gw, app.ReplicaStatus{Replica: replicaA, Version: faked, Build: "b", StartTime: &future}); err != nil {
		t.Fatal(err)
	}
	sweep(t, f, e.org)
	for _, m := range n.take() {
		for k, v := range m.Params {
			if strings.Contains(v, "evil") || strings.Contains(v, "<") {
				t.Fatalf("reported text reached the notice: %s=%q", k, v)
			}
		}
		if m.Params["version"] != "unknown" {
			t.Fatalf("a faked version shows as %q", m.Params["version"])
		}
	}
	clk.Advance(app.DefaultSilenceAfter)
	if r := sweep(t, f, e.org); r.Silent != 1 {
		t.Fatalf("a future start time masked the silence: %+v", r)
	}
	clk.Advance(app.ReplicaRetention + time.Hour)
	if _, err := svc.PruneReplicas(context.Background(), e.org); err != nil {
		t.Fatal(err)
	}
	if r := sweep(t, f, e.org); r != (app.SweepResult{}) {
		t.Fatalf("a pruned silent gateway alerted again: %+v", r)
	}
	report(t, svc, gw, replicaB, "3.0.0")
	if r := sweep(t, f, e.org); r.Recovered != 1 || r.Silent != 0 {
		t.Fatalf("recovery after the prune: %+v", r)
	}
}

// TestFleetEditionsAndPermissions: reading the policy works in every
// edition; setting it needs Enterprise and gateway.manage; the fleet view
// needs Team and gateway.read (G0 M18 D161).
// Covers: PN-010.6
func TestFleetEditionsAndPermissions(t *testing.T) {
	e := newEnv(t)
	community, _, _, _ := e.fleetAt(time.Now(), editions{})
	if p, err := community.GetFleetPolicy(e.admin); err != nil || p.SilenceAfter != app.DefaultSilenceAfter || p.MinimumVersion.Known() {
		t.Fatalf("Community read: %+v %v", p, err)
	}
	if _, err := community.ListFleet(e.admin, 10, ""); !errors.Is(err, app.ErrFleetViewEdition) {
		t.Fatalf("Community fleet view: %v", err)
	}
	team, _, _, _ := e.fleetAt(time.Now(), editions{e.org: billing.Team})
	if _, err := team.ListFleet(e.admin, 10, ""); err != nil {
		t.Fatalf("Team fleet view: %v", err)
	}
	if _, err := team.SetFleetPolicy(e.admin, "v1.0.0", 0); !errors.Is(err, app.ErrFleetPolicyEdition) {
		t.Fatalf("Team set: %v", err)
	}
	ent, _, _, _ := e.fleetAt(time.Now(), editions{e.org: billing.Enterprise})
	if _, err := ent.SetFleetPolicy(e.caller(td.KindUser, td.RoleAuditor), "v1.0.0", 0); err == nil {
		t.Fatal("an auditor set the fleet policy")
	}
	if _, err := ent.SetFleetPolicy(e.admin, "", 119*time.Second); !errors.Is(err, app.ErrSilenceAfter) {
		t.Fatalf("a threshold below 120 s: %v", err)
	}
	p, err := ent.SetFleetPolicy(e.admin, "1.2.3-rc.1", 600*time.Second)
	if err != nil || p.MinimumVersion.String() != "v1.2.3-rc.1" || p.SilenceAfter != 600*time.Second {
		t.Fatalf("set: %+v %v", p, err)
	}
	if got, err := ent.GetFleetPolicy(e.admin); err != nil || got.MinimumVersion.String() != "v1.2.3-rc.1" || got.UpdatedBy == "" {
		t.Fatalf("read back: %+v %v", got, err)
	}
}

func callerOrg(ctx context.Context) (ids.OrgID, error) {
	c, err := tapp.CallerFrom(ctx)
	return c.Org, err
}

// otherOrg is a second org on e's database, with its own admin.
func (e *env) otherOrg(t *testing.T) *env {
	t.Helper()
	o := &env{pool: e.pool, svc: e.svc, org: ids.New[ids.Org]()}
	o.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'gateways-other')", o.org)
	o.admin = o.caller(td.KindUser, td.RoleGatewayAdmin)
	return o
}
