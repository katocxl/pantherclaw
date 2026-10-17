// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package enforcementpoints_test

import (
	"slices"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/automations/triggers/triggerstest"
	"github.com/katocxl/pantherclaw/internal/enforcementpoints"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type fixture struct {
	*triggerstest.Fixture
	svc                    *enforcementpoints.Service
	sa                     ids.UUID
	held, enforced, bounce ids.UUID // agent_held, target_enforced, pantherclaw_held
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{Fixture: triggerstest.New(t), sa: ids.NewV7(), held: ids.NewV7(), enforced: ids.NewV7(), bounce: ids.NewV7()}
	f.svc = enforcementpoints.New(f.Pool)
	gw := ids.NewV7()
	f.Exec(t, "INSERT INTO pc.service_accounts (org_id, id, name, created_by) VALUES ($1, $2, 'pep', 'test')", f.Org, f.sa)
	f.Exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", f.Org, gw)
	for id, c := range map[ids.UUID][2]string{
		f.held: {"payments", "agent_held"}, f.enforced: {"ledger", "target_enforced"}, f.bounce: {"billing", "pantherclaw_held"},
	} {
		f.Exec(t, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, default_mode,
			created_by, updated_by) VALUES ($1, $2, $3, 'http', $4, 'pc.mock-payments', 'https://'||$3||'.example.test', $5,
			'enforce', 'test', 'test')`, f.Org, id, c[0], gw, c[1])
	}
	return f
}

func (f *fixture) admin() *stepup.StepUp { return &stepup.StepUp{Credential: f.Cred, At: time.Now()} }

func sameSet(a, b []ids.UUID) bool {
	key := func(x ids.UUID) string { return x.String() }
	as, bs := make([]string, len(a)), make([]string, len(b))
	for i := range a {
		as[i] = key(a[i])
	}
	for i := range b {
		bs[i] = key(b[i])
	}
	slices.Sort(as)
	slices.Sort(bs)
	return slices.Equal(as, bs)
}

// TestHR317_EnforcementPointLifecycle: a person creates a PENDING point
// proposing agent_held and target_enforced connections (never a
// pantherclaw_held one); only a fresh step-up activates it and binds them;
// narrowing applies at once, widening waits for a confirmation while the
// point keeps its connections; disabling is final (G0 M14 D29).
func TestHR317_EnforcementPointLifecycle(t *testing.T) {
	f := newFixture(t)
	admin := f.As(td.KindUser, td.RoleOrgAdmin)
	if _, err := f.svc.Create(admin, enforcementpoints.NewPoint{
		Name: "edge-pep", ServiceAccount: f.sa, Connections: []ids.UUID{f.held, f.bounce},
	}); pcerr.CodeOf(err) != pcerr.FailedPrecondition {
		t.Fatalf("a pantherclaw_held connection: %v", err)
	}
	p, err := f.svc.Create(admin, enforcementpoints.NewPoint{Name: "edge-pep", ServiceAccount: f.sa, Connections: []ids.UUID{f.held}})
	if err != nil || p.State != enforcementpoints.StatePending || len(p.Connections) != 0 || !sameSet(p.Proposed, []ids.UUID{f.held}) ||
		p.RatePerSecond != enforcementpoints.DefaultRatePerSecond {
		t.Fatalf("create: %+v %v", p, err)
	}
	if _, err := f.svc.Create(admin, enforcementpoints.NewPoint{Name: "other", ServiceAccount: f.sa, Connections: []ids.UUID{f.held}}); pcerr.CodeOf(err) != pcerr.AlreadyExists {
		t.Fatalf("a second point for the service account: %v", err)
	}
	if _, err := f.svc.Activate(admin, p.ID, nil); !stepup.Is(err) {
		t.Fatalf("activate over the API: %v", err)
	}
	if _, err := f.svc.Activate(admin, p.ID, &stepup.StepUp{Credential: f.Cred, At: time.Now().Add(-10 * time.Minute)}); !stepup.Is(err) {
		t.Fatalf("a stale step-up: %v", err)
	}
	p, err = f.svc.Activate(admin, p.ID, f.admin())
	if err != nil || p.State != enforcementpoints.StateActive || !sameSet(p.Connections, []ids.UUID{f.held}) || len(p.Proposed) != 0 ||
		p.ActivatedSecurity == nil || *p.ActivatedSecurity != f.Cred {
		t.Fatalf("activate: %+v %v", p, err)
	}
	if _, err := f.svc.Activate(admin, p.ID, f.admin()); pcerr.CodeOf(err) != pcerr.FailedPrecondition {
		t.Fatalf("nothing to confirm: %v", err)
	}

	// Widening is proposed; the point keeps what it had.
	p, pending, err := f.svc.UpdateConnections(admin, p.ID, []ids.UUID{f.held, f.enforced})
	if err != nil || !pending || !sameSet(p.Connections, []ids.UUID{f.held}) || !sameSet(p.Proposed, []ids.UUID{f.held, f.enforced}) {
		t.Fatalf("widen: %+v %v %v", p, pending, err)
	}
	if _, _, err := f.svc.UpdateConnections(admin, p.ID, []ids.UUID{f.bounce}); pcerr.CodeOf(err) != pcerr.FailedPrecondition {
		t.Fatalf("widen to a pantherclaw_held connection: %v", err)
	}
	if p, err = f.svc.Activate(admin, p.ID, f.admin()); err != nil || !sameSet(p.Connections, []ids.UUID{f.held, f.enforced}) {
		t.Fatalf("confirm the widening: %+v %v", p, err)
	}
	// Narrowing applies at once.
	if p, pending, err = f.svc.UpdateConnections(admin, p.ID, []ids.UUID{f.enforced}); err != nil || pending ||
		!sameSet(p.Connections, []ids.UUID{f.enforced}) {
		t.Fatalf("narrow: %+v %v %v", p, pending, err)
	}
	// A connection whose access mode changed since cannot be confirmed.
	if _, _, err = f.svc.UpdateConnections(admin, p.ID, []ids.UUID{f.enforced, f.held}); err != nil {
		t.Fatal(err)
	}
	f.Exec(t, "UPDATE pc.connections SET access_mode = 'pantherclaw_held' WHERE org_id = $1 AND id = $2", f.Org, f.held)
	if _, err := f.svc.Activate(admin, p.ID, f.admin()); pcerr.CodeOf(err) != pcerr.FailedPrecondition {
		t.Fatalf("confirm a connection now pantherclaw_held: %v", err)
	}

	if p, err = f.svc.Disable(admin, p.ID); err != nil || p.State != enforcementpoints.StateDisabled || len(p.Proposed) != 0 {
		t.Fatalf("disable: %+v %v", p, err)
	}
	if _, err := f.svc.Disable(admin, p.ID); pcerr.CodeOf(err) != pcerr.FailedPrecondition {
		t.Fatalf("disable twice: %v", err)
	}
	if _, _, err := f.svc.UpdateConnections(admin, p.ID, []ids.UUID{f.enforced}); pcerr.CodeOf(err) != pcerr.FailedPrecondition {
		t.Fatalf("change a disabled point: %v", err)
	}
	// Once disabled, the service account may front another point.
	if _, err := f.svc.Create(admin, enforcementpoints.NewPoint{Name: "edge-pep", ServiceAccount: f.sa, Connections: []ids.UUID{f.enforced}}); err != nil {
		t.Fatalf("a new point after disabling: %v", err)
	}
	if n := countAudit(t, f, "authzen.enforcement_point_%"); n != 8 {
		t.Fatalf("audit records: %d", n)
	}
}

// TestHR317_EnforcementPointsArePeopleOnly: enforcement_point.manage is
// bindable to service accounts through Org Admin, so every change refuses
// a caller who is not a person, even holding it (G0 M14 D62); reading
// needs the permission.
func TestHR317_EnforcementPointsArePeopleOnly(t *testing.T) {
	f := newFixture(t)
	admin := f.As(td.KindUser, td.RoleOrgAdmin)
	p, err := f.svc.Create(admin, enforcementpoints.NewPoint{Name: "edge-pep", ServiceAccount: f.sa, Connections: []ids.UUID{f.held}})
	if err != nil {
		t.Fatal(err)
	}
	service := f.As(td.KindServiceAccount, td.RoleOrgAdmin)
	if _, err := f.svc.Create(service, enforcementpoints.NewPoint{Name: "svc-pep", ServiceAccount: f.sa, Connections: []ids.UUID{f.held}}); err != enforcementpoints.ErrHuman { //nolint:errorlint // sentinel
		t.Fatalf("create by a service: %v", err)
	}
	if _, err := f.svc.Activate(service, p.ID, f.admin()); err != enforcementpoints.ErrHuman { //nolint:errorlint // sentinel
		t.Fatalf("activate by a service: %v", err)
	}
	if _, _, err := f.svc.UpdateConnections(service, p.ID, []ids.UUID{f.enforced}); err != enforcementpoints.ErrHuman { //nolint:errorlint // sentinel
		t.Fatalf("update by a service: %v", err)
	}
	if _, err := f.svc.Disable(service, p.ID); err != enforcementpoints.ErrHuman { //nolint:errorlint // sentinel
		t.Fatalf("disable by a service: %v", err)
	}
	if _, err := f.svc.Get(service, p.ID); err != nil {
		t.Fatalf("a service holding the permission reads: %v", err)
	}
	viewer := f.As(td.KindUser, td.RoleAuditor)
	if _, err := f.svc.Create(viewer, enforcementpoints.NewPoint{Name: "x", ServiceAccount: f.sa, Connections: []ids.UUID{f.held}}); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("create without the permission: %v", err)
	}
	if _, err := f.svc.List(viewer); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("list without the permission: %v", err)
	}
	if got, _ := f.svc.Get(admin, p.ID); got.State != enforcementpoints.StatePending {
		t.Fatalf("nothing changed: %+v", got)
	}
}

func countAudit(t *testing.T, f *fixture, like string) int {
	t.Helper()
	return f.Count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind LIKE 'audit.' || $2", like)
}
