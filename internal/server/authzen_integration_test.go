// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/automations/triggers/triggerstest"
	"github.com/katocxl/pantherclaw/internal/enforcementpoints"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR317_OnlyConfirmedConnectionsAreServed: a widening is not served
// until a person confirms it; until then a request naming the proposed
// connection is refused as not bound, while the current one keeps
// serving (G0 M14 D67, HR-317). Who asked is recorded once per
// transaction (D65).
func TestHR317_OnlyConfirmedConnectionsAreServed(t *testing.T) {
	f := triggerstest.New(t)
	sa, gw, a, b := ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7()
	f.Exec(t, "INSERT INTO pc.service_accounts (org_id, id, name, created_by) VALUES ($1, $2, 'pep', 'test')", f.Org, sa)
	f.Exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", f.Org, gw)
	pkg, ver, digest := ids.NewV7(), ids.NewV7(), "sha256:"+strings.Repeat("0", 64)
	f.Exec(t, `INSERT INTO pc.tool_packages (org_id, id, name) VALUES ($1, $2, 'pc.mock-payments')`, f.Org, pkg)
	f.Exec(t, `INSERT INTO pc.package_versions (org_id, id, package_id, version, file_digest, raw, state)
		VALUES ($1, $2, $3, '1.0.0', $4, '\x7b7d', 'ACTIVE')`, f.Org, ver, pkg, digest)
	f.Exec(t, `INSERT INTO pc.package_pins (org_id, package_id, version_id, version, digest) VALUES ($1, $2, $3, '1.0.0', $4)`,
		f.Org, pkg, ver, digest)
	for id, name := range map[ids.UUID]string{a: "payments", b: "ledger"} {
		f.Exec(t, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, default_mode,
			created_by, updated_by) VALUES ($1, $2, $3, 'http', $4, 'pc.mock-payments', 'https://x.example.test', 'agent_held',
			'enforce', 'test', 'test')`, f.Org, id, name, gw)
	}
	svc := enforcementpoints.New(f.Pool)
	admin := f.As(td.KindUser, td.RoleOrgAdmin)
	pt, err := svc.Create(admin, enforcementpoints.NewPoint{Name: "edge-pep", ServiceAccount: sa, Connections: []ids.UUID{a}})
	if err != nil {
		t.Fatal(err)
	}
	e := newAuthZENEndpoint(f.Pool, nil, nil, "https://pc.example.test", celenv.Limits{}, nil, nil)
	p := point{Org: f.Org, ID: pt.ID, Name: pt.Name, Rate: 50, Subject: sa}
	named := func(name string) []azEvaluation {
		return []azEvaluation{{Resource: &azEntity{Type: authzenResourceType, ID: name}}}
	}
	if _, err := e.connections(context.Background(), p, named("payments")); !errors.Is(err, errNotBound) {
		t.Fatalf("a PENDING point's proposed connection: %v", err)
	}
	if _, err := svc.Activate(admin, pt.ID, &stepup.StepUp{Credential: f.Cred, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, pending, err := svc.UpdateConnections(admin, pt.ID, []ids.UUID{a, b}); err != nil || !pending {
		t.Fatalf("widen: %v %v", pending, err)
	}
	if _, err := e.connections(context.Background(), p, named("ledger")); !errors.Is(err, errNotBound) {
		t.Fatalf("a proposed connection before the confirmation: %v", err)
	}
	if _, err := e.connections(context.Background(), p, named("payments")); err != nil {
		t.Fatalf("the current connection while a widening waits: %v", err)
	}
	if _, err := svc.Activate(admin, pt.ID, &stepup.StepUp{Credential: f.Cred, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.connections(context.Background(), p, named("ledger")); err != nil {
		t.Fatalf("the confirmed connection: %v", err)
	}
}
