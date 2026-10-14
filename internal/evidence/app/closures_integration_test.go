// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app

import (
	"context"
	"errors"
	"testing"
	"time"

	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR227_AClosureOfAnAgentTheCallerCannotReadIsLeftOut: refEntries with
// skipDenied (the closures a snapshot names in a transaction bundle) leaves
// out a closure whose agent the caller may not read, so verify fails the
// snapshot that names it; without skipDenied (--closure) the export is
// refused, and a closure whose agent is missing fails the export either way.
func TestHR227_AClosureOfAnAgentTheCallerCannotReadIsLeftOut(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	ctx := context.Background()
	org, agent, closure := ids.New[ids.Org](), ids.NewV7(), ids.NewV7()
	if err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		for _, s := range []struct {
			sql  string
			args []any
		}{
			{"INSERT INTO pc.orgs (id, name) VALUES ($1, 'ev')", []any{org}},
			{"INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'coder', 'DISCOVERED', 'test')", []any{org, agent}},
		} {
			if _, err := tx.Exec(ctx, s.sql, s.args...); err != nil {
				return err
			}
		}
		body, err := evdomain.CanonicalBody(map[string]any{"v": 1, "closure": closure.String(), "agent": agent.String(), "reports": []any{}})
		if err != nil {
			return err
		}
		_, err = ledger.Append(ctx, tx, "sandbox.closure", evdomain.Actor{Type: "system", ID: "test"}, body)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(time.Minute); ; {
		if n, err := ledger.ChainAll(ctx, p, org, 100); err != nil {
			t.Fatal(err)
		} else if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the entry was not chained within a minute")
		}
		time.Sleep(200 * time.Millisecond)
	}
	caller := func(bs ...td.Binding) tenancy.Caller {
		return tenancy.Caller{Subject: td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()}, Bindings: bs}}
	}
	auditor := caller(td.Binding{Role: td.RoleAuditor, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}})
	nobody := caller()
	s := New(p, "pc.test")
	entries := func(c tenancy.Caller, agentID string, skip bool) (n int, err error) {
		err = p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			refs, err := dbq.New(tx).ClosureEntryRefs(ctx, org, []string{closure.String()})
			if err != nil || len(refs) != 1 {
				t.Fatalf("refs %v (%v)", refs, err)
			}
			refs[0].AgentID = agentID
			got, err := s.refEntries(ctx, c, dbq.New(tx), refs, skip)
			n = len(got)
			return err
		}, db.ReadOnly())
		return n, err
	}
	if n, err := entries(auditor, agent.String(), true); err != nil || n != 1 {
		t.Fatalf("a reader got %d entries (%v), want 1", n, err)
	}
	if n, err := entries(nobody, agent.String(), true); err != nil || n != 0 {
		t.Fatalf("a caller who may not read got %d entries (%v), want the closure left out", n, err)
	}
	if _, err := entries(nobody, agent.String(), false); err == nil {
		t.Fatal("--closure for an agent the caller may not read was not refused")
	}
	for _, skip := range []bool{true, false} {
		if _, err := entries(auditor, ids.NewV7().String(), skip); !errors.Is(err, ErrClosureNotFound) {
			t.Fatalf("a missing agent with skipDenied=%v: %v, want CLOSURE_NOT_FOUND", skip, err)
		}
	}
}
