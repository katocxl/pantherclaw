// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package investigations_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/investigations"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// scope makes the listed agents visible.
type scope map[ids.UUID]bool

func (s scope) Visible(_ context.Context, a ids.UUID) (bool, error) { return s[a], nil }
func (s scope) Limited() bool                                       { return true }
func (s scope) Agents(context.Context) ([]ids.UUID, error) {
	out := []ids.UUID{}
	for a, ok := range s {
		if ok {
			out = append(out, a)
		}
	}
	return out, nil
}

type fixture struct {
	p                *db.Pool
	org              ids.OrgID
	alice, env       ids.UUID
	agent, other     ids.UUID
	internal, public ids.UUID
	gw               ids.UUID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	d := dbtest.New(t)
	f := &fixture{
		p: d.AppPool(t), org: ids.New[ids.Org](), alice: ids.NewV7(), env: ids.NewV7(), agent: ids.NewV7(),
		other: ids.NewV7(), internal: ids.NewV7(), public: ids.NewV7(), gw: ids.NewV7(),
	}
	team := ids.NewV7()
	f.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'inv')", f.org)
	f.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", f.org, f.alice)
	f.exec(t, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'eng', 'Eng')", f.org, team)
	f.exec(t, "INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'dev', 'Dev', 'DEVELOPMENT')", f.org, f.env, team)
	f.exec(t, "INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'bot', 'DISCOVERED', 'test'), ($1, $3, 'other', 'DISCOVERED', 'test')",
		f.org, f.agent, f.other)
	f.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'gw', 'test')", f.org, f.gw)
	f.exec(t, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, destination_class, access_mode, base_url, created_by, updated_by)
		VALUES ($1, $2, 'wiki', 'http', $4, 'pc.wiki', 'internal', 'pantherclaw_held', 'https://wiki.example.test', 'test', 'test'),
		       ($1, $3, 'paste', 'http', $4, 'pc.paste', 'public', 'pantherclaw_held', 'https://paste.example.test', 'test', 'test')`, f.org, f.internal, f.public, f.gw)
	return f
}

func (f *fixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (f *fixture) run(t *testing.T, agent ids.UUID) ids.UUID {
	t.Helper()
	r := ids.NewV7()
	f.exec(t, `INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_user_id, principal_user_id, principal_source, expires_at)
		VALUES ($1, $2, $3, $4, $5, $5, 'launcher', now() + interval '1 hour')`, f.org, r, agent, f.env, f.alice)
	return r
}

func (f *fixture) txn(t *testing.T, run, conn ids.UUID, op, decision string) ids.UUID {
	t.Helper()
	id := ids.NewV7()
	f.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id,
		connection_id, target_type, target_id) VALUES ($1, $2, $3, $4, $5, $6, $7, 'R', 'gw', $8, 'page', 'home')`,
		f.org, id, run, ids.NewV7(), make([]byte, 32), op, decision, conn)
	return id
}

func (f *fixture) read(t *testing.T, fn func(context.Context, db.TenantTx) error) {
	t.Helper()
	if err := f.p.InTenantTx(context.Background(), f.org, fn, db.ReadOnly()); err != nil {
		t.Fatal(err)
	}
}

// TestHR247_RunInvestigationViewsApplyTheViewersScope: an action of a hidden
// agent is not found, and a hidden agent's run is never listed among shared
// targets; context links carry their basis.
func TestHR247_RunInvestigationViewsApplyTheViewersScope(t *testing.T) {
	f := newFixture(t)
	run := f.run(t, f.agent)
	read := f.txn(t, run, f.internal, "wiki.page.read", "ALLOW")
	time.Sleep(2 * time.Millisecond)
	post := f.txn(t, run, f.public, "paste.create", "DENY")
	ref := f.run(t, f.agent)
	f.txn(t, ref, f.internal, "wiki.page.read", "ALLOW")
	hidden := f.run(t, f.other)
	f.txn(t, hidden, f.public, "paste.create", "ALLOW")
	s := scope{f.agent: true}

	f.read(t, func(ctx context.Context, tx db.TenantTx) error {
		h, err := investigations.WhatHappened(ctx, tx, s, post)
		if err != nil {
			return err
		}
		if !h.Denied || h.Allowed || h.Dispatched || h.Launcher == nil || h.Launcher.ID != f.alice || !h.ScopeLimited {
			t.Errorf("what happened = %+v", h)
		}
		if _, err := investigations.WhatHappened(ctx, tx, scope{}, post); !errors.Is(err, investigations.ErrTransactionNotFound) {
			t.Errorf("hidden agent: %v", err)
		}

		tl, err := investigations.RunTimeline(ctx, tx, s, run, true)
		if err != nil {
			return err
		}
		if len(tl.Events) != 2 || len(tl.Gaps) != 2 || len(tl.Phases) != 2 || tl.Phases[0].Basis != investigations.BasisInferred {
			t.Errorf("timeline = %+v", tl)
		}

		p, err := investigations.PrecedingContext(ctx, tx, s, ids.UUID{}, &post,
			investigations.Range{Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Hour)})
		if err != nil {
			return err
		}
		if len(p.Links) != 1 || p.Links[0].From != read || p.Links[0].Basis != investigations.BasisInferred {
			t.Errorf("links = %+v", p.Links)
		}
		// The other agent's run shares the public target but is out of scope:
		// only the reference run of the same agent is listed.
		for _, x := range p.Shared {
			if x.Agent != f.agent {
				t.Errorf("shared lists a hidden agent: %+v", x)
			}
		}
		if len(p.Shared) != 1 || p.Shared[0].Run != ref {
			t.Errorf("shared = %+v", p.Shared)
		}
		if p.ContentProvenance != investigations.ProvenanceNotCollected {
			t.Errorf("provenance = %q", p.ContentProvenance)
		}

		c, err := investigations.CompareRun(ctx, tx, s, run, investigations.Range{Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Hour)})
		if err != nil {
			return err
		}
		if c.SampleSize != 1 || len(c.NewDestinations) != 1 || c.NewDestinations[0].Connection != f.public ||
			len(c.NewOperations) != 1 || c.NewOperations[0] != "paste.create" || c.Actions != 2 || c.ReferenceMedianActions != 1 {
			t.Errorf("comparison = %+v", c)
		}
		return nil
	})
}
