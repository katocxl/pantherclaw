// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/identity/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// idrOrg adds a second org, with its own team, environment and owner, to
// w's database; its world shares w's services.
func idrOrg(t *testing.T, w *world) *world {
	t.Helper()
	o := &world{
		d: w.d, pool: w.pool, svc: w.svc, inv: w.inv, reg: w.reg,
		org: ids.New[ids.Org](), team: ids.NewV7(), env: ids.NewV7(), owner: ids.NewV7(),
	}
	o.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'globex')", o.org)
	o.exec(t, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'eng', 'Eng')", o.org, o.team)
	o.exec(t, "INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'dev', 'Dev', 'DEVELOPMENT')", o.org, o.env, o.team)
	o.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", o.org, o.owner)
	return o
}

// idrAdmin is w's owner holding every agent role at org scope.
func idrAdmin(w *world) context.Context {
	var bs []td.Binding
	for _, r := range []td.RoleName{td.RoleOrgAdmin, td.RoleAgentOwner, td.RoleAgentAdmitter} {
		bs = append(bs, td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}})
	}
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{Org: w.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: w.owner}, Bindings: bs}, Credential: tenancy.CredAccessToken,
	})
}

// TestT037_InstancesOfAnotherOrgAreNotFound: T-037 — a person holding every
// agent role at org scope gets, lists, admits, rejects and revokes another
// org's real instances, and mints an enrollment token for that org's agent,
// by their ids: each is NotFound exactly as for an unknown id, and the other
// org's instances, enrollment tokens and admission entries are unchanged.
// The same person does each of these in its own org. TestHR094_* and
// TestT004_* cover the owner and permission checks inside an org.
func TestT037_InstancesOfAnotherOrgAreNotFound(t *testing.T) {
	w := newWorld(t)
	other := idrOrg(t, w)
	_, admitted, agent := other.admitted(t, adomain.ContextCI)
	pending, err := other.enroll(t, newWorkload(), other.enrollmentToken(t, agent))
	if err != nil {
		t.Fatal(err)
	}
	theirs := func() []app.Instance {
		t.Helper()
		var out []app.Instance
		for _, id := range []ids.UUID{admitted.Instance, pending.Instance.Instance} {
			in, err := other.svc.GetInstance(other.ownerCtx(), id)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, in)
		}
		return out
	}
	const (
		tokens = "SELECT count(*) FROM pc.enrollment_tokens WHERE org_id = $1"
		open   = "SELECT count(*) FROM pc.waitlist_entries WHERE org_id = $1 AND subject_type = 'instance' AND state = 'OPEN'"
	)
	before, nTokens, nOpen := theirs(), other.count(t, tokens, other.org), other.count(t, open, other.org)

	admin := idrAdmin(w)
	for name, c := range map[string]struct {
		call   func(ids.UUID) error
		theirs ids.UUID
		want   error
	}{
		"get pending":  {func(id ids.UUID) error { _, err := w.svc.GetInstance(admin, id); return err }, pending.Instance.Instance, app.ErrInstanceNotFound},
		"get admitted": {func(id ids.UUID) error { _, err := w.svc.GetInstance(admin, id); return err }, admitted.Instance, app.ErrInstanceNotFound},
		"list": {func(id ids.UUID) error {
			rows, _, err := w.svc.ListInstances(admin, id, page.Request{Size: page.Max}, nil)
			if len(rows) != 0 {
				t.Errorf("list %s: %d instances", id, len(rows))
			}
			return err
		}, agent, app.ErrAgentNotFound},
		"admit":           {func(id ids.UUID) error { _, err := w.svc.Admit(admin, id, pending.Fingerprint); return err }, pending.Instance.Instance, app.ErrInstanceNotFound},
		"reject":          {func(id ids.UUID) error { _, err := w.svc.Reject(admin, id, "not ours"); return err }, pending.Instance.Instance, app.ErrInstanceNotFound},
		"revoke pending":  {func(id ids.UUID) error { _, err := w.svc.Revoke(admin, id, "not ours"); return err }, pending.Instance.Instance, app.ErrInstanceNotFound},
		"revoke admitted": {func(id ids.UUID) error { _, err := w.svc.Revoke(admin, id, "not ours"); return err }, admitted.Instance, app.ErrInstanceNotFound},
		"mint a token":    {func(id ids.UUID) error { _, err := w.svc.CreateEnrollmentToken(admin, id, 0); return err }, agent, app.ErrAgentNotFound},
	} {
		for what, id := range map[string]ids.UUID{"theirs": c.theirs, "unknown": ids.NewV7()} {
			if err := c.call(id); !errors.Is(err, c.want) {
				t.Errorf("%s, %s id: %v, want %v", name, what, err, c.want)
			}
		}
	}
	if after := theirs(); !reflect.DeepEqual(after, before) {
		t.Errorf("the other org's instances changed:\n%+v\nwas\n%+v", after, before)
	}
	if n, m := other.count(t, tokens, other.org), other.count(t, open, other.org); n != nTokens || m != nOpen {
		t.Errorf("the other org has %d enrollment tokens and %d open admissions, was %d and %d", n, m, nTokens, nOpen)
	}

	mine := w.agent(t, adomain.ContextCI)
	et, err := w.svc.CreateEnrollmentToken(admin, mine, 0)
	if err != nil {
		t.Fatalf("mint a token in its own org: %v", err)
	}
	own, err := w.enroll(t, newWorkload(), et.Secret.Reveal())
	if err != nil {
		t.Fatal(err)
	}
	if rows, _, err := w.svc.ListInstances(admin, mine, page.Request{Size: page.Max}, nil); err != nil || len(rows) != 1 {
		t.Fatalf("list in its own org: %d %v", len(rows), err)
	}
	if _, err := w.svc.Admit(admin, own.Instance.Instance, own.Fingerprint); err != nil {
		t.Fatalf("admit in its own org: %v", err)
	}
	if in, err := w.svc.Revoke(admin, own.Instance.Instance, "rotated"); err != nil || in.State != "REVOKED" {
		t.Fatalf("revoke in its own org: %+v %v", in, err)
	}
}
