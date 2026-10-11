// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/coverage/app"
	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// notifier records the notifications it is asked to send.
type notifier struct{ sent []napp.Message }

func (n *notifier) Enqueue(_ context.Context, _ db.TenantTx, m napp.Message) (napp.Enqueued, error) {
	n.sent = append(n.sent, m)
	return napp.Enqueued{}, nil
}

// TestHR212_OnlyAPersonExcludesWithAReasonAndAnExpiryAudited: a person
// holding coverage.manage creates an exclusion with a written reason and
// an expiry; it is audited, notified without its reason and asks for a
// reassessment. An API key, a viewer, an org admin, a reason that says
// nothing, a channel or a 91-day expiry are refused; revoking is audited
// too and happens once.
func TestHR212_OnlyAPersonExcludesWithAReasonAndAnExpiryAudited(t *testing.T) {
	f := newFixture(t)
	n := &notifier{}
	f.svc.Notify = n
	op := "payments.refund.get"
	req := app.ExclusionRequest{
		Connection: f.conn, Agent: &f.agent, Operation: &op, Kind: domain.KindBrowser,
		Reason: "The build container has no browser.", ExpiresInDays: 30,
	}
	admin := f.as(td.RoleSecurityAdmin)
	apiKey := tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{
			Org: f.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: f.user},
			Bindings: []td.Binding{{Role: td.RoleSecurityAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}}},
		},
		Credential: tenancy.CredAPIKey,
	})
	if _, err := f.svc.CreateExclusion(apiKey, req); !errors.Is(err, app.ErrHumanOnly) {
		t.Fatalf("an API key excluded: %v", err)
	}
	for _, r := range []td.RoleName{td.RoleViewer, td.RoleOrgAdmin} {
		if _, err := f.svc.CreateExclusion(f.as(r), req); !errors.Is(err, td.ErrPermissionDenied(td.PermCoverageManage)) {
			t.Fatalf("%s excluded: %v", r, err)
		}
	}
	for name, mod := range map[string]func(*app.ExclusionRequest){
		"a reason that says nothing": func(r *app.ExclusionRequest) { r.Reason = "  ok      " },
		"a channel":                  func(r *app.ExclusionRequest) { r.Kind = domain.KindChannel },
		"91 days":                    func(r *app.ExclusionRequest) { r.ExpiresInDays = 91 },
	} {
		bad := req
		mod(&bad)
		if _, err := f.svc.CreateExclusion(admin, bad); !errors.Is(err, app.ErrExclusion) {
			t.Errorf("%s: %v", name, err)
		}
	}
	x, err := f.svc.CreateExclusion(admin, req)
	if err != nil || x.State != "ACTIVE" || x.CreatedBy != f.user {
		t.Fatalf("exclusion %+v (%v)", x, err)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.coverage.exclusion_created'`); n != 1 {
		t.Fatalf("%d audited exclusions", n)
	}
	if len(n.sent) != 1 || n.sent[0].Type != "security.coverage_excluded" ||
		n.sent[0].Params["scope"] != "the browser route of payments.refund.get for agent "+f.agent.String() ||
		strings.Contains(fmt.Sprint(n.sent[0].Params), req.Reason) {
		t.Fatalf("notifications %+v", n.sent)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.coverage_invalidations WHERE kind = 'exclusion' AND subject_id = $1`, x.ID); n != 1 {
		t.Fatalf("%d reassessments asked", n)
	}
	list, _, err := f.svc.ListExclusions(f.as(td.RoleAuditor), &f.conn, 10, "")
	if err != nil || len(list) != 1 || list[0].EffectiveState != "ACTIVE" {
		t.Fatalf("list %v (%v)", list, err)
	}
	if r, err := f.svc.RevokeExclusion(admin, x.ID); err != nil || r.State != "REVOKED" {
		t.Fatalf("revoke %+v (%v)", r, err)
	}
	if _, err := f.svc.RevokeExclusion(admin, x.ID); !errors.Is(err, app.ErrExclusionClosed) {
		t.Fatalf("revoked twice: %v", err)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.coverage.exclusion_revoked'`); n != 1 {
		t.Fatalf("%d audited revocations", n)
	}
}
