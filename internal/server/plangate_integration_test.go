// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR357_ALapsedOrgThroughTheServerKeepsContainmentAndApprovals (D88):
// through the real server wiring (the plan gate on, billing external), a
// lapsed org is refused a new agent but still contains an agent and still
// reaches its approval decisions.
func TestHR357_ALapsedOrgThroughTheServerKeepsContainmentAndApprovals(t *testing.T) {
	d := dbtest.New(t)
	base := serveForTest(t, testConfig(t, d, RoleAPI, func(c map[string]any) {
		c["billing"] = map[string]any{"mode": "external", "require_plan": true}
	}))
	pool := d.AppPool(t)
	ctx := context.Background()
	org, user, agent := ids.New[ids.Org](), ids.NewV7(), ids.NewV7()
	secret, err := credential.New(credential.BrowserSession, "", org)
	if err != nil {
		t.Fatal(err)
	}
	err = pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{"INSERT INTO pc.orgs (id, name) VALUES ($1, 'lapsed')", []any{org}},
			{"INSERT INTO pc.org_containment (org_id) VALUES ($1)", []any{org}},
			{"INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'resp')", []any{org, user}},
			{"INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'bot', 'DISCOVERED', 'test')", []any{org, agent}},
			{`INSERT INTO pc.sessions (org_id, id, user_id, secret_hash, provider, roles_digest, expires_at)
				VALUES ($1, $2, $3, $4, 'test', $5, now() + interval '1 hour')`, []any{org, ids.NewV7(), user, secret.Hash(), make([]byte, 32)}},
		} {
			if _, err := tx.Exec(ctx, q.sql, q.args...); err != nil {
				return err
			}
		}
		for _, role := range []string{"agent_owner", "responder", "approver"} {
			if _, err := tx.Exec(ctx, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by)
				VALUES ($1, $2, $3, $4, 'ORG', 'test')`, org, ids.NewV7(), role, user); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	plans, err := entitlements.New(pool, entitlements.LicenceFunc(func(context.Context) (billing.Entitlements, error) {
		return billing.CommunityEntitlements(), nil
	}), entitlements.ModeExternal, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := plans.ApplyPlan(ctx, org, entitlements.Snapshot{
		PlanID: "team", Edition: "team", Status: entitlements.StatusLapsed, EventID: "evt_lapse", EventAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	cookie := secret.Reveal()
	call := func(procedure, body string) (int, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+procedure, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Origin", "http://127.0.0.1:8080") // the configured public origin
		req.Header.Set("PC-CSRF", "1")
		req.Header.Set("Cookie", "pc_session="+cookie)
		res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		for _, c := range res.Cookies() {
			if c.Name == "pc_session" && c.Value != "" {
				cookie = c.Value // a role change rotates the secret
			}
		}
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	if code, body := call("/pantherclaw.v1.AgentService/CreateAgent", `{"name":"new-bot"}`); code == http.StatusOK || !strings.Contains(body, "PLAN_REQUIRED") {
		t.Errorf("new agent on a lapsed plan: %d %s", code, body)
	}
	if code, body := call("/pantherclaw.v1.ResponseService/Contain",
		`{"scope":{"type":"agent","id":"`+agent.String()+`"},"control":"DENY_ALL","reason":"lapsed plan test"}`); code != http.StatusOK {
		t.Errorf("containment on a lapsed plan: %d %s", code, body)
	}
	// An approval decision reaches its use case: the gate lets it through,
	// and the unknown request is not found.
	if code, body := call("/pantherclaw.v1.ApprovalService/DeclineApprovalRequest",
		`{"id":"`+ids.NewV7().String()+`","reason":"DECLINE_REASON_TOO_RISKY"}`); strings.Contains(body, "PLAN_REQUIRED") || code == http.StatusForbidden {
		t.Errorf("approval decision on a lapsed plan: %d %s", code, body)
	}
}
