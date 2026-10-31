// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package webhookkeys_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/webhookkeys"
)

type fixture struct {
	d                    *dbtest.DB
	p                    *db.Pool
	org                  ids.OrgID
	alice, cred, session ids.UUID
	svc                  *webhookkeys.Service
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	d := dbtest.New(t)
	f := &fixture{d: d, p: d.AppPool(t), org: ids.New[ids.Org](), alice: ids.NewV7(), cred: ids.NewV7(), session: ids.NewV7()}
	kek := filepath.Join(t.TempDir(), "kek")
	if err := keys.GenerateKEKFile(kek); err != nil {
		t.Fatal(err)
	}
	kp, err := keys.NewFileProvider([]string{kek})
	if err != nil {
		t.Fatal(err)
	}
	f.svc = webhookkeys.New(f.p, keystore.NewWebhookKeys(f.p, kp), "https://pc.example.test")
	secret := make([]byte, 32)
	copy(secret, f.alice[:])
	d.AdminExec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'webhooks')", f.org)
	d.AdminExec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", f.org, f.alice)
	d.AdminExec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		f.org, f.cred, f.alice, secret[:16], secret)
	d.AdminExec(t, `INSERT INTO pc.sessions (org_id, id, user_id, secret_hash, provider, auth_time, roles_digest, expires_at)
		VALUES ($1, $2, $3, $4, 'keycloak', now(), $4, now() + interval '12 hours')`, f.org, f.session, f.alice, secret)
	return f
}

func (f *fixture) as(kind td.PrincipalKind, cred tenancy.Credential, role td.RoleName) context.Context {
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{
			Org: f.org, Principal: td.PrincipalRef{Kind: kind, ID: f.alice},
			Bindings: []td.Binding{{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}}},
		},
		Credential: cred, Session: f.session,
	})
}

func (f *fixture) stepUp(t *testing.T, ago string) {
	t.Helper()
	f.d.AdminExec(t, "UPDATE pc.sessions SET step_up_at = now() - $1::interval, step_up_credential_id = $2 WHERE id = $3", ago, f.cred, f.session)
}

// TestHR512_WebhookKeyRotationNeedsManageAndAStepUp: listing needs
// webhook_key.read (the Auditor has it, the Viewer does not); rotating
// needs webhook_key.manage and a fresh browser-session step-up, so over
// the API it answers STEP_UP_REQUIRED; a rotation during the overlap is
// refused; each rotation is audited with its security key (G0 M20 D261).
// Covers: PN-018
func TestHR512_WebhookKeyRotationNeedsManageAndAStepUp(t *testing.T) {
	f := newFixture(t)
	admin := f.as(td.KindUser, tenancy.CredBrowserSession, td.RoleSecurityAdmin)
	if _, jwks, err := f.svc.List(f.as(td.KindUser, tenancy.CredBrowserSession, td.RoleAuditor)); err != nil ||
		jwks != "https://pc.example.test/.well-known/pantherclaw/orgs/"+f.org.String()+"/webhook-jwks.json" {
		t.Fatalf("auditor list: %s %v", jwks, err)
	}
	if _, _, err := f.svc.List(f.as(td.KindUser, tenancy.CredBrowserSession, td.RoleViewer)); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("viewer list: %v", err)
	}
	if _, _, err := f.svc.Rotate(f.as(td.KindUser, tenancy.CredBrowserSession, td.RoleAuditor)); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("auditor rotate: %v", err)
	}
	for name, ctx := range map[string]context.Context{
		"API key":         f.as(td.KindUser, tenancy.CredAPIKey, td.RoleOrgAdmin),
		"service account": f.as(td.KindServiceAccount, tenancy.CredAPIKey, td.RoleOrgAdmin),
		"no step-up":      admin,
	} {
		if _, _, err := f.svc.Rotate(ctx); !errors.Is(err, webhookkeys.ErrStepUp) {
			t.Fatalf("%s: %v, want STEP_UP_REQUIRED", name, err)
		}
	}
	f.stepUp(t, "10 minutes")
	if _, _, err := f.svc.Rotate(admin); !errors.Is(err, webhookkeys.ErrStepUp) {
		t.Fatalf("stale step-up: %v", err)
	}
	var n int
	f.d.AdminQueryRow(t, "SELECT count(*) FROM pc.keys WHERE org_id = $1", []any{f.org}, &n)
	if n != 0 {
		t.Fatalf("refused rotations left %d keys", n)
	}

	f.stepUp(t, "1 minute")
	k, retiring, err := f.svc.Rotate(admin)
	if err != nil || k.State != keys.StateActive || retiring != "" {
		t.Fatalf("first rotation: %+v %q %v", k, retiring, err)
	}
	k2, retiring, err := f.svc.Rotate(f.as(td.KindUser, tenancy.CredBrowserSession, td.RoleOrgAdmin))
	if err != nil || retiring != k.KID || k2.KID == k.KID {
		t.Fatalf("second rotation: %+v %q %v", k2, retiring, err)
	}
	if _, _, err := f.svc.Rotate(admin); !errors.Is(err, webhookkeys.ErrRotating) {
		t.Fatalf("rotation during the overlap: %v", err)
	}
	ks, _, err := f.svc.List(admin)
	if err != nil || len(ks) != 2 || ks[0].KID != k2.KID || ks[1].KID != k.KID || ks[1].RetiresAt.IsZero() {
		t.Fatalf("keys %+v %v", ks, err)
	}
	f.d.AdminQueryRow(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.webhook_key.rotated'
		AND actor_type = 'user' AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'security_key' = $2`, []any{f.org, f.cred.String()}, &n)
	if n != 2 {
		t.Fatalf("rotation audits %d", n)
	}
}
