// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package exports

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/platform/sigv4"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type edition struct{ e billing.Edition }

func (e *edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: e.e}, nil
}

type fixture struct {
	d         *dbtest.DB
	p         *db.Pool
	svc       *Service
	ed        *edition
	org       ids.OrgID
	user, key ids.UUID
}

func newFixture(t *testing.T, cfg Config) *fixture {
	t.Helper()
	d := dbtest.New(t)
	f := &fixture{d: d, p: d.AppPool(t), org: ids.New[ids.Org](), user: ids.NewV7(), key: ids.NewV7(), ed: &edition{e: billing.Business}}
	kek := filepath.Join(t.TempDir(), "kek")
	if err := keys.GenerateKEKFile(kek); err != nil {
		t.Fatal(err)
	}
	kp, err := keys.NewFileProvider([]string{kek})
	if err != nil {
		t.Fatal(err)
	}
	env := pccrypto.NewEnvelope(keystore.NewCurrentCache(keystore.NewDEKStore(f.p, kp), time.Minute, clock.System{}))
	if cfg.PublicURL == "" {
		cfg.PublicURL = "https://pc.example.com"
	}
	f.svc, err = New(f.p, env, cfg, clock.System{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.svc.WithEditions(f.ed)
	f.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'exports')", f.org)
	f.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", f.org, f.user)
	f.exec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		f.org, f.key, f.user, bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 32))
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

func (f *fixture) as(kind td.PrincipalKind, roles ...td.RoleName) context.Context {
	bs := make([]td.Binding, 0, len(roles))
	for _, r := range roles {
		bs = append(bs, td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}})
	}
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{Org: f.org, Principal: td.PrincipalRef{Kind: kind, ID: f.user}, Bindings: bs},
	})
}

var s3Key = Credential{S3: sigv4.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "secret/value+1"}}

// TestHR513_ActivationNeedsAPersonAKeyAndBusiness: a destination is created
// PENDING by a person holding siem.manage on a Business licence, is
// activated only with a fresh step-up made with their own key, and its
// target rules hold at creation and again at activation.
// Covers: F517
func TestHR513_ActivationNeedsAPersonAKeyAndBusiness(t *testing.T) {
	f := newFixture(t, Config{})
	f.ed.e = billing.Team
	admin := f.as(td.KindUser, td.RoleSecurityAdmin)
	in := NewDestination{
		Name: "vault", Target: s3("https://s3.eu-west-1.amazonaws.com", "evidence-bkt"), DataClasses: []string{ClassEvidencePacks}, Credential: s3Key,
	}
	if _, err := f.svc.Create(admin, in); !errors.Is(err, ErrEdition) {
		t.Fatalf("Team edition: %v", err)
	}
	f.ed.e = billing.Business
	if _, err := f.svc.Create(f.as(td.KindUser, td.RoleAuditor), in); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("auditor: %v", err)
	}
	if _, err := f.svc.Create(f.as(td.KindServiceAccount, td.RoleSecurityAdmin), in); err == nil {
		t.Fatal("a service account created a destination")
	}
	for _, bad := range []NewDestination{
		{Name: "a", Target: put("https://10.0.0.5/x"), DataClasses: []string{ClassOrgExports}, Credential: Credential{BearerToken: "token-1234"}},
		{
			Name: "b", Target: Target{Kind: KindHTTPSPut, URL: "https://169.254.169.254/", Internal: true}, DataClasses: []string{ClassOrgExports},
			Credential: Credential{BearerToken: "token-1234"},
		},
		{Name: "c", Target: put("https://pc.example.com/x"), DataClasses: []string{ClassOrgExports}, Credential: Credential{BearerToken: "token-1234"}},
		{Name: "d", Target: put("https://s.example.net/"), DataClasses: []string{"payloads"}, Credential: Credential{BearerToken: "token-1234"}},
		{Name: "e", Target: put("https://s.example.net/"), DataClasses: []string{ClassOrgExports}, Credential: s3Key},
	} {
		if _, err := f.svc.Create(admin, bad); err == nil {
			t.Errorf("created %+v", bad.Target)
		}
	}
	d, err := f.svc.Create(admin, in)
	if err != nil {
		t.Fatal(err)
	}
	if d.State != StatePending || d.Health != HealthNotConfirmed || d.Bucket != "evidence-bkt" {
		t.Fatalf("created = %+v", d)
	}
	if _, err := f.svc.Create(admin, in); !errors.Is(err, ErrExists) {
		t.Fatalf("same name: %v", err)
	}

	now := time.Now()
	for name, su := range map[string]stepup.StepUp{
		"no step-up": {}, "stale": {Credential: f.key, At: now.Add(-10 * time.Minute)}, "unknown key": {Credential: ids.NewV7(), At: now},
	} {
		if _, err := f.svc.Activate(admin, d.ID, su); !errors.Is(err, stepup.ErrStepUp) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if got, err := f.svc.Get(f.as(td.KindUser, td.RoleAuditor), d.ID); err != nil || got.State != StatePending {
		t.Fatalf("refused activations changed it: %+v %v", got, err)
	}
	a, err := f.svc.Activate(admin, d.ID, stepup.StepUp{Credential: f.key, At: now})
	if err != nil {
		t.Fatal(err)
	}
	if a.State != StateActive || a.ActivatedBy == nil || *a.ActivatedBy != f.user {
		t.Fatalf("activated = %+v", a)
	}
	if _, err := f.svc.Activate(admin, d.ID, stepup.StepUp{Credential: f.key, At: now}); !errors.Is(err, ErrState) {
		t.Fatalf("second activation: %v", err)
	}
	list, next, err := f.svc.List(admin, 0, "")
	if err != nil || len(list) != 1 || next != "" {
		t.Fatalf("list: %d %q %v", len(list), next, err)
	}
	// A new credential never changes the target, and is checked for its
	// kind.
	if _, err := f.svc.ReplaceCredential(admin, d.ID, Credential{BearerToken: "token-1234"}); !errors.Is(err, ErrCredential) {
		t.Fatalf("a token for an s3 destination: %v", err)
	}
	r, err := f.svc.ReplaceCredential(admin, d.ID, s3Key)
	if err != nil || r.SecretReplacedAt == nil {
		t.Fatalf("replace: %+v %v", r, err)
	}
	// After the licence lapses, pausing and disabling still work; resuming
	// does not.
	f.ed.e = billing.Team
	if _, err := f.svc.SetState(admin, d.ID, StatePaused); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SetState(admin, d.ID, StateActive); !errors.Is(err, ErrEdition) {
		t.Fatalf("resume after lapse: %v", err)
	}
	if _, err := f.svc.SetState(admin, d.ID, StateDisabled); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SetState(admin, d.ID, StatePaused); !errors.Is(err, ErrState) {
		t.Fatalf("a disabled destination changed: %v", err)
	}
}

// TestHR513_ActivationRechecksTheTarget: a target stored before the rules
// changed is refused when a person activates it.
// Covers: F517
func TestHR513_ActivationRechecksTheTarget(t *testing.T) {
	f := newFixture(t, Config{})
	admin := f.as(td.KindUser, td.RoleSecurityAdmin)
	d, err := f.svc.Create(admin, NewDestination{
		Name: "vault", Target: put("https://s.example.net/in"), DataClasses: []string{ClassOrgExports}, Credential: Credential{BearerToken: "token-1234"},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.svc.ownHost = "s.example.net"
	if _, err := f.svc.Activate(admin, d.ID, stepup.StepUp{Credential: f.key, At: time.Now()}); !errors.Is(err, ErrURL) {
		t.Fatalf("got %v", err)
	}
}
