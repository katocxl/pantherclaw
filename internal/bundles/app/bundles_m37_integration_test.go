// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	autoapp "github.com/katocxl/pantherclaw/internal/automations/app"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	bdomain "github.com/katocxl/pantherclaw/internal/bundles/domain"
	"github.com/katocxl/pantherclaw/internal/bundles/format"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexapp "github.com/katocxl/pantherclaw/internal/reflex/app"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const channelBody = `{"kind":"log","description":"Ops notices","event_types":["bundle.revoked"],"settings":{"room":"ops"}}`

type noteBox struct{ n int }

func (b *noteBox) Enqueue(context.Context, db.TenantTx, napp.Message) (napp.Enqueued, error) {
	b.n++
	return napp.Enqueued{}, nil
}

type rig struct {
	t          *testing.T
	d          *dbtest.DB
	p          *db.Pool
	org        ids.OrgID
	user, cred ids.UUID
	svc        *Service
	notes      *noteBox
	pub        ed25519.PublicKey
	priv       ed25519.PrivateKey
}

func newRig(t *testing.T) *rig {
	t.Helper()
	d := dbtest.New(t)
	p := d.AppPool(t)
	org := ids.New[ids.Org]()
	user, cred := ids.NewV7(), ids.NewV7()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	d.AdminExec(t, `INSERT INTO pc.orgs (id, name) VALUES ($1, 'bundles')`, org)
	d.AdminExec(t, `INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'ada')`, org, user)
	d.AdminExec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		org, cred, user, secret[:16], secret)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notes := &noteBox{}
	svc := New(p, Deps{Notify: notes}, Config{PublicURL: "https://pc.example.test"}, clock.System{}, nil)
	return &rig{t: t, d: d, p: p, org: org, user: user, cred: cred, svc: svc, notes: notes, pub: pub, priv: priv}
}

func (r *rig) as(role td.RoleName, cred tenancy.Credential) context.Context {
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{
			Org: r.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: r.user},
			Bindings: []td.Binding{{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: r.org.UUID()}}},
		},
		Credential: cred,
	})
}

func (r *rig) admin() context.Context {
	return r.as(td.RoleOrgAdmin, tenancy.CredBrowserSession)
}

func (r *rig) fresh() *stepup.StepUp {
	return &stepup.StepUp{Credential: r.cred, At: time.Now().Add(-2 * time.Minute)}
}

func (r *rig) pin(kinds ...string) Pin {
	r.t.Helper()
	p, err := r.svc.PinKey(r.admin(), NewPin{Publisher: "acme", PublicKey: r.pub, AllowedKinds: kinds})
	if err != nil {
		r.t.Fatal(err)
	}
	return p
}

func (r *rig) activate(id ids.UUID) Pin {
	r.t.Helper()
	p, err := r.svc.ActivatePin(r.admin(), id, r.fresh())
	if err != nil {
		r.t.Fatal(err)
	}
	return p
}

func (r *rig) bundle(version, body string) []byte {
	r.t.Helper()
	return channelBundle(r.t, "acme", r.priv, version, []byte(body))
}

func (r *rig) install(raw []byte) Install {
	r.t.Helper()
	in, err := r.svc.InstallBundle(r.admin(), raw)
	if err != nil {
		r.t.Fatal(err)
	}
	return in
}

func (r *rig) ledger(kind string) int {
	r.t.Helper()
	var n int
	err := r.p.InTenantTx(context.Background(), r.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = $2`, r.org, kind).Scan(&n)
	}, db.ReadOnly())
	if err != nil {
		r.t.Fatal(err)
	}
	return n
}

func TestHR795_APinTrustsNothingUntilStepUp(t *testing.T) {
	r := newRig(t)
	if _, err := r.svc.PinKey(r.as(td.RoleViewer, tenancy.CredBrowserSession), NewPin{Publisher: "acme", PublicKey: r.pub}); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("viewer: %v", err)
	}
	if _, err := r.svc.PinKey(r.as(td.RoleOrgAdmin, tenancy.CredAPIKey), NewPin{Publisher: "acme", PublicKey: r.pub}); !errors.Is(err, bdomain.ErrHuman) {
		t.Fatalf("API key: %v", err)
	}
	if _, err := r.svc.PinKey(r.admin(), NewPin{Publisher: "acme", PublicKey: r.pub, ExpectedFingerprint: hex.EncodeToString(bytes.Repeat([]byte{1}, 32))}); !errors.Is(err, bdomain.ErrFingerprint) {
		t.Fatalf("fingerprint: %v", err)
	}

	p := r.pin()
	if p.State != bdomain.PinPending {
		t.Fatalf("pending pin %+v", p)
	}
	if !strings.Contains(r.svc.ConfirmURL(p.ID), "/integrations/publisher-pins/"+p.ID.String()+"/confirm") {
		t.Fatalf("confirm url %s", r.svc.ConfirmURL(p.ID))
	}
	if _, err := r.svc.ActivatePin(r.admin(), p.ID, nil); !errors.Is(err, stepup.ErrStepUp) {
		t.Fatalf("RPC activate: %v", err)
	}
	stale := &stepup.StepUp{Credential: r.cred, At: time.Now().Add(-10 * time.Minute)}
	if _, err := r.svc.ActivatePin(r.admin(), p.ID, stale); !errors.Is(err, stepup.ErrStepUp) {
		t.Fatalf("stale step-up: %v", err)
	}
	got := r.activate(p.ID)
	if got.State != bdomain.PinActive || got.ActivatedBy == nil {
		t.Fatalf("activated %+v", got)
	}
	if _, err := r.svc.PinKey(r.admin(), NewPin{Publisher: "acme", PublicKey: r.pub}); !errors.Is(err, bdomain.ErrPinExists) {
		t.Fatalf("second pin: %v", err)
	}
	err := r.p.InTenantTx(context.Background(), r.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, `UPDATE pc.publisher_pins SET state = 'PENDING' WHERE org_id = $1 AND id = $2`, r.org, p.ID)
		return err
	})
	if err == nil {
		t.Fatal("the guard allowed ACTIVE to go back to PENDING")
	}
	if _, _, err := r.svc.RevokePin(r.admin(), p.ID, bdomain.ReasonUnpinned); err != nil {
		t.Fatal(err)
	}
	again := r.pin()
	if again.State != bdomain.PinPending {
		t.Fatalf("re-pin after UNPINNED: %+v", again)
	}
	if _, err := r.svc.ActivatePin(r.admin(), again.ID, r.fresh()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.svc.RevokePin(r.admin(), again.ID, bdomain.ReasonCompromised); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.PinKey(r.admin(), NewPin{Publisher: "acme", PublicKey: r.pub}); !errors.Is(err, bdomain.ErrKeyWithdrawn) {
		t.Fatalf("re-pin after COMPROMISED: %v", err)
	}
}

func TestHR796_InstallChecksThePinTheDigestAndTheNamespace(t *testing.T) {
	r := newRig(t)
	raw := r.bundle("1.0.0", channelBody)
	if _, err := r.svc.InstallBundle(r.admin(), raw); pcerr.ReasonOf(err) != "PUBLISHER_NOT_PINNED" {
		t.Fatalf("no pin: %v", err)
	}
	p := r.pin(string(format.KindDetectionRule))
	r.activate(p.ID)
	if _, err := r.svc.InstallBundle(r.admin(), raw); pcerr.ReasonOf(err) != "BUNDLE_KIND_NOT_ALLOWED" {
		t.Fatalf("kind: %v", err)
	}
	if _, _, err := r.svc.RevokePin(r.admin(), p.ID, bdomain.ReasonUnpinned); err != nil {
		t.Fatal(err)
	}
	p = r.pin()
	r.activate(p.ID)
	in := r.install(raw)
	if in.State != bdomain.InstallInstalled || len(in.Items) != 1 || in.Items[0].State != bdomain.ItemTemplate {
		t.Fatalf("install %+v", in)
	}
	if _, err := r.svc.InstallBundle(r.admin(), raw); !errors.Is(err, errAlreadyInstalled) {
		t.Fatalf("same file again: %v", err)
	}
	if _, err := r.svc.InstallBundle(r.admin(), r.bundle("1.0.0", strings.Replace(channelBody, `"ops"`, `"ops2"`, 1))); pcerr.ReasonOf(err) != "EQUIVOCATION" {
		t.Fatalf("equivocation: %v", err)
	}
	if _, err := r.svc.InstallBundle(r.admin(), r.bundle("0.9.0", channelBody)); pcerr.ReasonOf(err) != "ROLLBACK" {
		t.Fatalf("rollback: %v", err)
	}
}

func TestHR798_InstallLeavesItemsAsDraftsOrTemplates(t *testing.T) {
	r := newRig(t)
	p := r.pin()
	r.activate(p.ID)
	in := r.install(r.bundle("1.0.0", channelBody))
	it := in.Items[0]
	if it.State != bdomain.ItemTemplate || it.TargetType != bdomain.TargetTemplate || it.Kind != string(format.KindChannelTemplate) {
		t.Fatalf("item %+v", it)
	}
	if in.State != bdomain.InstallInstalled {
		t.Fatalf("state %s", in.State)
	}
}

func TestHR799_RevocationStopsTheInstallAndAlerts(t *testing.T) {
	r := newRig(t)
	p := r.pin()
	r.activate(p.ID)
	first := r.install(r.bundle("1.0.0", channelBody))
	if _, _, err := r.svc.RevokePin(r.admin(), p.ID, bdomain.ReasonUnpinned); err != nil {
		t.Fatal(err)
	}
	still, err := r.svc.GetInstall(r.as(td.RoleAuditor, tenancy.CredBrowserSession), first.ID)
	if err != nil || still.State != bdomain.InstallInstalled {
		t.Fatalf("UNPINNED revoked an install: %+v %v", still, err)
	}
	if _, err := r.svc.InstallBundle(r.admin(), r.bundle("1.1.0", channelBody)); pcerr.ReasonOf(err) != "PUBLISHER_NOT_PINNED" {
		t.Fatalf("install after UNPINNED: %v", err)
	}
	p = r.pin()
	r.activate(p.ID)
	second := r.install(r.bundle("1.1.0", channelBody))
	revoked, err := r.svc.RevokeInstall(r.admin(), second.ID)
	if err != nil || len(revoked) != 2 {
		t.Fatalf("revoke %v %v", revoked, err)
	}
	for _, id := range []ids.UUID{first.ID, second.ID} {
		in, err := r.svc.GetInstall(r.admin(), id)
		if err != nil || in.State != bdomain.InstallRevoked || len(in.Items) != 1 || in.Items[0].State != bdomain.ItemRevoked {
			t.Fatalf("after revoke %+v %v", in, err)
		}
	}
	if r.notes.n != 2 {
		t.Fatalf("notifications %d, want one per revoked install", r.notes.n)
	}
	if r.ledger("audit.bundle.revoked") != 2 {
		t.Fatalf("ledger rows %d", r.ledger("audit.bundle.revoked"))
	}
	if _, err := r.svc.InstallBundle(r.admin(), r.bundle("1.0.0", channelBody)); !errors.Is(err, bdomain.ErrBundleRevoked) {
		t.Fatalf("reinstall of a revoked version: %v", err)
	}
	resumed := r.install(r.bundle("1.2.0", channelBody))
	if resumed.State != bdomain.InstallInstalled {
		t.Fatalf("a later version: %+v", resumed)
	}
}

func TestHR800_AStatementNeedsAKeyTheOrgPinned(t *testing.T) {
	r := newRig(t)
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.SubmitRevocation(r.admin(), revocation(t, "acme", other)); pcerr.ReasonOf(err) != "PUBLISHER_NOT_PINNED" {
		t.Fatalf("unpinned key: %v", err)
	}
	p := r.pin()
	r.activate(p.ID)
	in := r.install(r.bundle("1.0.0", channelBody))
	stmt := revocation(t, "acme", r.priv)
	applied, err := r.svc.SubmitRevocation(r.admin(), stmt)
	if err != nil || applied.AlreadyApplied || len(applied.Installs) != 1 || applied.Installs[0] != in.ID {
		t.Fatalf("statement %+v %v", applied, err)
	}
	again, err := r.svc.SubmitRevocation(r.admin(), stmt)
	if err != nil || !again.AlreadyApplied {
		t.Fatalf("second statement %+v %v", again, err)
	}
}

// TestHR799_RevokedPlaybookAndRuleStayOff: a REVOKED bundle item keeps its
// playbook and its custom rule off. Resuming the playbook and publishing
// the rule are refused with BUNDLE_REVOKED before either object is loaded
// (G0 M37 D1083a).
func TestHR799_RevokedPlaybookAndRuleStayOff(t *testing.T) {
	r := newRig(t)
	playbook, rule := ids.NewV7(), ids.NewV7()
	install := ids.NewV7()
	sha := strings.Repeat("ab", 32)
	r.d.AdminExec(t, `INSERT INTO pc.bundle_installs (org_id, id, publisher, name, version, bundle_sha256, installed_by)
		VALUES ($1, $2, 'acme', 'ext.acme.starter', '1.0.0', $3, $4)`, r.org, install, sha, r.user)
	r.d.AdminExec(t, `INSERT INTO pc.bundle_items (org_id, install_id, kind, name, sha256, target_type, target_id, state)
		VALUES ($1, $2, 'playbook', 'ext.acme.stay-off', $3, 'automation', $4, 'REVOKED')`,
		r.org, install, sha, playbook.String())
	r.d.AdminExec(t, `INSERT INTO pc.bundle_items (org_id, install_id, kind, name, sha256, target_type, target_id, state)
		VALUES ($1, $2, 'detection_rule', 'ext.acme.stay_off', $3, 'custom_rule', $4, 'REVOKED')`,
		r.org, install, sha, rule.String())

	autos := &autoapp.Service{Pool: r.p, Editions: businessEnts{}}
	if _, _, err := autos.ResumeAutomation(r.as(td.RoleAutomationAuthor, tenancy.CredBrowserSession), playbook); !errors.Is(err, autoapp.ErrBundleRevoked) {
		t.Fatalf("resume: %v", err)
	}
	det := &reflexapp.Detections{Pool: r.p, Ents: businessEnts{}}
	if _, _, err := det.PublishCustomRule(r.as(td.RoleSecurityAdmin, tenancy.CredBrowserSession), rule); !errors.Is(err, reflexapp.ErrBundleRevoked) {
		t.Fatalf("publish: %v", err)
	}
}

// businessEnts is the Business edition, which includes automations and
// custom detection rules.
type businessEnts struct{}

func (businessEnts) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Business}, nil
}

func revocation(t *testing.T, publisher string, priv ed25519.PrivateKey) string {
	t.Helper()
	pub, _ := priv.Public().(ed25519.PublicKey)
	s, err := jws.NewSigner(format.KID(publisher, pub), priv)
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := format.SignRevocation(s, format.Revocation{
		Publisher: publisher, Scope: format.ScopeKey, Kid: s.KeyID(), IssuedAt: time.Now().Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return stmt
}

func channelBundle(t *testing.T, publisher string, priv ed25519.PrivateKey, version string, body []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(body)
	raw, err := json.Marshal(format.Manifest{
		Spec: format.Spec, Publisher: publisher, Name: "ext." + publisher + ".starter", Version: version,
		Title: "Ops bundle", Summary: "A channel template.",
		Items: []format.ManifestItem{{
			Kind: format.KindChannelTemplate, Name: "ext." + publisher + ".ops", Path: "items/channel_template/ops.json",
			SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body)),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	s, err := jws.NewSigner(format.KID(publisher, pub), priv)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	sig, err := format.Sign(s, raw, now, now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range map[string][]byte{
		format.ManifestFile: raw, format.SignatureFile: []byte(sig + "\n"), "items/channel_template/ops.json": body,
	} {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate, Modified: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
		h.SetMode(0o644)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
