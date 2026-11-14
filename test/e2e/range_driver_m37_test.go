// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bapp "github.com/katocxl/pantherclaw/internal/bundles/app"
	"github.com/katocxl/pantherclaw/internal/bundles/format"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const m37Channel = `{"kind":"log","description":"Ops notices","event_types":["bundle.revoked"],"settings":{"room":"ops"}}`

// bundleProbe runs bundle.probe (G0 M37; RT-240..RT-244).
func (d *rangeDriver) bundleProbe(st domain.Step) (domain.Observation, error) {
	var w struct {
		Attack string `json:"attack"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	switch w.Attack {
	case "spoofed_listing":
		return d.spoofedListing()
	case "executable":
		ctx, svc, priv, _ := d.bundleAdmin()
		raw := m37Bundle(d.t, "acme", priv, "1.0.0", []byte("#!/bin/sh\necho hi\n"), "ext.acme.ops")
		_, err := svc.InstallBundle(ctx, raw)
		return bundleObs(err), nil
	case "namespace":
		ctx, svc, priv, _ := d.bundleAdmin()
		raw := m37Bundle(d.t, "acme", priv, "1.0.0", []byte(m37Channel), "ext.other.ops")
		_, err := svc.InstallBundle(ctx, raw)
		return bundleObs(err), nil
	case "stolen_key":
		ctx, svc, priv, cred := d.bundleAdmin()
		if err := m37Activate(d.t, ctx, svc, priv, cred); err != nil {
			return domain.Observation{}, err
		}
		_, stolen, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return domain.Observation{}, err
		}
		raw := m37Bundle(d.t, "acme", stolen, "1.0.0", []byte(m37Channel), "ext.acme.ops")
		_, err = svc.InstallBundle(ctx, raw)
		return bundleObs(err), nil
	case "rollback":
		ctx, svc, priv, cred := d.bundleAdmin()
		if err := m37Activate(d.t, ctx, svc, priv, cred); err != nil {
			return domain.Observation{}, err
		}
		if _, err := svc.InstallBundle(ctx, m37Bundle(d.t, "acme", priv, "1.0.0", []byte(m37Channel), "ext.acme.ops")); err != nil {
			return domain.Observation{}, err
		}
		_, err := svc.InstallBundle(ctx, m37Bundle(d.t, "acme", priv, "0.9.0", []byte(m37Channel), "ext.acme.ops"))
		return bundleObs(err), nil
	default:
		return domain.Observation{}, fmt.Errorf("bundle.probe attack %q", w.Attack)
	}
}

func (d *rangeDriver) bundleAdmin() (context.Context, *bapp.Service, ed25519.PrivateKey, ids.UUID) {
	d.t.Helper()
	user, cred := ids.NewV7(), ids.NewV7()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		d.t.Fatal(err)
	}
	d.s.db.AdminExec(d.t, `INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)`, d.s.org, user, "m37-"+user.String())
	d.s.db.AdminExec(d.t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		d.s.org, cred, user, secret[:16], secret)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		d.t.Fatal(err)
	}
	svc := bapp.New(d.s.pool, bapp.Deps{}, bapp.Config{PublicURL: "https://pc.example.test"}, clock.System{}, nil)
	ctx := tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{
			Org: d.s.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user},
			Bindings: []td.Binding{{Role: td.RoleOrgAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: d.s.org.UUID()}}},
		},
		Credential: tenancy.CredBrowserSession,
	})
	return ctx, svc, priv, cred
}

func (d *rangeDriver) spoofedListing() (domain.Observation, error) {
	repo := filepath.Join("..", "..")
	root := d.t.TempDir()
	dir := filepath.Join(root, "marketplace", "listings")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return domain.Observation{}, err
	}
	listing := `{"publisher":"acme","display_name":"Acme","homepage":"http://acme.example/","keys":[{"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","fingerprint":"` + strings.Repeat("ab", 32) + `"}],"bundles":[]}`
	if err := os.WriteFile(filepath.Join(dir, "acme.json"), []byte(listing+"\n"), 0o600); err != nil {
		return domain.Observation{}, err
	}
	var stderr bytes.Buffer
	cmd := exec.Command("go", "run", ".", "-root", root, "-out", filepath.Join(d.t.TempDir(), "dist"))
	cmd.Dir = filepath.Join(repo, "tools", "marketplace")
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if strings.Contains(stderr.String(), "https") {
			return domain.Observation{Outcome: domain.OutcomeRefused, Reason: "LISTING_REFUSED", Detail: stderr.String()}, nil
		}
		return domain.Observation{}, fmt.Errorf("marketplace: %w: %s", err, stderr.String())
	}
	return domain.Observation{Outcome: domain.OutcomeAllow, Detail: stderr.String()}, nil
}

func bundleObs(err error) domain.Observation {
	if err == nil {
		return domain.Observation{Outcome: domain.OutcomeAllow}
	}
	reason := pcerr.ReasonOf(err)
	if reason == "" {
		var fe *format.Error
		if errors.As(err, &fe) {
			reason = fe.Code
		}
	}
	if reason == "" {
		reason = "REFUSED"
	}
	return domain.Observation{Outcome: domain.OutcomeRefused, Reason: reason, Detail: err.Error()}
}

func m37Activate(t *testing.T, ctx context.Context, svc *bapp.Service, priv ed25519.PrivateKey, cred ids.UUID) error {
	t.Helper()
	pub, _ := priv.Public().(ed25519.PublicKey)
	p, err := svc.PinKey(ctx, bapp.NewPin{Publisher: "acme", PublicKey: pub})
	if err != nil {
		return err
	}
	_, err = svc.ActivatePin(ctx, p.ID, &stepup.StepUp{Credential: cred, At: time.Now().Add(-2 * time.Minute)})
	return err
}

// TestE2E_M37_PublishersAndBundles is M37's exit: a publisher key trusts
// nothing until a person activates it with a step-up, an install lands as
// a template, and revocation stops that version (G0 M37).
// Covers: HR-795, HR-798, HR-799
func TestE2E_M37_PublishersAndBundles(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	org := ids.New[ids.Org]()
	user, credID := ids.NewV7(), ids.NewV7()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	d.AdminExec(t, `INSERT INTO pc.orgs (id, name) VALUES ($1, 'bundles')`, org)
	d.AdminExec(t, `INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'ada')`, org, user)
	d.AdminExec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		org, credID, user, secret[:16], secret)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	svc := bapp.New(p, bapp.Deps{}, bapp.Config{PublicURL: "https://pc.example.test"}, clock.System{}, nil)
	ctx := tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{
			Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user},
			Bindings: []td.Binding{{Role: td.RoleOrgAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}},
		},
		Credential: tenancy.CredBrowserSession,
	})
	pin, err := svc.PinKey(ctx, bapp.NewPin{Publisher: "acme", PublicKey: pub})
	if err != nil || pin.State != "PENDING" {
		t.Fatalf("pin %+v %v", pin, err)
	}
	if _, err := svc.ActivatePin(ctx, pin.ID, nil); !errors.Is(err, stepup.ErrStepUp) {
		t.Fatalf("activate over RPC: %v", err)
	}
	if _, err := svc.InstallBundle(ctx, m37Bundle(t, "acme", priv, "1.0.0", []byte(m37Channel), "ext.acme.ops")); pcerr.ReasonOf(err) != "PUBLISHER_NOT_PINNED" {
		t.Fatalf("install before activation: %v", err)
	}
	if _, err := svc.ActivatePin(ctx, pin.ID, &stepup.StepUp{Credential: credID, At: time.Now().Add(-2 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	in, err := svc.InstallBundle(ctx, m37Bundle(t, "acme", priv, "1.0.0", []byte(m37Channel), "ext.acme.ops"))
	if err != nil || in.State != "INSTALLED" || len(in.Items) != 1 || in.Items[0].State != "TEMPLATE" {
		t.Fatalf("install %+v %v", in, err)
	}
	if _, err := svc.RevokeInstall(ctx, in.ID); err != nil {
		t.Fatal(err)
	}
	got, err := svc.GetInstall(ctx, in.ID)
	if err != nil || got.State != "REVOKED" || got.Items[0].State != "REVOKED" {
		t.Fatalf("revoked %+v %v", got, err)
	}
}

func m37Bundle(t *testing.T, publisher string, priv ed25519.PrivateKey, version string, body []byte, item string) []byte {
	t.Helper()
	sum := sha256.Sum256(body)
	raw, err := json.Marshal(format.Manifest{
		Spec: format.Spec, Publisher: publisher, Name: "ext." + publisher + ".starter", Version: version,
		Title: "Ops bundle", Summary: "A channel template.",
		Items: []format.ManifestItem{{
			Kind: format.KindChannelTemplate, Name: item, Path: "items/channel_template/ops.json",
			SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body)),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	signer, err := jws.NewSigner(format.KID(publisher, pub), priv)
	if err != nil {
		t.Fatal(err)
	}
	// A namespace the signer does not own never gets a signature. Decode
	// refuses it from the manifest alone.
	if item != "ext."+publisher+".ops" {
		return m37Zip(t, raw, "unsigned", body)
	}
	now := time.Now().UTC().Truncate(time.Second)
	sig, err := format.Sign(signer, raw, now, now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return m37Zip(t, raw, sig, body)
}

func m37Zip(t *testing.T, manifest []byte, sig string, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range map[string][]byte{
		format.ManifestFile: manifest, format.SignatureFile: []byte(sig + "\n"), "items/channel_template/ops.json": body,
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
