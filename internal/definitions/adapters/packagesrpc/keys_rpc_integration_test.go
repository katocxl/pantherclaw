// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package packagesrpc_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"testing"
	"time"

	"connectrpc.com/connect/v2"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type ents struct{ e billing.Entitlements }

func (e *ents) Current(context.Context) (billing.Entitlements, error) { return e.e, nil }

var team = billing.Entitlements{Edition: billing.Team, Status: billing.StatusValid}

// orgSigned returns the reference package renamed into an org namespace
// (with its own operations when ownOps) and targets signed by key.
func orgSigned(t *testing.T, raw []byte, key *jws.Signer, version int64, ownOps bool) ([]byte, string) {
	t.Helper()
	pkg := bytes.Replace(raw, []byte("name: pc.mock-payments"), []byte("name: acme.payments"), 1)
	if ownOps {
		pkg = bytes.ReplaceAll(pkg, []byte("payments.refund."), []byte("acmepay.refund."))
		pkg = bytes.ReplaceAll(pkg, []byte("payments.account."), []byte("acmepay.account."))
	}
	sum := sha256.Sum256(pkg)
	doc, err := trust.Sign(trust.Targets{
		Version: version, Expires: time.Now().Add(180 * 24 * time.Hour).UTC().Format(time.RFC3339),
		Targets: map[string]trust.Target{
			trust.Key("acme.payments", "1.0.0"): {Length: int64(len(pkg)), Hashes: map[string]string{"sha256": hex.EncodeToString(sum[:])}},
		},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pkg, doc
}

// TestIntRPC_HR162_OrgPackageSigningKeys drives the signing-key RPCs: an
// Org Admin (a person, Team edition) registers a key; a package signed with
// it imports into that org only and is activated by a Policy Publisher;
// revoking the key as compromised withdraws it (HR-162, T-056).
func TestIntRPC_HR162_OrgPackageSigningKeys(t *testing.T) {
	raw, rootDoc, roots := signedPackage(t)
	s := newStack(t, roots)
	ctx := context.Background()
	org, other := s.org(t), s.org(t)
	admin := s.clients(s.login(t, org, "admin", td.RoleOrgAdmin))
	publisher := s.clients(s.login(t, org, "publisher", td.RolePolicyPublisher))
	stranger := s.clients(s.login(t, other, "admin", td.RoleOrgAdmin))

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := jws.NewSigner(trust.OrgKID(pub), priv)
	jwk, _ := json.Marshal(jws.PublicJWK(pub, key.KeyID()))
	register := &pantherclawv1.RegisterSigningKeyRequest{Name: "release 2026", PublicJwk: string(jwk)}

	_, saKey := s.serviceAccount(t, org, []string{"package.key.manage", "package.read"}, td.RoleOrgAdmin)
	_, err = s.clients(saKey).packages.RegisterSigningKey(ctx, register)
	wantCode(t, "a service account registers a key", err, connect.CodePermissionDenied)
	_, err = publisher.packages.RegisterSigningKey(ctx, register)
	wantCode(t, "a Policy Publisher registers a key", err, connect.CodePermissionDenied)
	_, err = admin.packages.RegisterSigningKey(ctx, &pantherclawv1.RegisterSigningKeyRequest{Name: "bad\nname", PublicJwk: string(jwk)})
	wantCode(t, "a control character in the name", err, connect.CodeInvalidArgument)
	s.ents.e = billing.CommunityEntitlements()
	_, err = admin.packages.RegisterSigningKey(ctx, register)
	wantCode(t, "Community edition", err, connect.CodeFailedPrecondition)
	s.ents.e = team

	reg, err := admin.packages.RegisterSigningKey(ctx, register)
	if err != nil || reg.GetKey().GetKid() != key.KeyID() || reg.GetKey().GetState() != pantherclawv1.SigningKeyState_SIGNING_KEY_STATE_ACTIVE {
		t.Fatalf("RegisterSigningKey = %v, %v", reg, err)
	}

	// An org package that redefines PantherClaw's refund is refused once
	// PantherClaw's package is imported; one with its own operations imports.
	if _, err := admin.packages.ImportPackage(ctx, &pantherclawv1.ImportPackageRequest{
		Name: "pc.mock-payments", Version: "1.0.0", Targets: rootDoc, Package: raw,
	}); err != nil {
		t.Fatal(err)
	}
	shadow, shadowDoc := orgSigned(t, raw, key, 1, false)
	_, err = admin.packages.ImportPackage(ctx, &pantherclawv1.ImportPackageRequest{Name: "acme.payments", Version: "1.0.0", Targets: shadowDoc, Package: shadow})
	wantCode(t, "an org package redefining a PantherClaw operation", err, connect.CodeFailedPrecondition)
	pkg, doc := orgSigned(t, raw, key, 1, true)
	imp, err := admin.packages.ImportPackage(ctx, &pantherclawv1.ImportPackageRequest{Name: "acme.payments", Version: "1.0.0", Targets: doc, Package: pkg})
	if err != nil || imp.GetPackage().GetSigningKey() != key.KeyID() || imp.GetPackage().GetState() != pantherclawv1.PackageState_PACKAGE_STATE_REVIEWED {
		t.Fatalf("org-signed ImportPackage = %v, %v", imp, err)
	}
	// IDOR: another org neither sees the key nor trusts what it signed.
	if keys, err := stranger.packages.ListSigningKeys(ctx, &pantherclawv1.ListSigningKeysRequest{}); err != nil || len(keys.GetKeys()) != 0 {
		t.Fatalf("another org lists %v (%v)", keys, err)
	}
	_, err = stranger.packages.ImportPackage(ctx, &pantherclawv1.ImportPackageRequest{Name: "acme.payments", Version: "1.0.0", Targets: doc, Package: pkg})
	wantCode(t, "another org imports with this org's key", err, connect.CodeFailedPrecondition)
	_, err = stranger.packages.RevokeSigningKey(ctx, &pantherclawv1.RevokeSigningKeyRequest{
		Kid: key.KeyID(), Reason: pantherclawv1.SigningKeyRevokeReason_SIGNING_KEY_REVOKE_REASON_COMPROMISED,
	})
	wantCode(t, "another org revokes the key", err, connect.CodeNotFound)

	// Activation stays a separate step that the key's registrar cannot do.
	activate := &pantherclawv1.TransitionPackageRequest{Name: "acme.payments", Version: "1.0.0", State: pantherclawv1.PackageState_PACKAGE_STATE_ACTIVE}
	_, err = admin.packages.TransitionPackage(ctx, activate)
	wantCode(t, "the Org Admin activates", err, connect.CodePermissionDenied)
	if _, err := publisher.packages.TransitionPackage(ctx, activate); err != nil {
		t.Fatal(err)
	}
	list, err := publisher.packages.ListSigningKeys(ctx, &pantherclawv1.ListSigningKeysRequest{})
	if err != nil || len(list.GetKeys()) != 1 || list.GetKeys()[0].GetMetadataVersion() != 1 || list.GetKeys()[0].GetPublicJwk() == "" {
		t.Fatalf("ListSigningKeys = %v, %v", list, err)
	}

	// A lapsed licence refuses new org imports but keeps the active one.
	s.ents.e = billing.CommunityEntitlements()
	_, err = admin.packages.ImportPackage(ctx, &pantherclawv1.ImportPackageRequest{Name: "acme.payments", Version: "1.0.0", Targets: doc, Package: pkg})
	wantCode(t, "org-signed import on Community", err, connect.CodeFailedPrecondition)

	rev, err := admin.packages.RevokeSigningKey(ctx, &pantherclawv1.RevokeSigningKeyRequest{
		Kid: key.KeyID(), Reason: pantherclawv1.SigningKeyRevokeReason_SIGNING_KEY_REVOKE_REASON_COMPROMISED,
	})
	if err != nil || rev.GetKey().GetState() != pantherclawv1.SigningKeyState_SIGNING_KEY_STATE_REVOKED || len(rev.GetWithdrawn()) != 1 ||
		rev.GetWithdrawn()[0].GetState() != pantherclawv1.PackageState_PACKAGE_STATE_QUARANTINED {
		t.Fatalf("RevokeSigningKey = %v, %v", rev, err)
	}
	if _, err := publisher.packages.TransitionPackage(ctx, &pantherclawv1.TransitionPackageRequest{
		Name: "acme.payments", Version: "1.0.0", State: pantherclawv1.PackageState_PACKAGE_STATE_REVIEWED,
	}); err != nil {
		t.Fatal(err)
	}
	_, err = publisher.packages.TransitionPackage(ctx, activate)
	wantCode(t, "re-activating a compromised key's version", err, connect.CodeFailedPrecondition)
}
