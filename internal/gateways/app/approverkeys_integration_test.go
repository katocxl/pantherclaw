// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"bytes"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/approvals/proof"
	"github.com/katocxl/pantherclaw/internal/authn/webauthntest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR038_ApproverKeysAreTheActiveKeysOfEnabledPeople: the export lists
// each enabled person's active security keys as the gateway pins them (the
// DER public key the authenticator holds, its algorithm and fingerprint),
// leaves out suspended and removed keys and disabled people, and needs
// gateway.read.
func TestHR038_ApproverKeysAreTheActiveKeysOfEnabledPeople(t *testing.T) {
	e := newEnv(t)
	bob, carol := ids.NewV7(), ids.NewV7()
	e.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject, email) VALUES ($1, $2, 'https://idp.test', 'bob', 'bob@example.test')", e.org, bob)
	e.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject, state) VALUES ($1, $2, 'https://idp.test', 'carol', 'DISABLED')", e.org, carol)
	keyOf := func(user ids.UUID, state, reason string) (*webauthntest.Authenticator, ids.UUID) {
		k, err := webauthntest.New("https://localhost", "localhost", webauthntest.ES256)
		if err != nil {
			t.Fatal(err)
		}
		cose, err := k.COSEKey()
		if err != nil {
			t.Fatal(err)
		}
		id := ids.NewV7()
		var why any
		var changed any
		if reason != "" {
			why, changed = reason, "now"
		}
		e.exec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible, backup_state,
			attestation_fmt, name, state, state_reason, changed_at) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key', $6, $7,
			CASE WHEN $8::text IS NULL THEN NULL ELSE now() END)`, e.org, id, user, k.CredentialID(), cose, state, why, changed)
		return k, id
	}
	active, activeID := keyOf(bob, "ACTIVE", "")
	keyOf(bob, "SUSPENDED", "CLONE_SUSPECTED")
	keyOf(bob, "REMOVED", "USER_REMOVED")
	keyOf(carol, "ACTIVE", "")

	keys, org, next, err := e.svc.ListApproverKeys(e.caller(td.KindUser, td.RoleAuditor), 0, "")
	if err != nil || org != e.org || next != "" || len(keys) != 1 {
		t.Fatalf("= %d keys of %s, next %q: %v", len(keys), org, next, err)
	}
	want, _ := x509.MarshalPKIXPublicKey(active.PublicKey())
	k := keys[0]
	if k.ID != activeID || k.User != bob || k.Email != "bob@example.test" || !bytes.Equal(k.CredentialID, active.CredentialID()) ||
		k.Algorithm != proof.AlgES256 || !bytes.Equal(k.PublicKey, want) || k.Fingerprint != proof.Fingerprint(want) {
		t.Fatalf("key %+v", k)
	}
	if _, _, _, err := e.svc.ListApproverKeys(e.caller(td.KindUser, td.RoleDeveloper), 0, ""); err == nil || !strings.Contains(err.Error(), "gateway.read") {
		t.Fatalf("a developer listed approver keys: %v", err)
	}
}
