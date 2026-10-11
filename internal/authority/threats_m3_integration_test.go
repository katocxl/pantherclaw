// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package authority_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json/v2"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/domain"
	iapp "github.com/katocxl/pantherclaw/internal/identity/app"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m3tReenrolled enrolls a new key for agent through the real enrollment
// flow, has the owner admit it, and issues its workload token.
func m3tReenrolled(t *testing.T, f idFixture) workload {
	t.Helper()
	ctx := context.Background()
	team := td.Scope{Type: td.ScopeTeam, ID: f.team}
	owner := tenancy.WithCaller(ctx, tenancy.Caller{Subject: td.Subject{
		Org: f.gw.Org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: f.owner},
		Bindings: []td.Binding{{Role: td.RoleAgentOwner, Scope: team}, {Role: td.RoleAgentAdmitter, Scope: team}},
	}})
	pub, key, _ := ed25519.GenerateKey(nil)
	checked := func(url string, body []byte) pap.Checked {
		t.Helper()
		n, err := f.ident.Nonce(ctx, f.gw.Org)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := pap.NewProof(key, pap.ProofParams{Method: "POST", URL: url, Body: body, Nonce: n, Now: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		c, err := pap.VerifyRequest(nil, pcIssuer, pap.Request{Method: "POST", URL: url, BodySHA256: sha256.Sum256(body)}, proof, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	et, err := f.ident.CreateEnrollmentToken(owner, f.wl.inst.Agent, 0)
	if err != nil {
		t.Fatal(err)
	}
	secret := et.Secret.Reveal()
	jwk, _ := json.Marshal(jws.PublicJWK(pub, ""))
	e, err := f.ident.Enroll(ctx, iapp.EnrollInput{
		Proof: checked(pcIssuer+"/pantherclaw.v1.WorkloadService/Enroll", []byte(secret)), EnrollmentToken: secret, PublicJWK: jwk,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.ident.Admit(owner, e.Instance.Instance, e.Fingerprint); err != nil {
		t.Fatal(err)
	}
	iss, err := f.ident.IssueToken(ctx, iapp.TokenInput{
		Proof: checked(pcIssuer+"/pantherclaw.v1.WorkloadService/IssueToken", []byte(e.Instance.String())), Identifier: e.Instance.String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return workload{key: key, inst: e.Instance, token: iss.Token}
}

// TestT049_AReenrolledInstanceIsDeniedTheOldRun: T-049 at the Authority —
// the workload behind an instance that holds a run enrolls a new key
// through the real enrollment flow, is admitted and gets a genuine workload
// token. Its action under the old instance's run is DENY RUN_MISMATCH,
// records no transaction and binds nothing, while the old instance is
// still allowed. Re-attestation, ownership transfer and reused names are
// TestT049_NewIdentitiesInheritNoRuns (internal/identity/app).
func TestT049_AReenrolledInstanceIsDeniedTheOldRun(t *testing.T) {
	f := setupIdentity(t)
	fresh := m3tReenrolled(t, f)
	wantDecision(t, "the re-enrolled instance on the old run", f.authorizeAs(t, fresh, f.run, f.creds(t, fresh, fresh.token)),
		domain.Deny, domain.ReasonRunMismatch, "")
	if res := f.authorizeAs(t, f.wl, f.run, f.creds(t, f.wl, f.wl.token)); res.Decision != domain.Allow {
		t.Fatalf("the run's own instance: %+v", res)
	}
	var held int
	if err := f.pool.InTenantTx(context.Background(), f.gw.Org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM pc.runs WHERE org_id = $1 AND instance_id = $2", f.gw.Org, fresh.inst.Instance).Scan(&held)
	}); err != nil {
		t.Fatal(err)
	}
	if held != 0 {
		t.Errorf("the re-enrolled instance holds %d runs", held)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.transactions WHERE org_id = $1"); n != 1 {
		t.Errorf("transactions %d, want only the allowed one", n)
	}
}
