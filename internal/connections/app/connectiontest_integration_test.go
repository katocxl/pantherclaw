// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// failed is the codes of a test's failed checks.
func failed(r app.TestResult) []string {
	var out []string
	for _, c := range r.Checks {
		if !c.Passed {
			out = append(out, c.Check)
		}
	}
	return out
}

// TestF354_ConnectionTestsCheckWhatTheConnectionDependsOn: a test checks
// the connection's state, its gateway and the gateway's current
// certificate, its package's routes, a credential sealed to the gateway's
// active broker key and its circuits, without calling the target. Every
// result is kept; the declaration names the last passed one, which a later
// failure does not replace. Testing is for people holding
// connection.manage, and another org's connection is NotFound.
func TestF354_ConnectionTestsCheckWhatTheConnectionDependsOn(t *testing.T) {
	e := newEnv(t)
	c := e.payments(t, "payments")
	r, err := e.svc.Test(e.admin, c.ID, "")
	if err != nil || r.Result != app.TestFailed || len(r.Checks) != 6 ||
		!slices.Equal(failed(r), []string{app.CheckGatewayCertificate, app.CheckCredential}) {
		t.Fatalf("a connection without a certificate or credential: %+v %v", r, err)
	}
	if got, _ := e.svc.Capabilities(e.admin, c.ID); got.LastPassedTest != nil {
		t.Fatalf("a failed test is the last passed one: %+v", got.LastPassedTest)
	}

	cert, key, cred := ids.NewV7(), ids.NewV7(), ids.NewV7()
	e.exec(t, `INSERT INTO pc.gateway_certs (org_id, id, gateway_id, serial, key_thumbprint, issued_via, not_before, not_after)
		VALUES ($1, $2, $3, $4, $5, 'ENROLL', now(), now() + interval '24 hours')`, e.org, cert, e.gateway, cert[:16], bytes.Repeat([]byte("A"), 43))
	e.exec(t, `INSERT INTO pc.broker_keys (org_id, id, gateway_id, version, public_key, fingerprint, cert_id)
		VALUES ($1, $2, $3, 1, $4, 'sha256:' || encode(sha256($4), 'hex'), $5)`, e.org, key, e.gateway, bytes.Repeat([]byte{7}, 1216), cert)
	e.exec(t, `INSERT INTO pc.credentials (org_id, id, connection_id, version, broker_key_id, sealed, allowed_hosts, header, created_by)
		VALUES ($1, $2, $3, 1, $4, $5, '{payments.example.test}', 'Authorization', 'test')`, e.org, cred, c.ID, key, bytes.Repeat([]byte{1}, 1200))
	passed, err := e.svc.Test(e.admin, c.ID, "")
	if err != nil || passed.Result != app.TestPassed || len(failed(passed)) != 0 {
		t.Fatalf("a ready connection: %+v %v", passed, err)
	}

	if _, err := e.svc.Quarantine(e.admin, c.ID, "incident"); err != nil {
		t.Fatal(err)
	}
	if r, err := e.svc.Test(e.admin, c.ID, ""); err != nil || r.Result != app.TestFailed || !slices.Equal(failed(r), []string{app.CheckConnectionActive}) {
		t.Fatalf("a quarantined connection: %+v %v", r, err)
	}
	got, err := e.svc.Capabilities(e.admin, c.ID)
	if err != nil || got.LastPassedTest == nil || got.LastPassedTest.ID != passed.ID || got.LastPassedTest.Result != app.TestPassed {
		t.Fatalf("last passed test %+v %v", got.LastPassedTest, err)
	}
	if n := e.int64(t, "SELECT count(*) FROM pc.connection_tests WHERE connection_id = $1", c.ID); n != 3 {
		t.Fatalf("%d tests kept, want 3", n)
	}

	// A local connection needs no credential of PantherClaw's.
	shell, err := e.svc.Create(e.admin, app.CreateInput{
		Name: "laptop", Kind: app.KindLocal, Package: "pc.shell", Gateway: e.gateway, AccessMode: app.AccessNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	if r, err := e.svc.Test(e.admin, shell.ID, ""); err != nil || r.Result != app.TestPassed {
		t.Fatalf("local connection: %+v %v", r, err)
	}

	if _, err := e.svc.Test(e.caller(td.KindUser, td.RoleDeveloper), c.ID, ""); !denied(err) {
		t.Errorf("a developer tests: %v", err)
	}
	if _, err := e.svc.Test(e.caller(td.KindServiceAccount, td.RoleGatewayAdmin), c.ID, ""); !denied(err) {
		t.Errorf("a service account tests: %v", err)
	}
	theirs := e.withOrg(t).payments(t, "payments")
	if _, err := e.svc.Test(e.admin, theirs.ID, ""); !is(err, app.ErrNotFound) {
		t.Errorf("another org's: %v", err)
	}
}
