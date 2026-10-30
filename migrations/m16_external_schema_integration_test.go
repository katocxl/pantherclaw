// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func (f govFixture) externalCheck(p *db.Pool, id ids.UUID, name, endpoint, state string) error {
	return m10Exec(p, f.org, `INSERT INTO pc.external_policy_checks (org_id, id, name, endpoint, operations, state, created_by)
		VALUES ($1, $2, $3, $4, '{stripe.*}', $5, 'user:x')`, f.org, id, name, endpoint, state)
}

func (f govFixture) activate(p *db.Pool, id ids.UUID) error {
	return m10Exec(p, f.org, "UPDATE pc.external_policy_checks SET state = 'ACTIVE', activated_by = $2, activated_credential = $3 WHERE id = $1",
		id, f.user, f.cred)
}

// TestHR438_ChecksStartPendingAndActivateOnceWithAKey (00199): a check is
// inserted PENDING with an https endpoint, becomes ACTIVE only with a
// person and a key, keeps its target, stays DISABLED, and at most three
// are ACTIVE per org.
// Covers: F366
func TestHR438_ChecksStartPendingAndActivateOnceWithAKey(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	f := govOrg(t, p)
	if err := f.externalCheck(p, ids.NewV7(), "active", "https://opa.example.com/x", "ACTIVE"); err == nil {
		t.Fatal("a check was inserted ACTIVE")
	}
	if err := f.externalCheck(p, ids.NewV7(), "plain", "http://opa.example.com/x", "PENDING"); err == nil {
		t.Fatal("an http endpoint was accepted")
	}
	var checks []ids.UUID
	for i, name := range []string{"one", "two", "three", "four"} {
		id := ids.NewV7()
		if err := f.externalCheck(p, id, name, "https://opa.example.com/"+name, "PENDING"); err != nil {
			t.Fatalf("%d: %v", i, err)
		}
		checks = append(checks, id)
	}
	if err := m10Exec(p, f.org, "UPDATE pc.external_policy_checks SET state = 'ACTIVE' WHERE id = $1", checks[0]); err == nil {
		t.Fatal("activated without a person and a key")
	}
	for _, id := range checks[:3] {
		if err := f.activate(p, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.activate(p, checks[3]); !db.IsCheckViolation(err) {
		t.Fatalf("a fourth active check: %v", err)
	}
	if err := m10Exec(p, f.org, "UPDATE pc.external_policy_checks SET endpoint = 'https://opa.example.com/other' WHERE id = $1", checks[0]); err == nil {
		t.Fatal("an active check's endpoint changed")
	}
	if err := m10Exec(p, f.org, "UPDATE pc.external_policy_checks SET state = 'DISABLED' WHERE id = $1", checks[0]); err != nil {
		t.Fatal(err)
	}
	if err := m10Exec(p, f.org, "UPDATE pc.external_policy_checks SET state = 'ACTIVE' WHERE id = $1", checks[0]); err == nil {
		t.Fatal("a disabled check came back")
	}
	if err := f.activate(p, checks[3]); err != nil {
		t.Fatalf("activating after one was disabled: %v", err)
	}
	if err := m10Exec(p, f.org, "DELETE FROM pc.external_policy_checks WHERE id = $1", checks[1]); err == nil {
		t.Fatal("pc_app deleted a check")
	}
}

// TestTenancy_external_policy_checks (00199): another org neither reads,
// changes nor activates an org's checks.
func TestTenancy_external_policy_checks(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a, b := govOrg(t, p), govOrg(t, p)
	id := ids.NewV7()
	if err := a.externalCheck(p, id, "opa", "https://opa.example.com/x", "PENDING"); err != nil {
		t.Fatal(err)
	}
	if n := m10Count(t, p, b.org, "SELECT count(*) FROM pc.external_policy_checks"); n != 0 {
		t.Fatalf("another org sees %d checks", n)
	}
	if err := b.activate(p, id); err != nil {
		t.Fatal(err)
	}
	if n := m10Count(t, p, a.org, "SELECT count(*) FROM pc.external_policy_checks WHERE state = 'PENDING'"); n != 1 {
		t.Fatal("another org activated our check")
	}
	if err := m10Exec(p, b.org, `INSERT INTO pc.external_policy_checks (org_id, id, name, endpoint, operations, created_by)
		VALUES ($1, $2, 'x', 'https://opa.example.com', '{a.b}', 'user:x')`, a.org, ids.NewV7()); err == nil {
		t.Fatal("wrote a check into another org")
	}
}

// builtinProvider creates the org's pc.signals provider with its
// pc.identity.risk declaration.
func builtinProvider(t *testing.T, p *db.Pool, org ids.OrgID) ids.UUID {
	t.Helper()
	id := ids.NewV7()
	if err := m10Exec(p, org, `INSERT INTO pc.fact_providers (org_id, id, name, builtin, created_by)
		VALUES ($1, $2, 'pc.signals', true, 'system:pc.signals')`, org, id); err != nil {
		t.Fatal(err)
	}
	if err := m10Exec(p, org, `INSERT INTO pc.fact_declarations (org_id, provider_id, name, value_type, subject_type, max_lag_s)
		VALUES ($1, $2, 'pc.identity.risk', 'object', 'user', 86400)`, org, id); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestHR441_OnlyTheBuiltinProviderDeclaresIdentityRiskInTheSchema (00198):
// a service account's provider cannot declare pc.identity.risk, the
// built-in provider is one per org with neither a service account nor a
// gateway, and only it may take the pc.signals name.
// Covers: F366
func TestHR441_OnlyTheBuiltinProviderDeclaresIdentityRiskInTheSchema(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	f := govOrg(t, p)
	sa, prov := ids.NewV7(), ids.NewV7()
	for _, s := range []string{
		"INSERT INTO pc.service_accounts (org_id, id, name, created_by) VALUES ($1, $2, 'idp', 'test')",
	} {
		if err := m10Exec(p, f.org, s, f.org, sa); err != nil {
			t.Fatal(err)
		}
	}
	if err := m10Exec(p, f.org, "INSERT INTO pc.fact_providers (org_id, id, name, service_account_id, created_by) VALUES ($1, $2, 'idp', $3, 'user:x')",
		f.org, prov, sa); err != nil {
		t.Fatal(err)
	}
	if err := m10Exec(p, f.org, `INSERT INTO pc.fact_declarations (org_id, provider_id, name, value_type, subject_type, max_lag_s)
		VALUES ($1, $2, 'pc.identity_risk', 'object', 'user', 60)`, f.org, prov); !db.IsCheckViolation(err) {
		t.Fatalf("a service account's provider declared the identity risk: %v", err)
	}
	if err := m10Exec(p, f.org, "INSERT INTO pc.fact_providers (org_id, id, name, service_account_id, builtin, created_by) VALUES ($1, $2, 'pc.signals', $3, true, 'x')",
		f.org, ids.NewV7(), sa); err == nil {
		t.Fatal("a built-in provider with a service account")
	}
	if err := m10Exec(p, f.org, "INSERT INTO pc.fact_providers (org_id, id, name, builtin, created_by) VALUES ($1, $2, 'other', true, 'x')",
		f.org, ids.NewV7()); err == nil {
		t.Fatal("a built-in provider not named pc.signals")
	}
	builtinProvider(t, p, f.org)
	if err := m10Exec(p, f.org, "INSERT INTO pc.fact_providers (org_id, id, name, builtin, created_by) VALUES ($1, $2, 'pc.signals', true, 'x')",
		f.org, ids.NewV7()); err == nil {
		t.Fatal("two built-in providers")
	}
}

// TestHR435_ProvenanceGoesTogether (00198): a fact's source and method are
// both set or both empty, and the method is manual, rule or model.
// Covers: F366
func TestHR435_ProvenanceGoesTogether(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	f := govOrg(t, p)
	prov := builtinProvider(t, p, f.org)
	put := func(source, method any) error {
		return m10Exec(p, f.org, `INSERT INTO pc.facts (org_id, id, name, subject_type, subject_id, provider_id, value, observed_at, source, method)
			VALUES ($1, $2, 'pc.identity.risk', 'user', $3, $4, '{"object":{}}', now(), $5, $6)`, f.org, ids.NewV7(), ids.NewV7().String(), prov, source, method)
	}
	if err := put("pc.signals", nil); !db.IsCheckViolation(err) {
		t.Errorf("a source without a method: %v", err)
	}
	if err := put("pc.signals", "guess"); !db.IsCheckViolation(err) {
		t.Errorf("an unknown method: %v", err)
	}
	if err := put(nil, nil); err != nil {
		t.Errorf("no provenance: %v", err)
	}
	if err := put("pc.signals", "rule"); err != nil {
		t.Errorf("both: %v", err)
	}
}

// TestTenancy_fact_provenance (00198): an org's built-in provider and its
// facts stay in the org.
func TestTenancy_fact_provenance(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a, b := govOrg(t, p), govOrg(t, p)
	prov := builtinProvider(t, p, a.org)
	if err := m10Exec(p, a.org, `INSERT INTO pc.facts (org_id, id, name, subject_type, subject_id, provider_id, value, observed_at, source, method)
		VALUES ($1, $2, 'pc.identity.risk', 'user', $3, $4, '{"object":{}}', now(), 'pc.signals', 'rule')`, a.org, ids.NewV7(), a.user.String(), prov); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"SELECT count(*) FROM pc.fact_providers WHERE builtin", "SELECT count(*) FROM pc.facts WHERE source IS NOT NULL",
	} {
		if n := m10Count(t, p, b.org, q); n != 0 {
			t.Errorf("%s: another org sees %d", q, n)
		}
	}
	builtinProvider(t, p, b.org) // each org has its own
	if err := m10Exec(p, b.org, "UPDATE pc.facts SET source = 'forged', method = 'manual'"); err != nil {
		t.Fatal(err)
	}
	if n := m10Count(t, p, a.org, "SELECT count(*) FROM pc.facts WHERE source = 'pc.signals'"); n != 1 {
		t.Fatal("another org changed our fact's provenance")
	}
}
