// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package assurance_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	autoapp "github.com/katocxl/pantherclaw/internal/automations/app"
	"github.com/katocxl/pantherclaw/internal/automations/assurance"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/changes"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/exposure/exposuretest"
	grantspg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type edition billing.Edition

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Edition(e), Status: billing.StatusValid}, nil
}

func admin(o *exposuretest.Org) context.Context {
	return tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: o.Org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: o.User},
		Bindings: []td.Binding{
			{Role: td.RoleOrgAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: o.Org.UUID()}},
			{Role: td.RoleAutomationAuthor, Scope: td.Scope{Type: td.ScopeOrg, ID: o.Org.UUID()}},
		},
	}})
}

// draft stores a VALIDATED second version of a.
func draft(t *testing.T, o *exposuretest.Org, a exposuretest.Automation) ids.UUID {
	t.Helper()
	canon, err := a.Definition.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canon)
	v := ids.NewV7()
	o.Exec(t, `INSERT INTO pc.automation_versions (org_id, id, automation_id, number, definition, digest, created_by)
		VALUES ($1, $2, $3, 2, $4, $5, $6)`, o.Org, v, a.ID, canon, digest[:], o.User)
	o.Exec(t, `UPDATE pc.automation_versions SET state = 'VALIDATED', validated_at = now() WHERE id = $1`, v)
	return v
}

// effects counts the rows tests and simulations must never write.
func effects(t *testing.T, o *exposuretest.Org) map[string]int {
	t.Helper()
	out := map[string]int{}
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		for _, table := range []string{
			"grants", "runs", "automation_executions", "automation_step_attempts", "automation_launches",
			"automation_deliveries", "approval_requests", "notifications", "response_actions", "cases",
		} {
			var n int
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM pc."+table).Scan(&n); err != nil {
				return err
			}
			out[table] = n
		}
		return nil
	})
	return out
}

func scenario() []assurance.Case {
	ticket := assurance.CaseTrigger{Params: map[string]string{"ticket": "T-1"}}
	ok := []assurance.StubResult{{State: "DONE", Effect: "CHANGED", Evidence: true}}
	return []assurance.Case{
		{
			Name: "normal", Kind: assurance.CaseNormal, Trigger: ticket, Stubs: map[string][]assurance.StubResult{"launch": ok, "wait": ok},
			Expect: assurance.Expect{State: "SUCCEEDED"},
		},
		{
			Name: "denied", Kind: assurance.CaseDenied, Trigger: ticket,
			Stubs:  map[string][]assurance.StubResult{"launch": {{State: "FAILED", Reason: "OUTSIDE_CEILING"}}},
			Expect: assurance.Expect{State: "FAILED"},
		},
		{
			Name: "timeout", Kind: assurance.CaseTimeout, Trigger: ticket,
			Stubs:  map[string][]assurance.StubResult{"launch": ok, "wait": {{State: "WAITING"}}},
			Expect: assurance.Expect{State: "PARTIALLY_COMPLETED", Reason: "TIMEOUT"},
		},
		{
			Name: "dup", Kind: assurance.CaseDuplicate, Trigger: ticket,
			Stubs: map[string][]assurance.StubResult{"launch": ok, "wait": ok}, Expect: assurance.Expect{State: "SUCCEEDED"},
		},
		{
			Name: "unknown", Kind: assurance.CaseUnknown, Trigger: ticket,
			Stubs:  map[string][]assurance.StubResult{"launch": ok, "wait": {{State: "UNKNOWN", Output: map[string]string{"irreversible": "true"}}}},
			Expect: assurance.Expect{State: "NEEDS_RECONCILIATION"},
		},
	}
}

// HR-287: a version becomes TESTED only by a passing run covering the
// required kinds for its digest; a run missing a kind leaves it VALIDATED,
// and the TestGate passes only for a passing run of today's cases.
// T-127, HR-288: running tests and a historical simulation writes no
// grant, run, execution, launch, delivery, approval, notification,
// containment or case.
func TestT127_TestsAndSimulationAreInert(t *testing.T) {
	o := exposuretest.New(t)
	a := o.Automation(t, "refunds", []ids.UUID{o.Other}, "payments.refund.*")
	o.IssuedGrant(t, a, o.Other, "payments.refund.create")
	v := draft(t, o, a)
	svc := &assurance.Service{Pool: o.P, Ents: edition(billing.Team), Issuer: issuer(o)}
	ctx := admin(o)
	before := effects(t, o)

	// The mock refund is irreversible, so PARTIAL or UNKNOWN is required.
	// D103 T1: in the caller's transaction, as a template sets them.
	var missing []string
	if err := o.P.InTenantTx(ctx, o.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		missing, err = svc.SetTestCasesTx(ctx, tx, v, scenario()[:4])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(missing) != 1 || missing[0] != "PARTIAL|UNKNOWN" {
		t.Fatalf("missing %v", missing)
	}
	run, err := svc.RunTests(ctx, v)
	if err != nil {
		t.Fatal(err)
	}
	if run.Passed || run.VersionState != "VALIDATED" {
		t.Fatalf("a run missing a kind: passed %v, state %s, %+v", run.Passed, run.VersionState, run.Result)
	}
	// D94 S3: a passing run of these cases (as when the ceiling reached no
	// irreversible operation) passes no gate while one is reachable.
	o.Exec(t, `INSERT INTO pc.automation_test_runs (org_id, id, version_id, definition_digest, tests_digest, passed, results, run_by)
		VALUES ($1, $2, $3, $4, $5, true, '{"cases": []}', $6)`, o.Org, ids.NewV7(), v, run.DefinitionDigest, run.TestsDigest, o.User)
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		if _, ok, err := (assurance.TestGate{}).Passed(ctx, tx.Pgx(), v, run.DefinitionDigest); err != nil || ok {
			t.Errorf("TestGate passed a run missing PARTIAL|UNKNOWN: %v %v", ok, err)
		}
		return nil
	})
	if _, err := svc.SetTestCases(ctx, v, scenario()); err != nil {
		t.Fatal(err)
	}
	run, err = svc.RunTests(ctx, v)
	if err != nil {
		t.Fatal(err)
	}
	if !run.Passed || run.VersionState != "TESTED" {
		t.Fatalf("complete run: passed %v, state %s, %+v", run.Passed, run.VersionState, run.Result)
	}
	if _, err := svc.SetTestCases(ctx, v, scenario()); !errors.Is(err, assurance.ErrVersionState) {
		t.Fatalf("tests changed on a TESTED version: %v", err)
	}
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		got, ok, err := (assurance.TestGate{}).Passed(ctx, tx.Pgx(), v, run.DefinitionDigest)
		if err != nil || !ok || got != run.ID {
			t.Errorf("TestGate: %s %v %v", got, ok, err)
		}
		if _, ok, _ := (assurance.TestGate{}).Passed(ctx, tx.Pgx(), v, make([]byte, 32)); ok {
			t.Error("TestGate passed another digest")
		}
		return nil
	})

	// A simulation over the last day: manual triggers are never replayed.
	sim := ids.NewV7()
	o.Exec(t, `INSERT INTO pc.automation_simulations (org_id, id, version_id, from_at, to_at, requested_by)
		VALUES ($1, $2, $3, now() - interval '1 day', now(), $4)`, o.Org, sim, v, o.User)
	if err := svc.RunSimulation(context.Background(), o.Org, sim); err != nil {
		t.Fatal(err)
	}
	got, err := svc.GetSimulation(ctx, sim)
	if err != nil || got.State != "DONE" || got.Results == nil || got.Results.Missing[assurance.MissingManual] != 1 ||
		got.Results.LaunchPreview["launch"] == "" {
		t.Fatalf("simulation %+v %v", got, err)
	}

	after := effects(t, o)
	for k, n := range before {
		if after[k] != n {
			t.Errorf("%s: %d rows before, %d after", k, n, after[k])
		}
	}

	// Rollout evidence: the automation is FULL, not in a COHORT stage.
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		ok, reasons, err := (assurance.RolloutEvidence{}).Verified(ctx, tx.Pgx(), a.ID, a.Version)
		if err != nil || ok || len(reasons) != 1 || reasons[0] != assurance.UnverifiedNotCohort {
			t.Errorf("rollout evidence: %v %v %v", ok, reasons, err)
		}
		return nil
	})
	st, err := svc.GetAutomationStatus(ctx, a.ID)
	if err != nil || st.State != "ACTIVE" || st.ReviewBy == nil || len(st.Budgets) < 2 {
		t.Fatalf("status %+v %v", st, err)
	}
	if _, err := svc.GetAutomationMetrics(ctx, nil, time.Now().Add(-time.Hour), time.Now()); err != nil {
		t.Fatal(err)
	}
	// D38: no gate is stalled and no automation failed three times running.
	if n, err := assurance.Sweep(context.Background(), o.P, &failures.Sink{}, o.Org); err != nil || n != 0 {
		t.Fatalf("sweep: %d %v", n, err)
	}
}

// issuer is grants' issuance with core's ceiling checks, as the
// simulation worker has it (D94 S5).
func issuer(o *exposuretest.Org) *grantsapp.Service {
	gstore := &grantspg.Store{Pool: o.P}
	grants := &grantsapp.Service{
		Repo: gstore, Subjects: gstore, Defs: &defspg.Store{Pool: o.P}, Authz: grantsapp.SubjectAuthorizer{},
		Clock: clock.System{}, Store: gstore,
	}
	grants.Ceilings = &autoapp.Service{
		Pool: o.P, Clock: clock.System{}, Changes: changes.New(o.P, "https://pc.example.test"), Grants: grants,
		Operations: &defspg.Store{Pool: o.P},
	}
	return grants
}

// D94 S1: a simulation an attempt left RUNNING is resumed by the next
// attempt and finishes; the last attempt marks one FAILED.
func TestSimulationResumesAfterAFailedAttempt(t *testing.T) {
	o := exposuretest.New(t)
	a := o.Automation(t, "refunds", []ids.UUID{o.Other}, "payments.refund.*")
	v := draft(t, o, a)
	svc := &assurance.Service{Pool: o.P, Ents: edition(billing.Team), Issuer: issuer(o)}
	sims := [2]ids.UUID{ids.NewV7(), ids.NewV7()}
	for _, sim := range sims {
		// A first attempt claimed it and failed.
		o.Exec(t, `INSERT INTO pc.automation_simulations (org_id, id, version_id, from_at, to_at, requested_by, state, started_at)
			VALUES ($1, $2, $3, now() - interval '1 day', now(), $4, 'RUNNING', now())`, o.Org, sim, v, o.User)
	}
	if err := svc.RunSimulation(context.Background(), o.Org, sims[0]); err != nil {
		t.Fatal(err)
	}
	if err := svc.FailSimulation(context.Background(), o.Org, sims[1], "SIMULATION_FAILED"); err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"DONE", "FAILED"} {
		got, err := svc.GetSimulation(admin(o), sims[i])
		if err != nil || got.State != want {
			t.Errorf("simulation %d: %+v %v", i, got, err)
		}
	}
}
