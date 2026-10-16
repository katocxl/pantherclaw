// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"testing"

	autoapp "github.com/katocxl/pantherclaw/internal/automations/app"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// The core-D review fixes (D106).

func (e *env) confirmEnable(v ids.UUID, rollout autodomain.Rollout) {
	e.t.Helper()
	var cohort []ids.UUID
	if rollout == autodomain.RolloutCohort {
		cohort = []ids.UUID{e.agent}
	}
	en, err := e.svc.RequestEnable(e.alice.cli, v, rollout, cohort, ids.UUID{})
	if err != nil {
		e.t.Fatal(err)
	}
	for _, p := range []person{e.bob, e.cat}[:en.Required] {
		if _, err := e.svc.Changes.Confirm(p.page, en.Request.ID, e.sign(p, en.Request)); err != nil {
			e.t.Fatalf("confirm: %v", err)
		}
	}
}

func (e *env) openFailures(kind string) int {
	e.t.Helper()
	return e.count(`SELECT count(*) FROM pc.operational_failures WHERE org_id = $1 AND kind = $2 AND state <> 'RESOLVED'`, e.org, kind)
}

func (e *env) resolvedRecords() int {
	e.t.Helper()
	return e.count(`SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.incident.failure_resolved'`, e.org)
}

// TestD106_AuthorityRevokedRecordsCancellations (D1).
func TestD106_AuthorityRevokedRecordsCancellations(t *testing.T) {
	e := newEnv(t)
	a, _ := e.enabled("refunds", autodomain.RolloutShadow, 5)
	if _, _, err := e.svc.RevokeAuthority(e.alice.cli, a.ID, "incident"); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.automation.authority_revoked'
		AND convert_from(body, 'UTF8') LIKE '%"executions_canceled"%' AND convert_from(body, 'UTF8') LIKE '%"deliveries_not_verified"%'`,
		e.org); n != 1 {
		t.Errorf("authority_revoked records with the counts: %d", n)
	}
}

// TestD106_SweepResolvesThroughTheSink (D2): the resolution is recorded
// like a manual one, and a sweep with nothing open records none.
func TestD106_SweepResolvesThroughTheSink(t *testing.T) {
	e := newEnv(t)
	a, _ := e.enabled("refunds", autodomain.RolloutShadow, 5)
	e.exec(`INSERT INTO pc.operational_failures (org_id, id, kind, summary, next_step, deadline, dedupe_key)
		VALUES ($1, gen_random_uuid(), $2, 'failed', 'look', now() + interval '1 day', $3)`,
		e.org, autoapp.FailureSweep, "sweep:"+a.Ceiling.ID.String())
	for range 2 {
		if _, err := e.svc.SweepOrg(context.Background(), e.org); err != nil {
			t.Fatal(err)
		}
	}
	if open, rec := e.openFailures(autoapp.FailureSweep), e.resolvedRecords(); open != 0 || rec != 1 {
		t.Errorf("open %d, resolution records %d", open, rec)
	}
}

// TestD106_EnableResolvesAuthorityChanged (A3): enabling a new version
// resolves the automation's authority_changed failures; widening the
// rollout of the same version does not.
func TestD106_EnableResolvesAuthorityChanged(t *testing.T) {
	e := newEnv(t)
	a, v := e.enabled("refunds", autodomain.RolloutCohort, 5)
	if err := e.svc.VoidCeiling(context.Background(), e.org, a.Ceiling.ID, "TEST"); err != nil {
		t.Fatal(err)
	}
	if n := e.openFailures(autoapp.FailureAuthorityChanged); n != 1 {
		t.Fatalf("authority_changed open %d", n)
	}
	e.confirmEnable(v.ID, autodomain.RolloutFull)
	if n := e.openFailures(autoapp.FailureAuthorityChanged); n != 1 {
		t.Errorf("a ROLLOUT resolved authority_changed (%d open)", n)
	}
	next, err := e.svc.CreateDraftVersion(e.alice.cli, a.ID, []byte(e.definition(4)))
	if err != nil {
		t.Fatal(err)
	}
	if next, ok, err := e.svc.ValidateVersion(e.alice.cli, next.ID); err != nil || !ok {
		t.Fatalf("validate: %v %+v", err, next.Findings)
	}
	e.confirmEnable(next.ID, autodomain.RolloutShadow)
	if n := e.openFailures(autoapp.FailureAuthorityChanged); n != 0 {
		t.Errorf("an ENABLE left %d authority_changed open", n)
	}
}
