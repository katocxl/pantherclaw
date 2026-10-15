// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"strconv"
	"sync"
	"testing"

	bdomain "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/response/adapters/pgresponse"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
	rdomain "github.com/katocxl/pantherclaw/internal/response/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR250_TheDatabaseRefusesAnInvolvedReviewer (D61): whatever code lifts
// a control, the trigger refuses a lift by the plan's requester, by the
// creator of one of its controls, or by a person one of them contains.
func TestHR250_TheDatabaseRefusesAnInvolvedReviewer(t *testing.T) {
	w := newWorld(t, "PARTIAL")
	_, byAlice := w.containAgent()
	carol := ids.NewV7()
	w.exec(`INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'carol')`, w.org, carol)
	res, err := w.contain(reflexdomain.ContainRequest{
		Scope: reflexdomain.Subject{Type: reflexdomain.SubjectUser, ID: carol.String()}, Control: reflexdomain.ControlDenyAll,
		Actor: rapp.PlaybookActor,
	})
	if err != nil {
		t.Fatal(err)
	}
	var onCarol ids.UUID
	w.d.AdminQueryRow(t, "SELECT id FROM pc.containment_controls WHERE org_id = $1 AND action_id = $2", []any{w.org, res.ActionID}, &onCarol)
	plan, dave := ids.NewV7(), ids.NewV7()
	w.exec(`INSERT INTO pc.restoration_plans (org_id, id, reason, requested_by, state, finished_at)
		VALUES ($1, $2, 'x', $3, 'COMPLETED', now())`, w.org, plan, "user:"+dave.String())
	for _, c := range []ids.UUID{byAlice, onCarol} {
		w.exec("INSERT INTO pc.restoration_plan_controls (org_id, plan_id, control_id) VALUES ($1, $2, $3)", w.org, plan, c)
	}
	lift := func(control, by ids.UUID) error {
		return w.tx(func(ctx context.Context, tx db.TenantTx) error {
			return pgresponse.LiftControl(ctx, tx, w.org, control, plan, "user:"+by.String())
		})
	}
	for name, by := range map[string]ids.UUID{"the requester": dave, "a control's creator": w.alice, "the contained person": carol} {
		if err := lift(byAlice, by); err == nil {
			t.Errorf("%s lifted a control", name)
		}
	}
	if err := lift(byAlice, ids.NewV7()); err != nil {
		t.Fatalf("an independent reviewer: %v", err)
	}
}

// TestHR251_SOARRateLimitHoldsUnderConcurrency (D61): fifteen wide SOAR
// requests at once never create more than ten controls; every other one is
// RATE_LIMITED, or SOAR_BUSY when it waited past the lock timeout (nothing
// done, retriable).
func TestHR251_SOARRateLimitHoldsUnderConcurrency(t *testing.T) {
	w := newWorld(t, "PARTIAL")
	sa := reflexdomain.Subject{Type: reflexdomain.SubjectServiceAccount, ID: ids.NewV7().String()}
	var wg sync.WaitGroup
	results := make([]rapp.SOARResult, 15)
	errs := make([]error, 15)
	for i := range 15 {
		wg.Go(func() {
			errs[i] = w.tx(func(ctx context.Context, tx db.TenantTx) error {
				var err error
				results[i], err = w.c.RequestControlIn(ctx, tx, rapp.SOARRequest{
					Key: "loop-" + strconv.Itoa(i), Scope: reflexdomain.Subject{Type: reflexdomain.SubjectGrant, ID: w.grant.String()},
					Control: rdomain.HoldWrites, Reason: "loop", Requester: sa,
				})
				return err
			})
		})
	}
	wg.Wait()
	created, refused := 0, 0
	for i, r := range results {
		switch {
		case errors.Is(errs[i], rapp.ErrSOARBusy), r.Reason == rapp.ReasonRateLimited:
			refused++
		case errs[i] != nil:
			t.Fatalf("request %d: %v", i, errs[i])
		default:
			created++
		}
	}
	n := w.count("SELECT count(*) FROM pc.response_actions WHERE org_id = $1 AND source = 'SOAR'", w.org)
	if n > 10 || n != created || created+refused != 15 || created == 0 {
		t.Fatalf("%d SOAR actions (%d created, %d refused), want at most 10", n, created, refused)
	}
}

// TestT110_SOARKeysAreTheirOwn (D61): a person's idempotency key never
// claims a SOAR key, and a SOAR key replayed by another integration is not
// found.
func TestT110_SOARKeysAreTheirOwn(t *testing.T) {
	w := newWorld(t, "PARTIAL")
	w.c.Editions = edition(bdomain.Business)
	r := &rapp.Response{C: w.c}
	run := reflexdomain.Subject{Type: reflexdomain.SubjectRun, ID: w.run.String()}
	if _, err := r.Contain(w.caller(td.KindUser, w.alice, td.RoleResponder), rapp.ContainInput{
		Scope: run, Control: rdomain.HoldWrites, Reason: "mine", Idempotency: "INC-42",
	}); err != nil {
		t.Fatal(err)
	}
	soar := w.caller(td.KindServiceAccount, ids.NewV7(), td.RoleSOARIntegration)
	req := rapp.SOARRequest{Key: "INC-42", Scope: run, Control: rdomain.DenyAll, Reason: "edr"}
	if _, _, err := r.RequestControl(soar, req); err != nil {
		t.Fatalf("a SOAR key a person used: %v", err)
	}
	other := w.caller(td.KindServiceAccount, ids.NewV7(), td.RoleSOARIntegration)
	if _, _, err := r.RequestControl(other, req); !errors.Is(err, rapp.ErrSOARNotFound) {
		t.Fatalf("another integration's key: %v", err)
	}
}

// TestT108_TerminationKeepsBypassRoutesOpen (D61): terminating a run of an
// agent with a bypass route lists the route, so the action stays PARTIAL
// once the gateways have the epoch.
func TestT108_TerminationKeepsBypassRoutesOpen(t *testing.T) {
	w := newWorld(t, "OBSERVE_ONLY")
	id, err := w.terminate()
	if err != nil {
		t.Fatal(err)
	}
	a := w.action(id)
	w.deliver(a.Epoch.Int64)
	if a = w.advance(id); a.Status != string(rdomain.StatusPartial) || !a.MediatedConfirmed || a.FutureConfirmed {
		t.Fatalf("terminated with a bypass route: %s mediated=%v future=%v", a.Status, a.MediatedConfirmed, a.FutureConfirmed)
	}
}

// TestT108_BypassClosesOnlyOnAnAttestedUpstreamRevoke (D61): an agent-held
// credential and its bypass route stay UNRESOLVED until a person attests
// that the agent's credential was revoked at the provider; an attested
// rotation leaves the agent a valid credential and closes nothing (D72).
// PantherClaw cannot revoke it, and refuses to pretend.
func TestT108_BypassClosesOnlyOnAnAttestedUpstreamRevoke(t *testing.T) {
	w := newWorld(t, "OBSERVE_ONLY")
	w.exec("UPDATE pc.connections SET access_mode = 'agent_held' WHERE org_id = $1 AND id = $2", w.org, w.conn)
	w.exec(`INSERT INTO pc.coverage_routes (org_id, id, agent_id, connection_id, kind, channel, observation, source)
		VALUES ($1, $2, $3, $4, 'channel', 'http', 'observed', 'gateway')`, w.org, ids.NewV7(), w.agent, w.conn)
	id, _ := w.containAgent()
	a := w.action(id)
	w.deliver(a.Epoch.Int64)
	if a = w.advance(id); a.Status != string(rdomain.StatusPartial) {
		t.Fatalf("before the attestation: %s", a.Status)
	}
	p := w.credentialPreview(0)
	if _, err := w.change(0, p.Digest, false, false); !errors.Is(err, rapp.ErrAttestationRequired) {
		t.Fatalf("an unattested agent-held revoke: %v", err)
	}
	// D72: an attested rotation confirms only its own credential path; the
	// agent now holds a fresh, valid credential, so the bypass stays open.
	rot, err := w.change(0, p.Digest, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if n := w.count(`SELECT count(*) FROM pc.response_paths WHERE org_id = $1 AND action_id = $2 AND path_type = 'CREDENTIAL' AND status = 'CONFIRMED'`,
		w.org, rot.ActionID); n != 1 {
		t.Fatal("the attested rotation did not confirm its own credential path")
	}
	if a = w.advance(id); a.Status != string(rdomain.StatusPartial) {
		t.Fatalf("an attested rotation closed the bypass: %s", a.Status)
	}
	if _, err := w.change(0, p.Digest, false, true); err != nil {
		t.Fatal(err)
	}
	if a = w.advance(id); a.Status != string(rdomain.StatusConfirmed) || !a.FutureConfirmed {
		t.Fatalf("after the attestation: %s future=%v", a.Status, a.FutureConfirmed)
	}
}

// TestT108_GitHubAppRotationWaitsForOldTokens (D61): a GitHub App rotation
// stays unconfirmed while installation tokens minted before it can still be
// used at GitHub, lists them as historical exposure, and confirms once they
// have expired and the gateway has the epoch.
func TestT108_GitHubAppRotationWaitsForOldTokens(t *testing.T) {
	w := newWorld(t, "PARTIAL")
	w.exec("ALTER TABLE pc.credentials DISABLE TRIGGER ALL")
	w.exec(`INSERT INTO pc.credentials (org_id, id, connection_id, version, broker_key_id, sealed, allowed_hosts, header, scheme, state, created_by, kind)
		VALUES ($1, $2, $3, 1, $4, decode(repeat('00', 1200), 'hex'), '{api.github.com}', 'Authorization', 'Bearer', 'ACTIVE', 'test', 'github_app')`,
		w.org, ids.NewV7(), w.conn, ids.NewV7())
	w.exec("ALTER TABLE pc.credentials ENABLE TRIGGER ALL")
	res, err := w.change(1, w.credentialPreview(1).Digest, true, false)
	if err != nil {
		t.Fatal(err)
	}
	w.deliver(w.epoch())
	a := w.advance(res.ActionID)
	var hist []map[string]string
	if err := json.Unmarshal(a.HistoricalOpen, &hist); err != nil || len(hist) != 1 || hist[0]["kind"] != "installation_tokens" {
		t.Fatalf("historical exposure %s (%v)", a.HistoricalOpen, err)
	}
	if a.Status == string(rdomain.StatusConfirmed) {
		t.Fatal("confirmed while earlier tokens are still valid")
	}
	w.exec(`UPDATE pc.response_paths
		SET evidence = jsonb_set(evidence, '{tokens_valid_until}', to_jsonb(to_char((now() - interval '1 minute') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')))
		WHERE org_id = $1 AND action_id = $2 AND path_type = 'CREDENTIAL'`, w.org, res.ActionID)
	if a = w.advance(res.ActionID); a.Status != string(rdomain.StatusConfirmed) {
		var paths []dbq.PcResponsePath
		_ = w.tx(func(ctx context.Context, tx db.TenantTx) error {
			paths, _ = dbq.New(tx).ListResponsePaths(ctx, w.org, res.ActionID)
			return nil
		})
		t.Fatalf("after the old tokens expired: %s %+v", a.Status, paths)
	}
}

// TestT108_TerminationListsEveryAgentOfTheTree (D72): a terminated run's
// delegated child lane of another agent brings that agent's bypass route,
// so the termination stays PARTIAL.
func TestT108_TerminationListsEveryAgentOfTheTree(t *testing.T) {
	w := newWorld(t, "PARTIAL")
	child, childAgent, entry := ids.NewV7(), ids.NewV7(), ids.NewV7()
	w.exec("INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'helper', 'DISCOVERED', 'test')", w.org, childAgent)
	// A child lane launched by the parent's instance (its foreign keys are not
	// what is tested).
	w.exec("ALTER TABLE pc.runs DISABLE TRIGGER ALL")
	w.exec(`INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_instance_id, principal_user_id, principal_source, expires_at, grant_id, parent_run_id, depth)
		SELECT org_id, $2, $3, environment_id, $5, principal_user_id, 'parent_run', expires_at, grant_id, id, 1
		FROM pc.runs WHERE org_id = $1 AND id = $4`, w.org, child, childAgent, w.run, ids.NewV7())
	w.exec("ALTER TABLE pc.runs ENABLE TRIGGER ALL")
	w.exec(`INSERT INTO pc.ledger_entries (org_id, id, kind, actor_type, actor_id, body) VALUES ($1, $2, 'coverage.snapshot', 'system', 'test', '\x7b7d')`, w.org, entry)
	w.exec(`INSERT INTO pc.coverage_snapshots (org_id, id, agent_id, connection_id, operation, state, reasons, body, body_sha256, ledger_entry_id)
		VALUES ($1, $2, $3, $4, 'payments.refund.create', 'OBSERVE_ONLY', '{}', '{}', decode(repeat('00', 32), 'hex'), $5)`,
		w.org, ids.NewV7(), childAgent, w.conn, entry)
	id, err := w.terminate()
	if err != nil {
		t.Fatal(err)
	}
	a := w.action(id)
	w.deliver(a.Epoch.Int64)
	if a = w.advance(id); a.Status != string(rdomain.StatusPartial) || a.FutureConfirmed {
		t.Fatalf("the child agent's bypass: %s future=%v", a.Status, a.FutureConfirmed)
	}
}
