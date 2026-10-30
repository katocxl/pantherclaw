// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json/v2"
	"strconv"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/credentials/app"
	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/transactions/adapters/pgtransactions"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
	txdomain "github.com/katocxl/pantherclaw/internal/transactions/domain"
)

var rotationGitHub = &domain.Installation{AppClientID: "Iv23liApp", ID: 7, Account: "acme"}

// rotationEnv is an env whose connection holds an ACTIVE GitHub App
// credential, a person with a security key, and the verification store
// leasing rotations.
type rotationEnv struct {
	*env
	person context.Context
	key    ids.UUID
	store  *pgtransactions.Store
	digest []byte
}

func newRotationEnv(t *testing.T) *rotationEnv {
	t.Helper()
	sum := sha256.Sum256([]byte("preview"))
	e := &rotationEnv{env: newEnv(t), digest: sum[:]}
	e.svc.WithRotations(func(context.Context, db.TenantTx, ids.UUID, int32) ([]byte, error) { return e.digest, nil })
	e.store = &pgtransactions.Store{Pool: e.pool, Rotations: e.svc}
	e.epoch(t) // the org's containment row, which leases need
	e.exec(t, "UPDATE pc.connections SET state = 'ACTIVE' WHERE id = $1", e.conn.ID)
	_, in := e.seal(t, `{"v":1}`)
	in.Kind, in.GitHub = domain.KindGitHubApp, rotationGitHub
	if _, err := e.svc.PutCredential(e.sealer, in); err != nil {
		t.Fatal(err)
	}
	user := ids.NewV7()
	e.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'rotator')", e.org, user)
	e.key = ids.NewV7()
	e.exec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		e.org, e.key, user, bytes.Repeat([]byte{9}, 16), bytes.Repeat([]byte{9}, 32))
	e.person = tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: e.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user},
		Bindings: []td.Binding{{Role: td.RoleGatewayAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}}},
	}, Credential: tapp.CredAccessToken})
	return e
}

// stepUp is a fresh step-up with the person's key.
func (e *rotationEnv) stepUp() stepup.StepUp { return stepup.StepUp{Credential: e.key, At: time.Now()} }

// sealed requests a rotation and seals its candidate.
func (e *rotationEnv) sealed(t *testing.T) app.Rotation {
	t.Helper()
	r, err := e.svc.RequestRotation(e.person, e.conn.ID, e.digest)
	if err != nil {
		t.Fatal(err)
	}
	_, in := e.seal(t, `{"v":1,"new":true}`)
	in.Kind, in.GitHub = domain.KindGitHubApp, rotationGitHub
	if _, err := e.svc.SealCandidate(e.person, r.ID, in); err != nil {
		t.Fatal(err)
	}
	return e.get(t, r.ID)
}

func (e *rotationEnv) get(t *testing.T, id ids.UUID) app.Rotation {
	t.Helper()
	r, err := e.svc.GetRotation(e.person, id)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// lease claims the gateway's due tasks and returns the rotation lease.
func (e *rotationEnv) lease(t *testing.T, gateway ids.UUID) (txapp.Lease, bool) {
	t.Helper()
	leases, err := e.store.Claim(context.Background(), e.org, gateway, 16, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range leases {
		if l.Purpose.Rotation() {
			return l, true
		}
	}
	return txapp.Lease{}, false
}

// report reports a probe under l.
func (e *rotationEnv) report(t *testing.T, l txapp.Lease, p domain.Probe) {
	t.Helper()
	if _, err := e.store.Report(context.Background(), e.org, e.gateway, txapp.Report{
		Task: l.Task, Secret: l.Secret, HTTPStatus: p.AppStatus, Found: true, Complete: true, Fields: p.Fields(),
	}, nil); err != nil {
		t.Fatal(err)
	}
}

func (e *rotationEnv) credentialStates(t *testing.T) map[int32]string {
	t.Helper()
	out := map[int32]string{}
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := tx.Query(ctx, "SELECT version, state FROM pc.credentials WHERE connection_id = $1", e.conn.ID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v int32
			var s string
			if err := rows.Scan(&v, &s); err != nil {
				return err
			}
			out[v] = s
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func (e *rotationEnv) served(t *testing.T) []int32 {
	t.Helper()
	var out []int32
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).GatewaySealedCredentials(ctx, e.org, e.gateway)
		for _, r := range rows {
			out = append(out, r.Version)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

var passed = domain.Probe{AppStatus: 200, AppMatches: true, InstallationStatus: 200}

// tested is a rotation whose candidate passed its test.
func (e *rotationEnv) tested(t *testing.T) app.Rotation {
	t.Helper()
	r := e.sealed(t)
	if _, err := e.svc.TestRotation(e.person, r.ID); err != nil {
		t.Fatal(err)
	}
	l, ok := e.lease(t, e.gateway)
	if !ok {
		t.Fatal("no test lease")
	}
	e.report(t, l, passed)
	return e.get(t, r.ID)
}

// TestHR517_ACandidateReachesItsGatewayOnlyInsideALease: a sealed
// candidate is not in the gateway's configuration; its test lease carries
// it, sealed as configuration is, to the connection's gateway only, while
// the task row holds the rotation's id only.
// Covers: F424
func TestHR517_ACandidateReachesItsGatewayOnlyInsideALease(t *testing.T) {
	e := newRotationEnv(t)
	r := e.sealed(t)
	if r.State != string(domain.RotationCandidateSealed) || r.CandidateCredentialID == nil {
		t.Fatalf("sealed: %+v", r)
	}
	if got := e.served(t); len(got) != 1 || got[0] != 1 {
		t.Fatalf("the gateway is served %v, want only version 1", got)
	}
	if _, err := e.svc.TestRotation(e.person, r.ID); err != nil {
		t.Fatal(err)
	}
	other := ids.NewV7()
	e.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'other', 'test')", e.org, other)
	if _, ok := e.lease(t, other); ok {
		t.Fatal("another gateway leased the rotation")
	}
	l, ok := e.lease(t, e.gateway)
	if !ok {
		t.Fatal("no test lease")
	}
	var req domain.RotationLease
	if err := json.Unmarshal(l.Request, &req); err != nil || req.Rotation != r.ID.String() || req.Credential.ID != r.CandidateCredentialID.String() ||
		req.Credential.Version != 2 || len(req.Credential.Sealed) < 1140 || req.Credential.BrokerKey != e.keyID.String() {
		t.Fatalf("lease request %+v %v", req.Credential, err)
	}
	var stored string
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT request::text FROM pc.verifications WHERE id = $1", l.Task).Scan(&stored)
	}); err != nil || stored != `{"rotation": "`+r.ID.String()+`"}` {
		t.Fatalf("the task row holds %s (%v)", stored, err)
	}
	if got := e.served(t); len(got) != 1 || got[0] != 1 {
		t.Fatalf("after the lease the gateway is served %v", got)
	}
}

// TestHR518_ActivationNeedsAPassedTestAndAStepUp: a candidate that fails
// its test fails the rotation and is revoked; activation before a passed
// test, or without a fresh step-up, is refused; a tested candidate with a
// step-up becomes ACTIVE, the old key SUPERSEDED, and the gateway is
// served the candidate.
// Covers: F424
func TestHR518_ActivationNeedsAPassedTestAndAStepUp(t *testing.T) {
	e := newRotationEnv(t)
	r := e.sealed(t)
	if _, err := e.svc.ActivateRotation(e.person, r.ID, e.stepUp()); !is(err, app.ErrRotationState) {
		t.Fatalf("activate before the test: %v", err)
	}
	if _, err := e.svc.TestRotation(e.person, r.ID); err != nil {
		t.Fatal(err)
	}
	l, _ := e.lease(t, e.gateway)
	e.report(t, l, domain.Probe{AppStatus: 401})
	if r = e.get(t, r.ID); r.State != string(domain.RotationFailed) || e.credentialStates(t)[2] != "REVOKED" || e.credentialStates(t)[1] != "ACTIVE" {
		t.Fatalf("failed test: %s %v", r.State, e.credentialStates(t))
	}

	r = e.sealed(t)
	if _, err := e.svc.TestRotation(e.person, r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.ActivateRotation(e.person, r.ID, e.stepUp()); !is(err, app.ErrRotationUntested) {
		t.Fatalf("activate while the test runs: %v", err)
	}
	l, _ = e.lease(t, e.gateway)
	e.report(t, l, passed)
	if _, err := e.svc.ActivateRotation(e.person, r.ID, stepup.StepUp{}); !stepup.Is(err) {
		t.Fatalf("activate without a step-up: %v", err)
	}
	if _, err := e.svc.ActivateRotation(e.person, r.ID, stepup.StepUp{Credential: e.key, At: time.Now().Add(-6 * time.Minute)}); !stepup.Is(err) {
		t.Fatalf("activate with a stale step-up: %v", err)
	}
	if _, err := e.svc.ActivateRotation(e.sealer, r.ID, e.stepUp()); !stepup.Is(err) {
		t.Fatalf("activate with another person's key: %v", err)
	}
	r, err := e.svc.ActivateRotation(e.person, r.ID, e.stepUp())
	if err != nil || r.State != string(domain.RotationActivating) || r.RollbackUntil == nil {
		t.Fatalf("activate: %+v %v", r, err)
	}
	if s := e.credentialStates(t); s[1] != "SUPERSEDED" || s[3] != "ACTIVE" {
		t.Fatalf("after activation: %v", s)
	}
	if got := e.served(t); len(got) != 1 || got[0] != 3 {
		t.Fatalf("after activation the gateway is served %v, want version 3", got)
	}
}

// TestHR519_RollbackOnlyBeforeConfirmation: a rollback, gated as activation
// is (credential.rotate with a fresh step-up of the person's own key; D274),
// restores the old
// key and revokes the candidate while the rotation is ACTIVATING; once
// confirmation started it is refused.
// Covers: F424
func TestHR519_RollbackOnlyBeforeConfirmation(t *testing.T) {
	e := newRotationEnv(t)
	r := e.tested(t)
	if _, err := e.svc.ActivateRotation(e.person, r.ID, e.stepUp()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.RollBackRotation(e.person, r.ID, "dispatches fail with the new key", stepup.StepUp{}); !stepup.Is(err) {
		t.Fatalf("roll back without a step-up: %v", err)
	}
	if _, err := e.svc.RollBackRotation(e.sealer, r.ID, "dispatches fail with the new key", e.stepUp()); !stepup.Is(err) {
		t.Fatalf("roll back with another person's key: %v", err)
	}
	if s := e.credentialStates(t); s[1] != "SUPERSEDED" || s[2] != "ACTIVE" {
		t.Fatalf("a refused rollback changed credentials: %v", s)
	}
	r, err := e.svc.RollBackRotation(e.person, r.ID, "dispatches fail with the new key", e.stepUp())
	if err != nil || r.State != string(domain.RotationRolledBack) {
		t.Fatalf("roll back: %+v %v", r, err)
	}
	if s := e.credentialStates(t); s[1] != "ACTIVE" || s[2] != "REVOKED" {
		t.Fatalf("after the rollback: %v", s)
	}
	if got := e.served(t); len(got) != 1 || got[0] != 1 {
		t.Fatalf("after the rollback the gateway is served %v", got)
	}

	r = e.tested(t)
	if _, err := e.svc.ActivateRotation(e.person, r.ID, e.stepUp()); err != nil {
		t.Fatal(err)
	}
	if r, err = e.svc.ConfirmRotation(e.person, r.ID); err != nil || r.State != string(domain.RotationConfirming) {
		t.Fatalf("confirm: %+v %v", r, err)
	}
	if _, err := e.svc.RollBackRotation(e.person, r.ID, "too late", e.stepUp()); !is(err, app.ErrRollbackClosed) {
		t.Fatalf("roll back while confirming: %v", err)
	}
	l, _ := e.lease(t, e.gateway)
	e.report(t, l, domain.Probe{AppStatus: 200, AppMatches: true, ActiveStatus: 200, ActiveMatches: true})
	if _, err := e.svc.RollBackRotation(e.person, r.ID, "still too late", e.stepUp()); !is(err, app.ErrRollbackClosed) {
		t.Fatalf("roll back after a confirmation: %v", err)
	}
}

// TestHR520_TheOldKeyIsRevokedOnlyWhenGitHubRefusesIt: the confirmation
// lease carries the old key and names the active (new) key as its control
// (D274). A confirmation in which GitHub did not refuse the old key, or
// refused both keys (a skewed clock), returns the rotation to
// AWAITING_OLD_REMOVAL and leaves the old credential SUPERSEDED; only a 401
// for the old key while the active key gets 200 for the App revokes it and
// confirms the rotation, audited.
// Covers: F424
func TestHR520_TheOldKeyIsRevokedOnlyWhenGitHubRefusesIt(t *testing.T) {
	e := newRotationEnv(t)
	r := e.tested(t)
	if _, err := e.svc.ActivateRotation(e.person, r.ID, e.stepUp()); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]domain.Probe{
		"old accepted":        {AppStatus: 200, AppMatches: true, ActiveStatus: 200, ActiveMatches: true},
		"old forbidden":       {AppStatus: 403, ActiveStatus: 200, ActiveMatches: true},
		"server error":        {AppStatus: 500, ActiveStatus: 200, ActiveMatches: true},
		"no answer":           {ActiveStatus: 200, ActiveMatches: true},
		"both refused (skew)": {AppStatus: 401, ActiveStatus: 401},
		"no control":          {AppStatus: 401},
	} {
		if _, err := e.svc.ConfirmRotation(e.person, r.ID); err != nil {
			t.Fatalf("confirm (%s): %v", name, err)
		}
		l, ok := e.lease(t, e.gateway)
		if !ok {
			t.Fatal("no confirmation lease")
		}
		var req domain.RotationLease
		if err := json.Unmarshal(l.Request, &req); err != nil || req.Credential.ID != r.OldCredentialID.String() ||
			req.Active != r.CandidateCredentialID.String() {
			t.Fatalf("the confirmation lease carries %s with control %s (%v)", req.Credential.ID, req.Active, err)
		}
		e.report(t, l, p)
		if got := e.get(t, r.ID); got.State != string(domain.RotationAwaitingOldRemoval) || e.credentialStates(t)[1] != "SUPERSEDED" {
			t.Fatalf("%s: %s %v", name, got.State, e.credentialStates(t))
		}
	}
	if _, err := e.svc.ConfirmRotation(e.person, r.ID); err != nil {
		t.Fatal(err)
	}
	l, _ := e.lease(t, e.gateway)
	e.report(t, l, domain.Probe{AppStatus: 401, ActiveStatus: 200, ActiveMatches: true})
	if got := e.get(t, r.ID); got.State != string(domain.RotationConfirmed) || e.credentialStates(t)[1] != "REVOKED" {
		t.Fatalf("401: %s %v", got.State, e.credentialStates(t))
	}
	var audited int
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.credential.rotation_confirmed'`).Scan(&audited)
	}); err != nil || audited != 1 {
		t.Fatalf("%d confirmations audited: %v", audited, err)
	}
}

// TestT224_RotationLockoutAndRollbackAbuse: a rotation needs the current
// preview; while one is open no other credential is stored, nor a second
// rotation opened; a test lease whose rotation moved on is cancelled
// rather than handed out; a report under another lease is refused; and a
// candidate for another installation is refused.
// Covers: F424
func TestT224_RotationLockoutAndRollbackAbuse(t *testing.T) {
	e := newRotationEnv(t)
	if _, err := e.svc.RequestRotation(e.person, e.conn.ID, []byte("stale")); !is(err, app.ErrRotationPreview) {
		t.Fatalf("a stale preview: %v", err)
	}
	r, err := e.svc.RequestRotation(e.person, e.conn.ID, e.digest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.RequestRotation(e.person, e.conn.ID, e.digest); !is(err, app.ErrRotationOpen) {
		t.Fatalf("a second rotation: %v", err)
	}
	_, in := e.seal(t, `{"v":1}`)
	in.Kind, in.GitHub = domain.KindGitHubApp, rotationGitHub
	if _, err := e.svc.PutCredential(e.sealer, in); !is(err, app.ErrRotationOpen) {
		t.Fatalf("a credential stored during a rotation: %v", err)
	}
	in.GitHub = &domain.Installation{AppClientID: "Iv23liApp", ID: 8, Account: "acme"}
	if _, err := e.svc.SealCandidate(e.person, r.ID, in); !is(err, app.ErrRotationInstallation) {
		t.Fatalf("a candidate for another installation: %v", err)
	}
	in.GitHub = rotationGitHub
	if _, err := e.svc.SealCandidate(e.person, r.ID, in); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.TestRotation(e.person, r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CancelRotation(e.person, r.ID, "wrong key"); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.lease(t, e.gateway); ok {
		t.Fatal("a cancelled rotation's test was leased")
	}
	r = e.sealed(t)
	if _, err := e.svc.TestRotation(e.person, r.ID); err != nil {
		t.Fatal(err)
	}
	l, _ := e.lease(t, e.gateway)
	forged := make([]byte, 32)
	_, _ = rand.Read(forged)
	if _, err := e.store.Report(context.Background(), e.org, e.gateway, txapp.Report{Task: l.Task, Secret: forged, Fields: passed.Fields()}, nil); !is(err, txapp.ErrLease) {
		t.Fatalf("a report under another lease: %v", err)
	}
	if got := e.get(t, r.ID); got.TestPassedAt != nil {
		t.Fatal("a forged report passed the test")
	}
	if l.Purpose != txdomain.PurposeRotationTest || strconv.Itoa(l.Attempt) != "1" {
		t.Fatalf("lease %s attempt %d", l.Purpose, l.Attempt)
	}
}

// TestT224_AnInconclusiveTestLeavesTheRotationTesting: no answer, a rate
// limit or a server error from GitHub neither passes nor fails the
// candidate; the rotation stays TESTING, the candidate stays sealed, and
// another test may be asked for (D274).
// Covers: F424
func TestT224_AnInconclusiveTestLeavesTheRotationTesting(t *testing.T) {
	e := newRotationEnv(t)
	r := e.sealed(t)
	for _, p := range []domain.Probe{{}, {AppStatus: 429}, {AppStatus: 502}, {AppStatus: 200, AppMatches: true, InstallationStatus: 503}} {
		if _, err := e.svc.TestRotation(e.person, r.ID); err != nil {
			t.Fatalf("test (%+v): %v", p, err)
		}
		l, ok := e.lease(t, e.gateway)
		if !ok {
			t.Fatal("no test lease")
		}
		e.report(t, l, p)
		if got := e.get(t, r.ID); got.State != string(domain.RotationTesting) || got.TestPassedAt != nil || e.credentialStates(t)[2] != "CANDIDATE" {
			t.Fatalf("%+v: %s %v", p, got.State, e.credentialStates(t))
		}
	}
	if _, err := e.svc.TestRotation(e.person, r.ID); err != nil {
		t.Fatal(err)
	}
	l, _ := e.lease(t, e.gateway)
	e.report(t, l, passed)
	if got := e.get(t, r.ID); got.TestPassedAt == nil {
		t.Fatal("the retried test did not pass")
	}
}

// TestT224_EveryRotationChangeEnqueuesARecompute: activation, the closing
// of a rollback window, a confirmation, a rollback and a failure each run
// the recompute hook in their transaction (D259, D274), so
// unconfirmed_rotation is raised and remediated without waiting for the
// periodic recompute.
// Covers: F424
func TestT224_EveryRotationChangeEnqueuesARecompute(t *testing.T) {
	e := newRotationEnv(t)
	events := map[string]int{}
	var last []string
	e.svc.OnRotationChange(func(ctx context.Context, tx db.TenantTx) error {
		if tx.OrgID() != e.org {
			t.Error("the hook ran outside the org's transaction")
		}
		var kind string
		if err := tx.QueryRow(ctx, "SELECT kind FROM pc.ledger_entries WHERE xid = pg_current_xact_id() ORDER BY id DESC LIMIT 1").Scan(&kind); err != nil {
			return err
		}
		events[kind]++
		last = append(last, kind)
		return nil
	})
	r := e.tested(t)
	if _, err := e.svc.ActivateRotation(e.person, r.ID, e.stepUp()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.RollBackRotation(e.person, r.ID, "back", e.stepUp()); err != nil {
		t.Fatal(err)
	}
	r = e.sealed(t)
	if _, err := e.svc.CancelRotation(e.person, r.ID, "wrong key"); err != nil {
		t.Fatal(err)
	}
	r = e.tested(t)
	if _, err := e.svc.ActivateRotation(e.person, r.ID, e.stepUp()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.ConfirmRotation(e.person, r.ID); err != nil {
		t.Fatal(err)
	}
	l, _ := e.lease(t, e.gateway)
	e.report(t, l, domain.Probe{AppStatus: 401, ActiveStatus: 200, ActiveMatches: true})
	for _, k := range []string{
		"audit.credential.rotation_activated", "audit.credential.rotation_rolled_back", "audit.credential.rotation_failed",
		"audit.credential.rotation_confirmed", "audit.credential.rotation_tested",
	} {
		if events[k] == 0 {
			t.Errorf("%s ran no recompute (ran for %v)", k, last)
		}
	}
	// The sweep that closes a passed rollback window is a change too.
	r = e.tested(t)
	e.exec(t, `UPDATE pc.credential_rotations SET state = 'ACTIVATING', activated_by = 'test', activated_at = now() - interval '25 hours',
		rollback_until = now() - interval '1 hour' WHERE id = $1`, r.ID)
	if _, err := e.svc.ListRotations(e.person, e.conn.ID); err != nil {
		t.Fatal(err)
	}
	if events["audit.credential.rotation_window_closed"] != 1 || e.get(t, r.ID).State != string(domain.RotationAwaitingOldRemoval) {
		t.Fatalf("closing the window: %v", last)
	}
}
