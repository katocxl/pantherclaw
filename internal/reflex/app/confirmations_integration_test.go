// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/changes"
	"github.com/katocxl/pantherclaw/internal/detection/engine"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/protect"
	reflexapp "github.com/katocxl/pantherclaw/internal/reflex/app"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// confirmer is a security admin with a security key and a browser session.
type confirmer struct {
	id, key, session ids.UUID
	page             context.Context
}

// confirmRange is a Business org with the real change ceremony, the Gate,
// the detections service and the detection engine.
type confirmRange struct {
	*fixture
	changes        *changes.Service
	det            *reflexapp.Detections
	eng            *engine.Engine
	author, second confirmer
}

func newConfirmRange(t *testing.T) *confirmRange {
	t.Helper()
	f := newFixture(t, billing.Business)
	env, err := engine.NewEnv(celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	r := &confirmRange{fixture: f, changes: changes.New(f.p, "https://pc.test")}
	gate := &protect.Gate{Requests: protect.Ceremony{Changes: r.changes}, Failures: &failures.Sink{}}
	protect.Register(r.changes, gate, nil)
	r.det = &reflexapp.Detections{Pool: f.p, Env: env, Ents: ents{billing.Business}}
	r.det.RegisterProtect(gate)
	r.eng = &engine.Engine{
		Pool: f.p, Builtin: []*engine.Compiled{}, Env: env, Raiser: f.hooks.Raiser(), Sink: &failures.Sink{}, Ents: ents{billing.Business},
	}
	r.author, r.second = r.person(t, "author"), r.person(t, "second")
	// Detection starts at the feed's head.
	r.drain(t)
	return r
}

func (r *confirmRange) person(t *testing.T, name string) confirmer {
	t.Helper()
	p := confirmer{id: ids.NewV7(), key: ids.NewV7(), session: ids.NewV7()}
	secret := make([]byte, 32)
	copy(secret, p.id[:])
	r.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", r.org, p.id, name)
	r.exec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		r.org, p.key, p.id, secret[:16], secret)
	r.exec(t, `INSERT INTO pc.sessions (org_id, id, user_id, secret_hash, provider, auth_time, roles_digest, expires_at)
		VALUES ($1, $2, $3, $4, 'keycloak', now(), $4, now() + interval '12 hours')`, r.org, p.session, p.id, secret)
	r.exec(t, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, $3, $4, 'ORG', 'test')`,
		r.org, ids.NewV7(), string(td.RoleSecurityAdmin), p.id)
	p.page = tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{
			Org: r.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: p.id},
			Bindings: []td.Binding{{Role: td.RoleSecurityAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: r.org.UUID()}}},
		},
		Credential: tenancy.CredBrowserSession, Session: p.session,
	})
	return p
}

// confirm signs the request's binding with p's key on their page and
// confirms it.
func (r *confirmRange) confirm(t *testing.T, p confirmer, held *protect.PendingError) error {
	t.Helper()
	req, err := r.changes.Get(p.page, held.Request)
	if err != nil {
		return err
	}
	cer := ids.NewV7()
	r.exec(t, `INSERT INTO pc.webauthn_ceremonies (org_id, id, session_id, user_id, purpose, challenge, change_request_id, expires_at)
		VALUES ($1, $2, $3, $4, 'BINDING', $5, $6, now() + interval '5 minutes')`, r.org, cer, p.session, p.id, req.Binding[:], req.ID)
	_, err = r.changes.Confirm(p.page, held.Request, changes.Assertion{Ceremony: cer, Credential: p.key})
	return err
}

// publish creates and publishes a version of the custom rule as the author.
func (r *confirmRange) publish(t *testing.T, content string) reflexapp.Rule {
	t.Helper()
	c, err := r.det.CreateCustomRule(r.author.page, content)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := r.det.PublishCustomRule(r.author.page, c.Custom.ID)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func (r *confirmRange) request(t *testing.T, version int32) *protect.PendingError {
	t.Helper()
	held, err := r.det.RequestCustomRuleConfirmation(r.author.page, "org.kill_watch", version, "reviewed with the team")
	if err != nil {
		t.Fatalf("request v%d: %v", version, err)
	}
	return held
}

// drain chains every committed entry, waiting while another transaction
// holds the chainer's xmin back, then runs the engine until the feed is
// empty.
func (r *confirmRange) drain(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for {
		if _, err := ledger.ChainAll(context.Background(), r.p, r.org, 1000); err != nil {
			t.Fatal(err)
		}
		if r.text(t, `SELECT count(*)::text FROM pc.ledger_entries e WHERE org_id = $1
			AND NOT EXISTS (SELECT 1 FROM pc.ledger_chain c WHERE c.org_id = e.org_id AND c.entry_id = e.id)`, r.org) == "0" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("entries not chained within a minute")
		}
		time.Sleep(100 * time.Millisecond)
	}
	for range 50 {
		res, err := r.eng.Process(context.Background(), r.org)
		if err != nil {
			t.Fatal(err)
		}
		if res.Events == 0 && res.To == res.From {
			return
		}
	}
	t.Fatal("the feed did not drain")
}

// fire engages the kill switch and returns the basis of the alert the
// custom rule raised for it.
func (r *confirmRange) fire(t *testing.T) reflexdomain.Basis {
	t.Helper()
	r.exec(t, "UPDATE pc.alerts SET state = 'RESOLVED' WHERE org_id = $1 AND rule_id = 'org.kill_watch' AND state = 'OPEN'", r.org)
	if err := r.p.InTenantTx(context.Background(), r.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := audit.Record(ctx, tx, audit.Event{
			Name: "security.kill_switch_engaged", Actor: evdomain.Actor{Type: "user", ID: "u1"}, Outcome: audit.Success,
			Object: &audit.Object{Type: "org", ID: r.org.String()},
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	r.drain(t)
	var basis string
	if err := r.p.InTenantTx(context.Background(), r.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, `SELECT basis FROM pc.alerts WHERE org_id = $1 AND rule_id = 'org.kill_watch' AND state = 'OPEN'
			ORDER BY id DESC LIMIT 1`, r.org).Scan(&basis)
	}); err != nil {
		t.Fatalf("no alert of the custom rule: %v", err)
	}
	return reflexdomain.Basis(basis)
}

// rule is the listed version of org.kill_watch.
func (r *confirmRange) rule(t *testing.T, version int32) reflexapp.Rule {
	t.Helper()
	l, err := r.det.ListRules(r.author.page)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range l.Rules {
		if x.Custom != nil && x.Custom.RuleID == "org.kill_watch" && x.Custom.Version == version {
			return x
		}
	}
	t.Fatalf("version %d not listed", version)
	return reflexapp.Rule{}
}

func (r *confirmRange) ended(t *testing.T, version int32) string {
	t.Helper()
	return r.text(t, `SELECT coalesce(ended_reason, 'open') FROM pc.custom_detection_rule_confirmations
		WHERE org_id = $1 AND rule_id = 'org.kill_watch' AND version = $2 ORDER BY id DESC LIMIT 1`, r.org, version)
}

func (r *confirmRange) text(t *testing.T, sql string, args ...any) string {
	t.Helper()
	var s string
	if err := r.p.InTenantTx(context.Background(), r.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&s)
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return s
}

// version n of the custom rule: the same rule with other content.
func version(n int) string {
	if n == 1 {
		return customRule
	}
	return strings.Replace(customRule, "Tells the team", "Tells the team (v"+strconv.Itoa(n)+")", 1)
}

// TestT288_OnePersonCannotMakeACustomRuleContain: a custom rule's alerts are
// RULE_MATCH only while a second person's confirmation of its exact published
// version applies. The author cannot confirm their own request; a version
// that is not the published one, or that changed before the confirmation,
// cannot be confirmed; a new version, a disable or a withdrawal makes its
// alerts INFERRED again at once. Covers: F951
func TestT288_OnePersonCannotMakeACustomRuleContain(t *testing.T) {
	r := newConfirmRange(t)
	r.publish(t, version(1))
	if b := r.fire(t); b != reflexdomain.BasisInferred {
		t.Fatalf("unconfirmed: %s", b)
	}

	// Business, a person, the published version only.
	team := &reflexapp.Detections{Pool: r.p, Env: r.det.Env, Ents: ents{billing.Team}, Protect: r.det.Protect}
	if _, err := team.RequestCustomRuleConfirmation(r.author.page, "org.kill_watch", 1, "why"); !errors.Is(err, reflexapp.ErrEdition) {
		t.Errorf("Team: %v, want EDITION_REQUIRED", err)
	}
	key := tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{
			Org: r.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: r.author.id},
			Bindings: []td.Binding{{Role: td.RoleSecurityAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: r.org.UUID()}}},
		},
		Credential: tenancy.CredAPIKey,
	})
	if _, err := r.det.RequestCustomRuleConfirmation(key, "org.kill_watch", 1, "why"); !errors.Is(err, reflexapp.ErrHumanOnly) {
		t.Errorf("API key: %v, want HUMAN_ONLY", err)
	}
	if _, err := r.det.RequestCustomRuleConfirmation(r.author.page, "org.kill_watch", 2, "why"); !errors.Is(err, reflexapp.ErrNotPublishedVersion) {
		t.Errorf("an unpublished version: %v", err)
	}
	if err := r.det.WithdrawCustomRuleConfirmation(key, "org.kill_watch", "why"); !errors.Is(err, reflexapp.ErrHumanOnly) {
		t.Errorf("withdraw with an API key: %v", err)
	}

	// The author cannot confirm their own request; a second person can.
	held := r.request(t, 1)
	if got := r.rule(t, 1); got.PendingConfirmation != held.Change || got.Confirmation != nil {
		t.Fatalf("pending: %+v", got)
	}
	if err := r.confirm(t, r.author, held); !errors.Is(err, changes.ErrSamePerson) && !errors.Is(err, changes.ErrNotEligible) {
		t.Fatalf("the author confirmed: %v", err)
	}
	if b := r.fire(t); b != reflexdomain.BasisInferred {
		t.Fatalf("after the author's attempt: %s", b)
	}
	if err := r.confirm(t, r.second, held); err != nil {
		t.Fatalf("a second person: %v", err)
	}
	got := r.rule(t, 1)
	if got.Confirmation == nil || got.Confirmation.Version != 1 || got.Confirmation.ProtectedChangeID != held.Change || !got.PendingConfirmation.IsZero() {
		t.Fatalf("confirmed: %+v", got)
	}
	if b := r.fire(t); b != reflexdomain.BasisRuleMatch {
		t.Fatalf("confirmed: %s", b)
	}
	if _, err := r.det.RequestCustomRuleConfirmation(r.author.page, "org.kill_watch", 1, "again"); !errors.Is(err, reflexapp.ErrAlreadyConfirmed) {
		t.Errorf("confirming twice: %v", err)
	}

	// A withdrawal applies at once.
	if err := r.det.WithdrawCustomRuleConfirmation(r.author.page, "org.kill_watch", "no longer reviewed"); err != nil {
		t.Fatal(err)
	}
	if b := r.fire(t); b != reflexdomain.BasisInferred || r.ended(t, 1) != "withdrawn" {
		t.Fatalf("withdrawn: %s %s", b, r.ended(t, 1))
	}
	if err := r.det.WithdrawCustomRuleConfirmation(r.author.page, "org.kill_watch", "again"); !errors.Is(err, reflexapp.ErrNotFound) {
		t.Errorf("withdrawing nothing: %v", err)
	}

	// A new version drops the confirmation.
	if err := r.confirm(t, r.second, r.request(t, 1)); err != nil {
		t.Fatal(err)
	}
	if b := r.fire(t); b != reflexdomain.BasisRuleMatch {
		t.Fatalf("confirmed again: %s", b)
	}
	r.publish(t, version(2))
	if b := r.fire(t); b != reflexdomain.BasisInferred || r.ended(t, 1) != "superseded" {
		t.Fatalf("a new version: %s %s", b, r.ended(t, 1))
	}

	// A confirmation of a version that changed before it was decided
	// applies nothing.
	stale := r.request(t, 2)
	r.publish(t, version(3))
	if err := r.confirm(t, r.second, stale); err == nil {
		t.Fatal("a stale version was confirmed")
	}
	if b := r.fire(t); b != reflexdomain.BasisInferred {
		t.Fatalf("after a stale confirmation: %s", b)
	}
	if n := r.count(t, `SELECT count(*) FROM pc.custom_detection_rule_confirmations WHERE org_id = $1 AND version = 2`, r.org); n != 0 {
		t.Fatalf("%d confirmations of the stale version", n)
	}

	// Applying checks the edition again.
	lapsed := r.request(t, 3)
	r.det.Ents = ents{billing.Team}
	if err := r.confirm(t, r.second, lapsed); !errors.Is(err, reflexapp.ErrRuleChanged) {
		t.Fatalf("confirmed after a lapse: %v", err)
	}
	r.det.Ents = ents{billing.Business}

	// A disable drops it.
	if err := r.confirm(t, r.second, r.request(t, 3)); err != nil {
		t.Fatal(err)
	}
	if b := r.fire(t); b != reflexdomain.BasisRuleMatch {
		t.Fatalf("v3 confirmed: %s", b)
	}
	if _, err := r.det.DisableCustomRule(r.author.page, r.rule(t, 3).Custom.ID, "retired"); err != nil {
		t.Fatal(err)
	}
	if r.ended(t, 3) != "disabled" || r.rule(t, 3).Confirmation != nil {
		t.Fatalf("disabled: %s", r.ended(t, 3))
	}

	// Each step is audited.
	for kind, want := range map[string]int{
		"audit.detection.custom_rule.confirmation_requested": 5, "audit.detection.custom_rule.confirmed": 3,
		"audit.detection.custom_rule.confirmation_withdrawn": 1,
	} {
		if n := r.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = $2`, r.org, kind); n != want {
			t.Errorf("%s: %d entries, want %d", kind, n, want)
		}
	}
	if n := r.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind IN ('audit.detection.rule_published', 'audit.detection.rule_disabled')
		AND convert_from(body, 'UTF8')::jsonb -> 'details' ? 'confirmation_ended'`, r.org); n != 2 {
		t.Errorf("%d publish or disable entries name the confirmation they ended, want 2", n)
	}
}

// TestHR666_AConfirmationOnlyEnds: a confirmation row's content never
// changes, and its end is written once.
func TestHR666_AConfirmationOnlyEnds(t *testing.T) {
	r := newConfirmRange(t)
	r.publish(t, version(1))
	if err := r.confirm(t, r.second, r.request(t, 1)); err != nil {
		t.Fatal(err)
	}
	err := r.p.InTenantTx(context.Background(), r.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "UPDATE pc.custom_detection_rule_confirmations SET version = 2 WHERE org_id = $1", r.org)
		return err
	})
	if !db.IsPermissionDenied(err) {
		t.Errorf("changing the version: %v, want permission denied", err)
	}
	if err := r.det.WithdrawCustomRuleConfirmation(r.author.page, "org.kill_watch", "done"); err != nil {
		t.Fatal(err)
	}
	err = r.p.InTenantTx(context.Background(), r.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "UPDATE pc.custom_detection_rule_confirmations SET ended_reason = 'disabled' WHERE org_id = $1", r.org)
		return err
	})
	if !db.IsCheckViolation(err) {
		t.Errorf("ending twice: %v, want a check violation", err)
	}
}
