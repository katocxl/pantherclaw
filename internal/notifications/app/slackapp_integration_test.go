// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	approvals "github.com/katocxl/pantherclaw/internal/approvals/app"
	billingdomain "github.com/katocxl/pantherclaw/internal/billing/domain"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	"github.com/katocxl/pantherclaw/internal/sim/slack"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	waitlist "github.com/katocxl/pantherclaw/internal/waitlist/app"
)

const (
	slackToken    = "xoxb-simulated-integration-token"
	slackApproval = "C0APPROVAL1"
	slackExternal = "C0EXTERNAL1"
	// boundTitle is an approval title rendered from the action's
	// parameters: a card never shows it (D88 H1).
	boundTitle = "Refund 125.00 USD on charge ch_1"
)

// approver is a person who may decide requests: an Approver for 30 days
// with a 30-day-old key and a browser session.
type approver struct{ id, cred, browser ids.UUID }

// slackEnv is a Team-edition notification service whose slack_app channels
// reach a simulated Slack, with the real approvals service and waitlist
// router driving the requests it posts cards for (G0 M14 D90).
type slackEnv struct {
	*env
	sim       *slack.Server
	key       ids.UUID // alice's security key
	approvals *approvals.Service
	router    *waitlist.Router
	dave      approver
	agent     ids.UUID
	run       ids.UUID
	grant     ids.UUID
}

// newSlackEnv starts the environment; require is the one bot token the
// simulator accepts ("" accepts any).
func newSlackEnv(t *testing.T, require string) *slackEnv {
	t.Helper()
	e := newEnv(t)
	e.svc.SetEditions(edition(billingdomain.Team))
	sim := slack.New([]slack.Channel{
		{ID: slackApproval, Name: "approvals", Member: true},
		{ID: slackExternal, Name: "shared", Member: true, ExtShared: true, Shared: true},
	}, slack.Faults{}, pclog.Discard()).WithRequire(slack.Require{Token: require})
	ts := httptest.NewServer(sim.Handler())
	t.Cleanup(ts.Close)
	if err := e.svc.SetSlackAPI(ts.URL+"/api", ts.Client()); err != nil {
		t.Fatal(err)
	}
	s := &slackEnv{env: e, sim: sim, key: ids.NewV7(), agent: ids.NewV7(), run: ids.NewV7(), grant: ids.NewV7()}
	s.approvals = &approvals.Service{Pool: e.pool, Notify: e.svc}
	s.router = &waitlist.Router{Pool: e.pool, Notify: e.svc}
	e.exec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name, state) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key', 'ACTIVE')`,
		e.org, s.key, e.alice, bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{7}, 32))
	s.dave = s.approver(t, "dave")
	team, envID := ids.NewV7(), ids.NewV7()
	e.exec(t, "INSERT INTO pc.environments (org_id, id, slug, name, kind) VALUES ($1, $2, 'prod', 'Production', 'PRODUCTION')", e.org, envID)
	e.exec(t, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'billing', 'Billing')", e.org, team)
	e.exec(t, `INSERT INTO pc.agents (org_id, id, name, state, created_by, claimed_at, team_id, environment_id, owner_user_id, execution_context)
		VALUES ($1, $2, 'billing-bot', 'CLAIMED', 'test', now(), $3, $4, $5, 'service')`, e.org, s.agent, team, envID, e.bob)
	e.exec(t, `INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_user_id, principal_user_id, principal_source, expires_at)
		VALUES ($1, $2, $3, $4, $5, $5, 'launcher', now() + interval '8 hours')`, e.org, s.run, s.agent, envID, e.bob)
	e.exec(t, `INSERT INTO pc.grants (org_id, id, agent_id, principal_user_id, environment_id, depth, current_revision, grantor_kind,
		grantor_id, basis) VALUES ($1, $2, $3, $4, $5, 0, 1, 'user', $4, 'test')`, e.org, s.grant, s.agent, e.bob, envID)
	e.exec(t, "INSERT INTO pc.grant_lineage (org_id, grant_id, ancestor_id, distance) VALUES ($1, $2, $2, 0)", e.org, s.grant)
	e.exec(t, "INSERT INTO pc.org_containment (org_id) VALUES ($1)", e.org)
	pkg, version := ids.NewV7(), ids.NewV7()
	e.exec(t, "INSERT INTO pc.tool_packages (org_id, id, name) VALUES ($1, $2, 'pc.mock-payments')", e.org, pkg)
	e.exec(t, `INSERT INTO pc.package_versions (org_id, id, package_id, version, file_digest, raw, state)
		VALUES ($1, $2, $3, '1.0.0', 'sha256:' || repeat('0', 64), '{7d', 'ACTIVE')`, e.org, version, pkg)
	return s
}

func (s *slackEnv) approver(t *testing.T, name string) approver {
	t.Helper()
	p := approver{id: ids.NewV7(), cred: ids.NewV7(), browser: ids.NewV7()}
	secret := make([]byte, 32)
	copy(secret, p.id[:])
	s.exec(t, `INSERT INTO pc.users (org_id, id, issuer, subject, created_at) VALUES ($1, $2, 'https://idp.test', $3, now() - interval '30 days')`,
		s.org, p.id, name)
	s.exec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name, created_at) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key', now() - interval '30 days')`,
		s.org, p.cred, p.id, secret[:16], secret)
	s.exec(t, `INSERT INTO pc.sessions (org_id, id, user_id, secret_hash, provider, auth_time, roles_digest, expires_at)
		VALUES ($1, $2, $3, $4, 'keycloak', now(), $4, now() + interval '12 hours')`, s.org, p.browser, p.id, secret)
	s.exec(t, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by, created_at)
		VALUES ($1, $2, 'approver', $3, 'ORG', $4, now() - interval '30 days')`, s.org, ids.NewV7(), p.id, "user:"+s.alice.String())
	return p
}

func (s *slackEnv) admin() context.Context { return s.as(td.KindUser, s.alice, td.RoleOrgAdmin) }

func (s *slackEnv) fresh() stepup.StepUp { return stepup.StepUp{Credential: s.key, At: time.Now()} }

func (s *slackEnv) channel(t *testing.T, name, slackChannel, level string) napp.ChannelView {
	t.Helper()
	c, _, err := s.svc.CreateChannel(s.admin(), napp.ChannelInput{
		Name: name, Kind: domain.KindSlackApp, EventTypes: []string{"approval.*", "channel.test"},
		SlackApp: &domain.SlackAppConfig{ChannelID: slackChannel, DataLevel: level, BotToken: slackToken},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// activate checks the channel on its page and activates it with alice's key.
func (s *slackEnv) activate(t *testing.T, c napp.ChannelView) napp.ChannelView {
	t.Helper()
	p, err := s.svc.PreviewSlackApp(s.admin(), c.ID)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	got, err := s.svc.ActivateSlackApp(s.admin(), c.ID, p.Version, s.fresh())
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	return got
}

// hold records a waiting approval request, as the Authority records a hold:
// a refund whose rendered title is boundTitle, with its hold slots and its
// waitlist entry; the router then sends its approval.requested notice.
func (s *slackEnv) hold(t *testing.T, deadline time.Duration) ids.UUID {
	t.Helper()
	txn, id := ids.NewV7(), ids.NewV7()
	binding := sha256.Sum256(id[:])
	s.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id, state)
		VALUES ($1, $2, $3, $4, $5, 'payments.refund.create', 'REQUIRE_APPROVAL', 'REFUND_OVER_50', 'gw', 'OPEN')`,
		s.org, txn, s.run, ids.NewV7(), binding[:])
	s.exec(t, `INSERT INTO pc.approval_requests (org_id, id, subject_kind, agent_id, transaction_id, evaluation, run_id, grant_id,
		grant_revision, variant_key, operation, binding, binding_input, requirements, display, display_hash, action_ir, deadline_at)
		VALUES ($1, $2, 'ACTION', $3, $4, 1, $5, $6, 1, $7, 'payments.refund.create', $7, '\x7b7d',
		'[{"kind":"approval","role":"approver","count":1,"sources":[]}]',
		jsonb_build_object('title', $8::text, 'consequence', jsonb_build_object('operation', 'payments.refund.create', 'reversibility', 'irreversible'),
			'fields', jsonb_build_array(jsonb_build_object('name', 'amount', 'value', '125.00 USD'))),
		$7, convert_to('{"definition":{"package":"pc.mock-payments","version":"1.0.0"}}', 'UTF8'),
		date_trunc('second', now()) + make_interval(secs => $9::int))`,
		s.org, id, s.agent, txn, s.run, s.grant, binding[:], boundTitle, int(deadline/time.Second))
	s.exec(t, `INSERT INTO pc.hold_slots (org_id, scope_kind, scope_id, pending) VALUES ($1, 'grant', $2, 1), ($1, 'run', $3, 1)
		ON CONFLICT (org_id, scope_kind, scope_id) DO UPDATE SET pending = pc.hold_slots.pending + 1`, s.org, s.grant, s.run)
	s.exec(t, `INSERT INTO pc.waitlist_entries (org_id, id, kind, subject_type, subject_id, agent_id, run_id, transaction_id, deadline_at)
		VALUES ($1, $2, 'ACTION_HOLD', 'approval_request', $3, $4, $5, $6, now() + make_interval(secs => $7::int))`,
		s.org, ids.NewV7(), id, s.agent, s.run, txn, int(deadline/time.Second))
	if _, err := s.router.RouteOrg(context.Background(), s.org); err != nil {
		t.Fatal(err)
	}
	return id
}

func (s *slackEnv) approve(t *testing.T, request ids.UUID) {
	t.Helper()
	ceremony := ids.NewV7()
	s.exec(t, `INSERT INTO pc.webauthn_ceremonies (org_id, id, session_id, user_id, purpose, challenge, approval_request_id, expires_at)
		SELECT $1, $2, $3, $4, 'BINDING', binding, id, now() + interval '5 minutes' FROM pc.approval_requests WHERE id = $5`,
		s.org, ceremony, s.dave.browser, s.dave.id, request)
	if _, err := s.approvals.Approve(context.Background(), s.org, approvals.Responder{User: s.dave.id, Browser: s.dave.browser}, request,
		approvals.Assertion{Ceremony: ceremony, Credential: s.dave.cred, AuthenticatorData: make([]byte, 37), ClientDataJSON: []byte(`{}`), Signature: []byte{1}},
	); err != nil {
		t.Fatalf("approve: %v", err)
	}
}

func (s *slackEnv) decline(t *testing.T, request ids.UUID) {
	t.Helper()
	ctx := tapp.WithCaller(context.Background(), tapp.Caller{
		Subject: td.Subject{Org: s.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: s.dave.id},
			Bindings: []td.Binding{{Role: td.RoleApprover, Scope: td.Scope{Type: td.ScopeOrg, ID: s.org.UUID()}}}},
		Credential: tapp.CredBrowserSession, Session: s.dave.browser,
	})
	if _, err := s.approvals.Decline(ctx, request, "TOO_RISKY", "", ""); err != nil {
		t.Fatalf("decline: %v", err)
	}
}

// deliverAll makes one attempt of every pending slack_app delivery, oldest
// first, and returns the last error.
func (s *slackEnv) deliverAll(t *testing.T) error {
	t.Helper()
	var pending []ids.UUID
	if err := s.pool.InTenantTx(context.Background(), s.org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := tx.Query(ctx, "SELECT id FROM pc.deliveries WHERE state = 'PENDING' AND kind = 'slack_app' ORDER BY created_at, id")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id ids.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			pending = append(pending, id)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	var last error
	for _, d := range pending {
		if err := s.svc.Deliver(context.Background(), s.org, d); err != nil {
			last = err
		}
	}
	return last
}

func (s *slackEnv) str(t *testing.T, sql string, args ...any) string {
	t.Helper()
	var v string
	if err := s.pool.InTenantTx(context.Background(), s.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&v)
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return v
}

func (s *slackEnv) cardState(t *testing.T, request ids.UUID) string {
	t.Helper()
	return s.str(t, "SELECT state FROM pc.slack_cards WHERE request_id = $1", request)
}

// card is the simulator's copy of the request's card, by its reference.
func (s *slackEnv) card(t *testing.T, request ids.UUID) slack.Message {
	t.Helper()
	for _, m := range s.sim.Messages() {
		if m.ThreadTS == "" && strings.Contains(m.Text, request.String()[28:]) {
			return m
		}
	}
	t.Fatalf("no card for %s in %+v", request, s.sim.Messages())
	return slack.Message{}
}

func noBoundValues(t *testing.T, what, s string) {
	t.Helper()
	for _, no := range []string{"125.00", "USD", "ch_1", "Refund 125", "bob"} {
		if strings.Contains(s, no) {
			t.Fatalf("%s shows %q: %s", what, no, s)
		}
	}
}

// TestHR315_SlackAppNeedsAStepUpAndSlacksChecks: a slack_app channel is
// stored PENDING_ACTIVATION and gets no deliveries; its page shows what
// Slack reports, and only an Org Admin with a fresh step-up of their own
// key activates it, for the version the page showed, when auth.test and
// conversations.info confirm the token and an internal channel the bot is
// in. A new token through UpdateChannel puts it back to
// PENDING_ACTIVATION, which stops its deliveries until it is confirmed
// again, and must stay in the same Slack workspace (D22, D66, D88).
func TestHR315_SlackAppNeedsAStepUpAndSlacksChecks(t *testing.T) {
	s := newSlackEnv(t, slackToken)
	c := s.channel(t, "approvals", slackApproval, "")
	if c.SlackApp == nil || c.SlackApp.State != napp.SlackPending || c.SlackApp.DataLevel != domain.SlackMinimal {
		t.Fatalf("created: %+v", c.SlackApp)
	}
	s.hold(t, time.Hour)
	if n := s.str(t, "SELECT count(*)::text FROM pc.deliveries WHERE channel_id = $1", c.ID); n != "0" {
		t.Fatalf("a pending channel got %s deliveries", n)
	}
	resume := false
	if _, err := s.svc.UpdateChannel(s.admin(), c.ID, napp.ChannelUpdate{Paused: &resume}); !errors.Is(err, napp.ErrSlackState) {
		t.Fatalf("resumed a pending channel: %v", err)
	}
	p, err := s.svc.PreviewSlackApp(s.admin(), c.ID)
	if err != nil || p.TeamID != slack.TeamID || p.BotID != slack.BotID || p.ChannelName != "approvals" || p.TeamName != "Simulated" || p.Version == "" {
		t.Fatalf("preview: %v %+v", err, p)
	}
	if _, err := s.svc.PreviewSlackApp(s.as(td.KindUser, s.carol, td.RoleViewer), c.ID); err == nil {
		t.Fatal("a viewer previewed")
	}
	for name, su := range map[string]stepup.StepUp{
		"none": {}, "stale": {Credential: s.key, At: time.Now().Add(-10 * time.Minute)}, "not hers": {Credential: ids.NewV7(), At: time.Now()},
	} {
		if _, err := s.svc.ActivateSlackApp(s.admin(), c.ID, p.Version, su); !errors.Is(err, stepup.ErrStepUp) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := s.svc.ActivateSlackApp(s.as(td.KindUser, s.alice, td.RoleSecurityAdmin), c.ID, p.Version, s.fresh()); !errors.Is(err, napp.ErrSlackOrgAdmin) {
		t.Fatalf("a Security Admin activated: %v", err)
	}
	if _, err := s.svc.ActivateSlackApp(s.admin(), c.ID, "1", s.fresh()); !errors.Is(err, napp.ErrSlackChanged) {
		t.Fatalf("activated another version: %v", err)
	}
	got, err := s.svc.ActivateSlackApp(s.admin(), c.ID, p.Version, s.fresh())
	if err != nil || got.SlackApp.State != napp.SlackActive || got.SlackApp.TeamID != slack.TeamID || got.SlackApp.ActivatedAt == nil {
		t.Fatalf("activate: %v %+v", err, got.SlackApp)
	}
	if _, err := s.svc.ActivateSlackApp(s.admin(), c.ID, p.Version, s.fresh()); !errors.Is(err, napp.ErrSlackState) {
		t.Fatalf("activated twice: %v", err)
	}

	// An externally shared channel is refused.
	ext := s.channel(t, "shared", slackExternal, "")
	if _, err := s.svc.PreviewSlackApp(s.admin(), ext.ID); !errors.Is(err, napp.ErrSlackShared) {
		t.Fatalf("external preview: %v", err)
	}

	// A new token: back to PENDING_ACTIVATION, queued deliveries stop, new
	// notices are not routed, until it is confirmed again.
	s.hold(t, time.Hour)
	queued := mustUUIDStr(t, s.str(t, "SELECT id::text FROM pc.deliveries WHERE state = 'PENDING' AND kind = 'slack_app' LIMIT 1"))
	bad := "not-a-token"
	if _, err := s.svc.UpdateChannel(s.admin(), c.ID, napp.ChannelUpdate{SlackBotToken: &bad}); !errors.Is(err, napp.ErrInvalidChannel) {
		t.Fatalf("bad token: %v", err)
	}
	other := "xoxb-simulated-replacement-token"
	v, err := s.svc.UpdateChannel(s.admin(), c.ID, napp.ChannelUpdate{SlackBotToken: &other})
	if err != nil || v.SlackApp.State != napp.SlackPending || v.SlackApp.ActivatedAt != nil || v.SlackApp.TokenReplacedAt == nil {
		t.Fatalf("replace: %v %+v", err, v.SlackApp)
	}
	if err := s.svc.Deliver(context.Background(), s.org, queued); err != nil || s.row(t, queued).lastError != "channel_pending" || len(s.sim.Messages()) != 0 {
		t.Fatalf("queued delivery after replacement: %v %+v", err, s.row(t, queued))
	}
	before := s.str(t, "SELECT count(*)::text FROM pc.deliveries WHERE channel_id = $1", c.ID)
	s.hold(t, time.Hour)
	if n := s.str(t, "SELECT count(*)::text FROM pc.deliveries WHERE channel_id = $1", c.ID); n != before {
		t.Fatalf("routed to a replaced channel: %s", n)
	}
	// The simulator accepts only the first token: the new one is refused.
	if _, err := s.svc.PreviewSlackApp(s.admin(), c.ID); !errors.Is(err, napp.ErrSlackTokenRefused) {
		t.Fatalf("preview a refused token: %v", err)
	}
	if _, err := s.svc.UpdateChannel(s.admin(), c.ID, napp.ChannelUpdate{SlackBotToken: ptr(slackToken)}); err != nil {
		t.Fatal(err)
	}
	// A token of another workspace is refused: that is a new channel.
	s.sim.SetTeam("T0OTHERTEAM")
	if _, err := s.svc.PreviewSlackApp(s.admin(), c.ID); !errors.Is(err, napp.ErrSlackWorkspace) {
		t.Fatalf("another workspace: %v", err)
	}
	s.sim.SetTeam(slack.TeamID)
	if got := s.activate(t, c); got.SlackApp.State != napp.SlackActive {
		t.Fatalf("reactivate: %+v", got.SlackApp)
	}

	// Below the Team edition nothing is created, previewed or activated.
	s.svc.SetEditions(edition(billingdomain.Community))
	if _, _, err := s.svc.CreateChannel(s.admin(), napp.ChannelInput{
		Name: "community", Kind: domain.KindSlackApp, EventTypes: []string{"approval.*"},
		SlackApp: &domain.SlackAppConfig{ChannelID: slackApproval, BotToken: slackToken},
	}); !errors.Is(err, napp.ErrSlackEdition) {
		t.Fatalf("community create: %v", err)
	}
	if _, err := s.svc.ActivateSlackApp(s.admin(), ext.ID, "1", s.fresh()); !errors.Is(err, napp.ErrSlackEdition) {
		t.Fatalf("community activate: %v", err)
	}
}

func ptr(s string) *string { return &s }

// TestT145_SlackCardLifecycle: the router's notice of a waiting request
// posts one minimal card, with a link button only and nothing the approval
// binds; the approvals service's decision, decline and expiry update the
// card in place to a closed card without button or link; a request made
// before the activation gets no card; a 429 is retried and posts once; none
// of it decides anything (D23, D66, D88, F167).
func TestT145_SlackCardLifecycle(t *testing.T) {
	s := newSlackEnv(t, slackToken)
	c := s.channel(t, "approvals", slackApproval, "")
	early := s.hold(t, time.Hour)
	s.activate(t, c)

	approved := s.hold(t, time.Hour)
	if err := s.deliverAll(t); err != nil {
		t.Fatal(err)
	}
	if len(s.sim.Messages()) != 1 {
		t.Fatalf("posted: %+v (the request before the activation gets no card)", s.sim.Messages())
	}
	open := s.card(t, approved)
	body := open.Text + string(open.Blocks)
	for _, want := range []string{"Approval needed", "Irreversible", "Agent action", `"button"`, "/approvals/" + approved.String()} {
		if !strings.Contains(body, want) {
			t.Fatalf("open card lacks %q: %s", want, body)
		}
	}
	noBoundValues(t, "the open card", body)
	if strings.Contains(body, "payments.refund.create") || strings.Contains(body, "billing-bot") {
		t.Fatalf("a minimal card shows summary data: %s", body)
	}
	if s.cardState(t, approved) != domain.CardOpen {
		t.Fatal("card not stored")
	}
	if n := s.str(t, "SELECT count(*)::text FROM pc.slack_cards WHERE request_id = $1", early); n != "0" {
		t.Fatalf("a request before the activation got a card: %s", n)
	}

	s.approve(t, approved)
	if err := s.deliverAll(t); err != nil {
		t.Fatal(err)
	}
	closed := s.card(t, approved)
	cb := closed.Text + string(closed.Blocks)
	if closed.Updates != 1 || !strings.Contains(cb, "Approved") || strings.Contains(cb, "button") || strings.Contains(cb, "/approvals/") ||
		strings.Contains(cb, "dave") || s.cardState(t, approved) != domain.CardClosed {
		t.Fatalf("approved card: %+v", closed)
	}

	declined := s.hold(t, time.Hour)
	_ = s.deliverAll(t)
	s.decline(t, declined)
	_ = s.deliverAll(t)
	if m := s.card(t, declined); !strings.Contains(m.Text, "Declined") || m.Updates != 1 {
		t.Fatalf("declined card: %+v", m)
	}

	expired := s.hold(t, 2*time.Second)
	_ = s.deliverAll(t)
	time.Sleep(3 * time.Second)
	if _, err := approvals.SweepOrg(context.Background(), s.pool, s.svc, s.org); err != nil {
		t.Fatal(err)
	}
	_ = s.deliverAll(t)
	if m := s.card(t, expired); !strings.Contains(m.Text, "Expired") {
		t.Fatalf("expired card: %+v", m)
	}

	// A 429 is retried after Retry-After; the card is posted once.
	s.sim.SetFaults(slack.Faults{RateLimit: 1, RetryAfter: 30})
	limited := s.hold(t, time.Hour)
	var ra napp.RetryAfterError
	if err := s.deliverAll(t); !errors.As(err, &ra) || ra.Wait < 30*time.Second {
		t.Fatalf("429: %v", err)
	}
	if n := s.str(t, "SELECT count(*)::text FROM pc.slack_cards WHERE request_id = $1", limited); n != "0" {
		t.Fatalf("a refused post kept its claim: %s", n)
	}
	before := len(s.sim.Messages())
	if err := s.deliverAll(t); err != nil || len(s.sim.Messages()) != before+1 || s.cardState(t, limited) != domain.CardOpen {
		t.Fatalf("retry: %v %d", err, len(s.sim.Messages()))
	}
	// The requests were decided by the approvals service alone.
	if st := s.str(t, "SELECT state FROM pc.approval_requests WHERE id = $1", limited); st != "PENDING" {
		t.Fatalf("a card changed a request: %s", st)
	}
}

// TestT145_ALostAnswerIsUnknownAndNeverReposted: a post whose answer is
// lost leaves its card UNKNOWN, fails the delivery, and is never posted
// again, however often the notice comes (D88 M1).
func TestT145_ALostAnswerIsUnknownAndNeverReposted(t *testing.T) {
	s := newSlackEnv(t, slackToken)
	s.activate(t, s.channel(t, "approvals", slackApproval, ""))
	s.sim.SetFaults(slack.Faults{DropAnswer: 1})
	req := s.hold(t, time.Hour)
	_ = s.deliverAll(t)
	if len(s.sim.Messages()) != 1 || s.cardState(t, req) != "UNKNOWN" {
		t.Fatalf("lost answer: %d messages, card %s", len(s.sim.Messages()), s.cardState(t, req))
	}
	if n := s.str(t, "SELECT count(*)::text FROM pc.deliveries WHERE kind = 'slack_app' AND state = 'FAILED' AND last_error = 'slack_post_unknown'"); n != "1" {
		t.Fatalf("delivery health: %s failed unknown", n)
	}
	// The same notice again, as a re-sent notification would: nothing is
	// posted.
	if err := s.pool.InTenantTx(context.Background(), s.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := s.svc.Enqueue(ctx, tx, napp.Message{
			Org: s.org, Type: "approval.requested", Subject: &napp.Subject{Type: "approval_request", ID: req},
			Params: map[string]string{"operation": "payments.refund.create", "agent": s.agent.String(), "deadline": "2026-10-17T12:00:00Z", "request": req.String()},
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	_ = s.deliverAll(t)
	if len(s.sim.Messages()) != 1 {
		t.Fatalf("reposted: %+v", s.sim.Messages())
	}
	s.approve(t, req)
	_ = s.deliverAll(t)
	if len(s.sim.Messages()) != 1 || s.sim.Messages()[0].Updates != 0 {
		t.Fatalf("an unknown card was updated: %+v", s.sim.Messages())
	}
}

// TestT145_SlackReconcilerClosesCardsAndPausesSharedChannels: the minute
// reconciler closes an OPEN card whose request the approvals service ended
// without its notice reaching Slack, also after a downgrade; a new request
// then gets no card; and a channel Slack now shares outside the workspace
// returns to PENDING_ACTIVATION, is audited, and its admins are told (D88).
func TestT145_SlackReconcilerClosesCardsAndPausesSharedChannels(t *testing.T) {
	s := newSlackEnv(t, slackToken)
	c := s.activate(t, s.channel(t, "approvals", slackApproval, ""))
	declined := s.hold(t, time.Hour)
	expired := s.hold(t, 2*time.Second)
	_ = s.deliverAll(t)
	s.decline(t, declined)
	time.Sleep(3 * time.Second)
	if _, err := approvals.SweepOrg(context.Background(), s.pool, s.svc, s.org); err != nil {
		t.Fatal(err)
	}
	// The decided and expired notices never reach Slack; after a downgrade,
	// closing still happens.
	s.exec(t, "UPDATE pc.deliveries SET state = 'CANCELLED', finished_at = now() WHERE state = 'PENDING' AND kind = 'slack_app'") //nolint:misspell // the schema's state name
	s.svc.SetEditions(edition(billingdomain.Community))
	r, err := s.svc.ReconcileSlack(context.Background(), s.org)
	if err != nil || r.Closed != 2 {
		t.Fatalf("reconcile: %v %+v", err, r)
	}
	if s.cardState(t, declined) != domain.CardClosed || !strings.Contains(s.card(t, declined).Text, "Declined") ||
		!strings.Contains(s.card(t, expired).Text, "Expired") {
		t.Fatalf("cards: %+v", s.sim.Messages())
	}
	if r, _ := s.svc.ReconcileSlack(context.Background(), s.org); r.Closed != 0 {
		t.Fatalf("closed twice: %+v", r)
	}
	// Below the Team edition a new request gets no card.
	s.hold(t, time.Hour)
	before := len(s.sim.Messages())
	_ = s.deliverAll(t)
	if len(s.sim.Messages()) != before {
		t.Fatal("a card was posted below the Team edition")
	}

	s.sim.SetChannel(slack.Channel{ID: slackApproval, Name: "approvals", Member: true, ExtShared: true, Shared: true})
	r, err = s.svc.ReconcileSlack(context.Background(), s.org)
	if err != nil || r.Paused != 1 {
		t.Fatalf("recheck: %v %+v", err, r)
	}
	v, _, err := s.svc.GetChannel(s.admin(), c.ID)
	if err != nil || v.SlackApp.State != napp.SlackPending {
		t.Fatalf("shared channel: %v %+v", err, v.SlackApp)
	}
	if n := s.str(t, "SELECT count(*)::text FROM pc.notifications WHERE type = 'notification.slack_channel_shared'"); n != "1" {
		t.Fatalf("admin notices: %s", n)
	}
	if n := s.str(t, "SELECT count(*)::text FROM pc.ledger_entries WHERE kind = 'audit.notification.slack_channel_shared'"); n != "1" {
		t.Fatalf("audit: %s", n)
	}
}

// TestT145_ANewTokenIsUsedForLaterUpdates: after a token replacement and a
// new activation in the same workspace, an existing card is updated with
// the new token (D88).
func TestT145_ANewTokenIsUsedForLaterUpdates(t *testing.T) {
	s := newSlackEnv(t, "")
	c := s.activate(t, s.channel(t, "approvals", slackApproval, ""))
	req := s.hold(t, time.Hour)
	_ = s.deliverAll(t)
	next := "xoxb-simulated-replacement-token"
	if _, err := s.svc.UpdateChannel(s.admin(), c.ID, napp.ChannelUpdate{SlackBotToken: &next}); err != nil {
		t.Fatal(err)
	}
	s.activate(t, c)
	s.approve(t, req)
	_ = s.deliverAll(t)
	tokens := s.sim.Tokens()
	if m := s.card(t, req); m.Updates != 1 || tokens[len(tokens)-1] != next {
		t.Fatalf("update: %+v, last token %q", m, tokens[len(tokens)-1])
	}
}

// TestHR314_SlackCardSummaryShowsNoBoundValues: SUMMARY adds the operation
// id, the agent and the environment, never the rendered approval title or
// anything else the approval binds (D23, D88 H1).
func TestHR314_SlackCardSummaryShowsNoBoundValues(t *testing.T) {
	s := newSlackEnv(t, slackToken)
	s.activate(t, s.channel(t, "summary", slackApproval, domain.SlackSummary))
	req := s.hold(t, time.Hour)
	if err := s.deliverAll(t); err != nil {
		t.Fatal(err)
	}
	m := s.card(t, req)
	body := string(m.Blocks) + m.Text
	for _, want := range []string{"Operation: payments.refund.create", "Agent: billing-bot", "Environment: Production"} {
		if !strings.Contains(body, want) {
			t.Fatalf("summary lacks %q: %s", want, body)
		}
	}
	noBoundValues(t, "the summary card", body)
}

// TestM14_SlackAPIBaseIsSlackOrLoopback: a simulator base must be loopback.
func TestM14_SlackAPIBaseIsSlackOrLoopback(t *testing.T) {
	e := newEnv(t)
	for _, base := range []string{"https://evil.example/api", "http://10.0.0.1/api", "ftp://127.0.0.1/api", "http://user@127.0.0.1/api"} {
		if err := e.svc.SetSlackAPI(base, http.DefaultClient); !errors.Is(err, napp.ErrSlackAPIBase) {
			t.Fatalf("%s: %v", base, err)
		}
	}
}

func mustUUIDStr(t *testing.T, s string) ids.UUID {
	t.Helper()
	id, err := ids.ParseUUID(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
