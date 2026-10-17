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

	billingdomain "github.com/katocxl/pantherclaw/internal/billing/domain"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	"github.com/katocxl/pantherclaw/internal/sim/slack"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const (
	slackToken    = "xoxb-simulated-integration-token"
	slackApproval = "C0APPROVAL1"
	slackExternal = "C0EXTERNAL1"
)

// slackEnv is a Team-edition service whose slack_app channels reach a
// simulated Slack.
type slackEnv struct {
	*env
	sim *slack.Server
	key ids.UUID // alice's security key
}

func newSlackEnv(t *testing.T) *slackEnv {
	t.Helper()
	e := newEnv(t)
	e.svc.SetEditions(edition(billingdomain.Team))
	sim := slack.New([]slack.Channel{
		{ID: slackApproval, Name: "approvals", Member: true},
		{ID: slackExternal, Name: "shared", Member: true, ExtShared: true, Shared: true},
	}, slack.Faults{}, pclog.Discard()).WithRequire(slack.Require{Token: slackToken})
	ts := httptest.NewServer(sim.Handler())
	t.Cleanup(ts.Close)
	if err := e.svc.SetSlackAPI(ts.URL+"/api", ts.Client()); err != nil {
		t.Fatal(err)
	}
	key := ids.NewV7()
	e.exec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name, state) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key', 'ACTIVE')`,
		e.org, key, e.alice, bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{7}, 32))
	return &slackEnv{env: e, sim: sim, key: key}
}

func (e *slackEnv) admin() context.Context { return e.as(td.KindUser, e.alice, td.RoleOrgAdmin) }

func (e *slackEnv) fresh() stepup.StepUp { return stepup.StepUp{Credential: e.key, At: time.Now()} }

func (e *slackEnv) channel(t *testing.T, slackChannel string) napp.ChannelView {
	t.Helper()
	c, _, err := e.svc.CreateChannel(e.admin(), napp.ChannelInput{
		Name: "slack-" + strings.ToLower(slackChannel), Kind: domain.KindSlackApp, EventTypes: []string{"approval.*", "channel.test"},
		SlackApp: &domain.SlackAppConfig{ChannelID: slackChannel, BotToken: slackToken},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// request records a waiting approval request for a refund of 1234.56 USD.
func (e *slackEnv) request(t *testing.T) ids.UUID {
	t.Helper()
	envID, agent, run, txn, grant, approval := ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7()
	binding := sha256.Sum256(approval[:])
	e.exec(t, "INSERT INTO pc.environments (org_id, id, slug, name, kind) VALUES ($1, $2, $3, 'Production', 'PRODUCTION')", e.org, envID, "p-"+envID.String()[28:])
	team := ids.NewV7()
	e.exec(t, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, $3, 'Billing')", e.org, team, "t-"+team.String()[28:])
	e.exec(t, `INSERT INTO pc.agents (org_id, id, name, state, created_by, claimed_at, team_id, environment_id, owner_user_id, execution_context)
		VALUES ($1, $2, 'billing-bot', 'CLAIMED', 'test', now(), $3, $4, $5, 'service')`, e.org, agent, team, envID, e.bob)
	e.exec(t, `INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_user_id, principal_user_id, principal_source, expires_at)
		VALUES ($1, $2, $3, $4, $5, $5, 'launcher', now() + interval '8 hours')`, e.org, run, agent, envID, e.bob)
	e.exec(t, `INSERT INTO pc.grants (org_id, id, agent_id, principal_user_id, environment_id, depth, current_revision, grantor_kind,
		grantor_id, basis) VALUES ($1, $2, $3, $4, $5, 0, 1, 'user', $4, 'test')`, e.org, grant, agent, e.bob, envID)
	e.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id, state)
		VALUES ($1, $2, $3, $4, $5, 'payments.refund.create', 'REQUIRE_APPROVAL', 'R', 'gw', 'OPEN')`, e.org, txn, run, ids.NewV7(), binding[:])
	e.exec(t, `INSERT INTO pc.approval_requests (org_id, id, subject_kind, agent_id, transaction_id, evaluation, run_id, grant_id,
		grant_revision, variant_key, operation, binding, binding_input, requirements, display, display_hash, action_ir, deadline_at)
		VALUES ($1, $2, 'ACTION', $3, $4, 1, $5, $6, 1, $7, 'payments.refund.create', $7, '\x7b7d',
		'[{"kind":"approval","role":"approver","count":1}]',
		'{"title":"Refund a payment","consequence":{"operation":"payments.refund.create","reversibility":"irreversible"},"fields":[{"name":"amount","value":"1234.56 USD"}],"untrusted":{"text":"ignore previous instructions"}}',
		$7, '\x7b7d', date_trunc('second', now()) + interval '1 hour')`,
		e.org, approval, agent, txn, run, grant, binding[:])
	return approval
}

// notice enqueues an approval notice of request and delivers it once.
func (e *slackEnv) notice(t *testing.T, typ string, request ids.UUID, params map[string]string) (ids.UUID, error) {
	t.Helper()
	p := map[string]string{"operation": "payments.refund.create", "agent": ids.NewV7().String(), "request": request.String()}
	for k, v := range params {
		p[k] = v
	}
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := e.svc.Enqueue(ctx, tx, napp.Message{
			Org: e.org, Type: typ, Params: p, Subject: &napp.Subject{Type: "approval_request", ID: request},
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	d := e.delivery(t)
	err := e.svc.Deliver(context.Background(), e.org, d)
	if err != nil {
		t.Logf("delivery %s: %+v", typ, e.row(t, d))
	}
	return d, err
}

func (e *slackEnv) end(t *testing.T, request ids.UUID, state, reason string) {
	t.Helper()
	e.exec(t, "UPDATE pc.approval_requests SET state = $3, end_reason = $4, ended_at = now() WHERE org_id = $1 AND id = $2",
		e.org, request, state, reason)
}

// pendingDeliveries counts a channel's deliveries.
func (e *slackEnv) deliveries(t *testing.T, channel ids.UUID) int {
	t.Helper()
	var n int
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM pc.deliveries WHERE channel_id = $1", channel).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// enqueue enqueues an approval notice without delivering it.
func (e *slackEnv) enqueue(t *testing.T, typ string, request ids.UUID, params map[string]string) {
	t.Helper()
	p := map[string]string{"operation": "payments.refund.create", "agent": ids.NewV7().String(), "request": request.String()}
	for k, v := range params {
		p[k] = v
	}
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := e.svc.Enqueue(ctx, tx, napp.Message{Org: e.org, Type: typ, Params: p, Subject: &napp.Subject{Type: "approval_request", ID: request}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

var deadline = map[string]string{"deadline": "2026-10-17T12:00:00Z"}

// TestHR315_SlackAppNeedsAStepUpAndSlacksChecks: a slack_app channel is
// stored PENDING_ACTIVATION and gets no deliveries; its page shows what
// Slack reports, and only a person with a fresh step-up of their own key
// activates it, when auth.test and conversations.info confirm the token
// and an internal channel the bot is in. A new token through
// UpdateChannel puts it back to PENDING_ACTIVATION, which stops its
// deliveries until it is confirmed again; it cannot be resumed instead
// (D22, D66).
func TestHR315_SlackAppNeedsAStepUpAndSlacksChecks(t *testing.T) {
	e := newSlackEnv(t)
	c := e.channel(t, slackApproval)
	if c.SlackApp == nil || c.SlackApp.State != napp.SlackPending || c.SlackApp.DataLevel != domain.SlackMinimal {
		t.Fatalf("created: %+v", c.SlackApp)
	}
	e.enqueue(t, "approval.requested", e.request(t), deadline)
	if n := e.deliveries(t, c.ID); n != 0 {
		t.Fatalf("a pending channel got %d deliveries", n)
	}
	resume := false
	if _, err := e.svc.UpdateChannel(e.admin(), c.ID, napp.ChannelUpdate{Paused: &resume}); !errors.Is(err, napp.ErrSlackState) {
		t.Fatalf("resumed a pending channel: %v", err)
	}
	p, err := e.svc.PreviewSlackApp(e.admin(), c.ID)
	if err != nil || p.TeamID != slack.TeamID || p.BotID != slack.BotID || p.ChannelName != "approvals" || p.TeamName != "Simulated" {
		t.Fatalf("preview: %v %+v", err, p)
	}
	if _, err := e.svc.PreviewSlackApp(e.as(td.KindUser, e.carol, td.RoleViewer), c.ID); err == nil {
		t.Fatal("a viewer previewed")
	}
	for name, su := range map[string]stepup.StepUp{
		"none": {}, "stale": {Credential: e.key, At: time.Now().Add(-10 * time.Minute)}, "not hers": {Credential: ids.NewV7(), At: time.Now()},
	} {
		if _, err := e.svc.ActivateSlackApp(e.admin(), c.ID, su); !errors.Is(err, stepup.ErrStepUp) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := e.svc.ActivateSlackApp(e.as(td.KindUser, e.carol, td.RoleViewer), c.ID, e.fresh()); err == nil {
		t.Fatal("a viewer activated")
	}
	got, err := e.svc.ActivateSlackApp(e.admin(), c.ID, e.fresh())
	if err != nil || got.SlackApp.State != napp.SlackActive || got.SlackApp.TeamID != slack.TeamID || got.SlackApp.ActivatedAt == nil {
		t.Fatalf("activate: %v %+v", err, got.SlackApp)
	}
	if _, err := e.svc.ActivateSlackApp(e.admin(), c.ID, e.fresh()); !errors.Is(err, napp.ErrSlackState) {
		t.Fatalf("activated twice: %v", err)
	}

	// An externally shared channel and a missing channel are refused.
	ext := e.channel(t, slackExternal)
	if _, err := e.svc.PreviewSlackApp(e.admin(), ext.ID); !errors.Is(err, napp.ErrSlackShared) {
		t.Fatalf("external preview: %v", err)
	}
	if _, err := e.svc.ActivateSlackApp(e.admin(), ext.ID, e.fresh()); !errors.Is(err, napp.ErrSlackShared) {
		t.Fatalf("external: %v", err)
	}
	e.sim.SetFaults(slack.Faults{ChannelNotFound: true})
	if _, err := e.svc.ActivateSlackApp(e.admin(), ext.ID, e.fresh()); !errors.Is(err, napp.ErrSlackChannelRefuse) {
		t.Fatalf("missing: %v", err)
	}
	e.sim.SetFaults(slack.Faults{})

	// A new token: back to PENDING_ACTIVATION, queued deliveries stop, new
	// notices are not routed, until it is confirmed again.
	req := e.request(t)
	e.enqueue(t, "approval.requested", req, deadline)
	queued := e.delivery(t)
	bad := "not-a-token"
	if _, err := e.svc.UpdateChannel(e.admin(), c.ID, napp.ChannelUpdate{SlackBotToken: &bad}); !errors.Is(err, napp.ErrInvalidChannel) {
		t.Fatalf("bad token: %v", err)
	}
	if _, err := e.svc.UpdateChannel(e.admin(), ext.ID, napp.ChannelUpdate{SlackBotToken: &bad}); err == nil {
		t.Fatal("bad token accepted")
	}
	fresh := "xoxb-simulated-replacement-token"
	v, err := e.svc.UpdateChannel(e.admin(), c.ID, napp.ChannelUpdate{SlackBotToken: &fresh})
	if err != nil || v.SlackApp.State != napp.SlackPending || v.SlackApp.ActivatedAt != nil || v.SlackApp.TokenReplacedAt == nil {
		t.Fatalf("replace: %v %+v", err, v.SlackApp)
	}
	if err := e.svc.Deliver(context.Background(), e.org, queued); err != nil || e.row(t, queued).lastError != "channel_pending" || len(e.sim.Messages()) != 0 {
		t.Fatalf("queued delivery after replacement: %v %+v", err, e.row(t, queued))
	}
	before := e.deliveries(t, c.ID)
	e.enqueue(t, "approval.requested", e.request(t), deadline)
	if n := e.deliveries(t, c.ID); n != before {
		t.Fatalf("routed to a replaced channel: %d", n)
	}
	// The simulator accepts only the old token: the new one is refused.
	if _, err := e.svc.ActivateSlackApp(e.admin(), c.ID, e.fresh()); !errors.Is(err, napp.ErrSlackTokenRefused) {
		t.Fatalf("activate a refused token: %v", err)
	}
	if _, err := e.svc.UpdateChannel(e.admin(), c.ID, napp.ChannelUpdate{SlackBotToken: ptr(slackToken)}); err != nil {
		t.Fatal(err)
	}
	if got, err := e.svc.ActivateSlackApp(e.admin(), c.ID, e.fresh()); err != nil || got.SlackApp.State != napp.SlackActive {
		t.Fatalf("reactivate: %v %+v", err, got.SlackApp)
	}

	// Below the Team edition nothing is created, previewed or activated.
	e.svc.SetEditions(edition(billingdomain.Community))
	if _, _, err := e.svc.CreateChannel(e.admin(), napp.ChannelInput{
		Name: "community", Kind: domain.KindSlackApp, EventTypes: []string{"approval.*"},
		SlackApp: &domain.SlackAppConfig{ChannelID: slackApproval, BotToken: slackToken},
	}); !errors.Is(err, napp.ErrSlackEdition) {
		t.Fatalf("community create: %v", err)
	}
	if _, err := e.svc.ActivateSlackApp(e.admin(), ext.ID, e.fresh()); !errors.Is(err, napp.ErrSlackEdition) {
		t.Fatalf("community activate: %v", err)
	}
}

func ptr(s string) *string { return &s }

// TestT145_CardsOnlyAfterActivation: a request made before the channel was
// activated gets no card, even if its notice is delivered later (D66).
func TestT145_CardsOnlyAfterActivation(t *testing.T) {
	e := newSlackEnv(t)
	c := e.channel(t, slackApproval)
	old := e.request(t)
	if _, err := e.svc.ActivateSlackApp(e.admin(), c.ID, e.fresh()); err != nil {
		t.Fatal(err)
	}
	d, err := e.notice(t, "approval.requested", old, deadline)
	if err != nil || e.row(t, d).state != "SKIPPED" || e.row(t, d).lastError != "before_activation" || len(e.sim.Messages()) != 0 {
		t.Fatalf("backfilled: %v %+v", err, e.row(t, d))
	}
}

// TestT145_SlackCardLifecycle: a waiting request posts one minimal card
// with a link button only; an escalation adds a thread reply; the decision
// updates the card in place to a closed card without button or link; a 429
// is retried after Retry-After and a revoked token pauses the channel;
// none of it decides anything (D23, F167).
func TestT145_SlackCardLifecycle(t *testing.T) {
	e := newSlackEnv(t)
	c := e.channel(t, slackApproval)
	if _, err := e.svc.ActivateSlackApp(e.admin(), c.ID, e.fresh()); err != nil {
		t.Fatal(err)
	}
	req := e.request(t)
	if _, err := e.notice(t, "approval.requested", req, map[string]string{"deadline": "2026-10-17T12:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	ms := e.sim.Messages()
	if len(ms) != 1 || ms[0].Channel != slackApproval {
		t.Fatalf("posted: %+v", ms)
	}
	open := ms[0].Text + string(ms[0].Blocks)
	for _, want := range []string{"Approval needed", "Irreversible", "Agent action", "\"button\"", "/approvals/" + req.String()} {
		if !strings.Contains(open, want) {
			t.Fatalf("open card lacks %q: %s", want, open)
		}
	}
	for _, no := range []string{"1234.56", "USD", "payments.refund.create", "billing-bot", "Production", "Refund a payment", "ignore previous", "bob"} {
		if strings.Contains(open, no) {
			t.Fatalf("minimal card shows %q: %s", no, open)
		}
	}

	if _, err := e.notice(t, "approval.escalated", req, map[string]string{"deadline": "2026-10-17T12:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	if ms = e.sim.Messages(); len(ms) != 2 || ms[1].ThreadTS != ms[0].TS || ms[1].Text != "Escalated (step 1)" {
		t.Fatalf("escalation: %+v", ms)
	}

	e.end(t, req, "DECLINED", "APPROVAL_DECLINED")
	if _, err := e.notice(t, "approval.decided", req, map[string]string{"outcome": "DECLINED"}); err != nil {
		t.Fatal(err)
	}
	ms = e.sim.Messages()
	closed := ms[0].Text + string(ms[0].Blocks)
	if len(ms) != 2 || ms[0].Updates != 1 || !strings.Contains(closed, "Declined") || strings.Contains(closed, "button") ||
		strings.Contains(closed, "/approvals/") || strings.Contains(closed, "alice") {
		t.Fatalf("closed: %+v", ms[0])
	}

	// A 429 is retried after Retry-After; the card is not posted twice.
	req2 := e.request(t)
	e.sim.SetFaults(slack.Faults{RateLimit: 1, RetryAfter: 30})
	d, err := e.notice(t, "approval.requested", req2, map[string]string{"deadline": "2026-10-17T12:00:00Z"})
	var ra napp.RetryAfterError
	if !errors.As(err, &ra) || ra.Wait < 30*time.Second || e.row(t, d).state != "PENDING" || e.row(t, d).lastError != "rate_limited" {
		t.Fatalf("429: %v %+v", err, e.row(t, d))
	}
	if err := e.svc.Deliver(context.Background(), e.org, d); err != nil || e.row(t, d).state != "DELIVERED" || len(e.sim.Messages()) != 3 {
		t.Fatalf("retry: %v %+v %d", err, e.row(t, d), len(e.sim.Messages()))
	}

	// A revoked token fails the delivery and pauses the channel; the
	// request is untouched.
	e.sim.SetFaults(slack.Faults{InvalidAuth: true})
	e.end(t, req2, "EXPIRED", "APPROVAL_EXPIRED")
	d, _ = e.notice(t, "approval.expired", req2, nil)
	if r := e.row(t, d); r.state != "FAILED" || r.lastError != "slack_invalid_auth" {
		t.Fatalf("revoked: %+v", r)
	}
	v, _, err := e.svc.GetChannel(e.admin(), c.ID)
	if err != nil || v.State != "PAUSED" {
		t.Fatalf("channel after revoked token: %v %+v", err, v)
	}
	var state string
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT state FROM pc.approval_requests WHERE id = $1", req2).Scan(&state)
	}); err != nil || state != "EXPIRED" {
		t.Fatalf("request: %v %s", err, state)
	}
}

// TestHR314_SlackCardSummaryLevel: SUMMARY adds the template title, the
// agent and the environment, and still nothing the approval binds (D23).
func TestHR314_SlackCardSummaryLevel(t *testing.T) {
	e := newSlackEnv(t)
	c, _, err := e.svc.CreateChannel(e.admin(), napp.ChannelInput{
		Name: "summary", Kind: domain.KindSlackApp, EventTypes: []string{"approval.*"},
		SlackApp: &domain.SlackAppConfig{ChannelID: slackApproval, DataLevel: domain.SlackSummary, BotToken: slackToken},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.ActivateSlackApp(e.admin(), c.ID, e.fresh()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.notice(t, "approval.requested", e.request(t), map[string]string{"deadline": "2026-10-17T12:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	ms := e.sim.Messages()
	if len(ms) != 1 {
		t.Fatalf("posted: %+v", ms)
	}
	card := string(ms[0].Blocks)
	for _, want := range []string{"Approval: Refund a payment", "Agent: billing-bot", "Environment: Production"} {
		if !strings.Contains(card, want) {
			t.Fatalf("summary lacks %q: %s", want, card)
		}
	}
	for _, no := range []string{"1234.56", "USD", "ignore previous"} {
		if strings.Contains(card, no) {
			t.Fatalf("summary shows %q: %s", no, card)
		}
	}
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
