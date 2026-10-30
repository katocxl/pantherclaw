// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/sim/slack"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const (
	daveSlack = "U0DAVE00001"
	erinSlack = "U0ERIN00001"
)

// dmEnv is a slackEnv with an active slack_app channel that sends DMs, and
// dave (an approver) and erin (a viewer, no decider) known to Slack by
// their confirmed emails.
type dmEnv struct {
	*slackEnv
	channel napp.ChannelView
	erin    ids.UUID
}

func newDMEnv(t *testing.T) *dmEnv {
	t.Helper()
	s := newSlackEnv(t, slackToken)
	c, _, err := s.svc.CreateChannel(s.admin(), napp.ChannelInput{
		Name: "approvals-dm", Kind: domain.KindSlackApp, EventTypes: []string{"channel.test"},
		SlackApp: &domain.SlackAppConfig{
			ChannelID: slackApproval, BotToken: slackToken, DirectMessages: true, AllowedEmailDomains: []string{"example.test"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	e := &dmEnv{slackEnv: s, channel: s.activate(t, c), erin: ids.NewV7()}
	if !e.channel.SlackApp.DirectMessages {
		t.Fatal("the channel does not send DMs")
	}
	s.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject, email) VALUES ($1, $2, 'https://idp.test', 'erin', 'erin@example.test')", s.org, e.erin)
	s.exec(t, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, 'viewer', $3, 'ORG', 'test')`,
		s.org, ids.NewV7(), e.erin)
	s.exec(t, "UPDATE pc.users SET email = 'dave@example.test' WHERE org_id = $1 AND id = $2", s.org, s.dave.id)
	s.d.AdminExec(t, `INSERT INTO pc.accounts (id, issuer, subject, email, email_verified, display_name)
		SELECT gen_random_uuid(), issuer, subject, email, true, 'person' FROM pc.users WHERE org_id = $1 AND id = ANY ($2)`,
		s.org, []ids.UUID{s.dave.id, e.erin})
	s.d.AdminExec(t, `UPDATE pc.users u SET account_id = a.id FROM pc.accounts a
		WHERE u.org_id = $1 AND a.issuer = u.issuer AND a.subject = u.subject`, s.org)
	s.sim.SetUser(slack.User{ID: daveSlack, Email: "dave@example.test", EmailConfirmed: true})
	s.sim.SetUser(slack.User{ID: erinSlack, Email: "erin@example.test", EmailConfirmed: true})
	return e
}

// person is a signed-in person with role at the org.
func (e *dmEnv) person(user ids.UUID, role td.RoleName) context.Context {
	return e.as(td.KindUser, user, role)
}

// link proposes and confirms user's Slack link.
func (e *dmEnv) link(t *testing.T, user ids.UUID, role td.RoleName) napp.ChatLink {
	t.Helper()
	ctx := e.person(user, role)
	l, err := e.svc.ProposeSlackLink(ctx)
	if err != nil || l.State != napp.LinkProposed {
		t.Fatalf("propose: %+v %v", l, err)
	}
	if l, err = e.svc.ConfirmChatLink(ctx, l.ID); err != nil || l.State != napp.LinkConfirmed {
		t.Fatalf("confirm: %+v %v", l, err)
	}
	return l
}

func (e *dmEnv) dmDeliveries(t *testing.T, user ids.UUID) []ids.UUID {
	t.Helper()
	var out []ids.UUID
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := tx.Query(ctx, "SELECT id FROM pc.deliveries WHERE kind = 'slack_dm' AND recipient_user_id = $1 ORDER BY created_at, id", user)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id ids.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out = append(out, id)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func (e *dmEnv) dms(user string) []slack.Message {
	var out []slack.Message
	for _, m := range e.sim.Messages() {
		if m.Channel == slack.DMChannel(user) {
			out = append(out, m)
		}
	}
	return out
}

// TestHR529_ApprovalDMsGoToLinkedDecidersOnly: a decider gets an approval
// DM only once they confirmed their Slack link; the DM is the minimal card
// with the approval link, shows no bound values and has no element but the
// link button; it is posted once per request (HR-529, HR-313, HR-314).
//
// Covers: F161, PN-017.3
func TestHR529_ApprovalDMsGoToLinkedDecidersOnly(t *testing.T) {
	e := newDMEnv(t)
	ctx := e.person(e.dave.id, td.RoleApprover)
	proposed, err := e.svc.ProposeSlackLink(ctx)
	if err != nil {
		t.Fatal(err)
	}
	unlinked := e.hold(t, 3600e9)
	if n := len(e.dmDeliveries(t, e.dave.id)); n != 0 {
		t.Fatalf("an unconfirmed link got %d DM deliveries", n)
	}
	// Only the person themself confirms their link.
	if _, err := e.svc.ConfirmChatLink(e.person(e.erin, td.RoleViewer), proposed.ID); !errors.Is(err, napp.ErrSlackLinkNotFound) {
		t.Fatalf("another person confirmed the link: %v", err)
	}
	if _, err := e.svc.ConfirmChatLink(ctx, proposed.ID); err != nil {
		t.Fatal(err)
	}
	request := e.hold(t, 3600e9)
	ds := e.dmDeliveries(t, e.dave.id)
	if len(ds) != 1 {
		t.Fatalf("%d DM deliveries for the linked decider", len(ds))
	}
	for range 2 { // a second attempt never posts again
		if err := e.svc.Deliver(context.Background(), e.org, ds[0]); err != nil {
			t.Fatalf("deliver: %v", err)
		}
	}
	msgs := e.dms(daveSlack)
	if len(msgs) != 1 {
		t.Fatalf("%d DMs to dave: %+v", len(msgs), e.sim.Messages())
	}
	m := msgs[0]
	if !strings.Contains(string(m.Blocks), "/approvals/"+request.String()) || !strings.Contains(m.Text, request.String()[28:]) {
		t.Fatalf("the DM does not link the request: %s %s", m.Text, m.Blocks)
	}
	if strings.Contains(string(m.Blocks), unlinked.String()) {
		t.Fatal("the DM names a request routed before the link was confirmed")
	}
	noBoundValues(t, "the DM", m.Text+string(m.Blocks))
	if strings.Contains(string(m.Blocks), "action_id") && !strings.Contains(string(m.Blocks), `"url"`) {
		t.Fatalf("the DM has an interactive element: %s", m.Blocks)
	}
	if got := e.str(t, "SELECT state FROM pc.slack_direct_messages WHERE request_id = $1 AND user_id = $2", request, e.dave.id); got != "POSTED" {
		t.Fatalf("DM state %s", got)
	}
	// A revoked link gets no more DMs.
	links, err := e.svc.ChatLinks(ctx)
	if err != nil || len(links) != 1 {
		t.Fatalf("links: %+v %v", links, err)
	}
	if _, err := e.svc.RevokeChatLink(ctx, links[0].ID); err != nil {
		t.Fatal(err)
	}
	e.hold(t, 3600e9)
	if n := len(e.dmDeliveries(t, e.dave.id)); n != 1 {
		t.Fatalf("a revoked link got %d DM deliveries", n)
	}
}

// TestT228_NoDMToANonDecider: a person who is not an eligible decider of
// the request gets no DM, even with a confirmed link and a DM delivery
// forced onto the queue (a notice wrongly marked for deciders, or a
// delivery row written by hand): the sender reads the router's deciders
// again and sends nothing (HR-529, T-228).
//
// Covers: F161, PN-017.3
func TestT228_NoDMToANonDecider(t *testing.T) {
	e := newDMEnv(t)
	e.link(t, e.erin, td.RoleViewer)
	request := e.hold(t, 3600e9)
	if n := len(e.dmDeliveries(t, e.erin)); n != 0 {
		t.Fatalf("the router queued %d DMs for a non-decider", n)
	}
	// A notice marked for deciders that names erin anyway.
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := e.svc.Enqueue(ctx, tx, napp.Message{
			Org: e.org, Type: "approval.requested", Personal: []ids.UUID{e.erin}, Deciders: true, PersonalOnly: true,
			Params:  map[string]string{"operation": "payments.refund.create", "agent": e.agent.String(), "deadline": "soon", "request": request.String()},
			Subject: &napp.Subject{Type: "approval_request", ID: request},
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	ds := e.dmDeliveries(t, e.erin)
	if len(ds) != 1 {
		t.Fatalf("%d forced DM deliveries", len(ds))
	}
	if err := e.svc.Deliver(context.Background(), e.org, ds[0]); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if n := len(e.dms(erinSlack)); n != 0 {
		t.Fatalf("a non-decider got %d DMs", n)
	}
	var d dbq.PcDelivery
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT state, last_error FROM pc.deliveries WHERE id = $1", ds[0]).Scan(&d.State, &d.LastError)
	}); err != nil {
		t.Fatal(err)
	}
	if d.State != "SKIPPED" || d.LastError == nil || *d.LastError != "not_a_decider" {
		t.Fatalf("the forced DM ended %s %v", d.State, d.LastError)
	}
}

// TestHR529_SlackLinkNeedsAFullMemberWithTheSameEmail: Slack must report a
// full, confirmed member of the DM channel's workspace with the person's
// own email; a guest, a bot, an unconfirmed email or another workspace is
// refused, and without a DM channel there is no link.
//
// Covers: F161
func TestHR529_SlackLinkNeedsAFullMemberWithTheSameEmail(t *testing.T) {
	e := newDMEnv(t)
	ctx := e.person(e.erin, td.RoleViewer)
	for name, u := range map[string]slack.User{
		"a guest":              {ID: erinSlack, Email: "erin@example.test", EmailConfirmed: true, Restricted: true},
		"another email":        {ID: erinSlack, Email: "erin.other@example.test", EmailConfirmed: true},
		"a bot":                {ID: erinSlack, Email: "erin@example.test", EmailConfirmed: true, Bot: true},
		"an unconfirmed email": {ID: erinSlack, Email: "erin@example.test"},
		"another workspace":    {ID: erinSlack, Email: "erin@example.test", EmailConfirmed: true, Team: "T0OTHER0001"},
		"a deleted user":       {ID: erinSlack, Email: "erin@example.test", EmailConfirmed: true, Deleted: true},
	} {
		e.sim.SetUser(u)
		if _, err := e.svc.ProposeSlackLink(ctx); !errors.Is(err, napp.ErrSlackLinkRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// An API key is not the person.
	if _, err := e.svc.ChatLinks(e.as(td.KindServiceAccount, ids.NewV7(), td.RoleViewer)); !errors.Is(err, napp.ErrLinkHumanOnly) {
		t.Fatalf("a service account: %v", err)
	}
}

// TestHR529_SlackLinkNeedsAnAllowedDomain: a person whose email is not on
// one of the DM channel's domains gets no link, whatever Slack says; a DM
// channel needs 1 to 20 lowercase exact domains and other channels none
// (D265).
//
// Covers: F161
func TestHR529_SlackLinkNeedsAnAllowedDomain(t *testing.T) {
	e := newDMEnv(t)
	e.exec(t, "UPDATE pc.users SET email = 'erin@elsewhere.test' WHERE org_id = $1 AND id = $2", e.org, e.erin)
	e.d.AdminExec(t, "UPDATE pc.accounts SET email = 'erin@elsewhere.test' WHERE email = 'erin@example.test'")
	e.sim.SetUser(slack.User{ID: erinSlack, Email: "erin@elsewhere.test", EmailConfirmed: true})
	if _, err := e.svc.ProposeSlackLink(e.person(e.erin, td.RoleViewer)); !errors.Is(err, napp.ErrSlackLinkRefused) {
		t.Fatalf("another domain: %v", err)
	}
	for name, domains := range map[string][]string{
		"none":     nil,
		"wildcard": {"*.example.test"},
		"upper":    {"Example.test"},
		"too many": {
			"a.test", "b.test", "c.test", "d.test", "e.test", "f.test", "g.test", "h.test", "i.test", "j.test", "k.test",
			"l.test", "m.test", "n.test", "o.test", "p.test", "q.test", "r.test", "s.test", "t.test", "u.test",
		},
	} {
		if _, _, err := e.svc.CreateChannel(e.admin(), napp.ChannelInput{
			Name: "dm-" + strings.ReplaceAll(name, " ", "-"), Kind: domain.KindSlackApp, EventTypes: []string{"channel.test"},
			SlackApp: &domain.SlackAppConfig{ChannelID: "C0OTHER0001", BotToken: slackToken, DirectMessages: true, AllowedEmailDomains: domains},
		}); err == nil {
			t.Errorf("a DM channel with %s domains was created", name)
		}
	}
	if _, _, err := e.svc.CreateChannel(e.admin(), napp.ChannelInput{
		Name: "cards", Kind: domain.KindSlackApp, EventTypes: []string{"channel.test"},
		SlackApp: &domain.SlackAppConfig{ChannelID: "C0OTHER0001", BotToken: slackToken, AllowedEmailDomains: []string{"example.test"}},
	}); err == nil {
		t.Error("a card channel with email domains was created")
	}
}

// TestHR529_AChangedSlackMemberMakesTheLinkStale: before each DM Slack is
// asked again; when the email now belongs to another Slack user (a reused
// address) or the member's email changed, no DM goes, the link is STALE
// and audited, and later requests send none (D265).
//
// Covers: F161, PN-017.3
func TestHR529_AChangedSlackMemberMakesTheLinkStale(t *testing.T) {
	for name, change := range map[string]func(*dmEnv){
		"a reused address": func(e *dmEnv) {
			e.sim.SetUser(slack.User{ID: daveSlack, Email: "dave.old@example.test", EmailConfirmed: true})
			e.sim.SetUser(slack.User{ID: "U0MALLORY01", Email: "dave@example.test", EmailConfirmed: true})
		},
		"a changed email": func(e *dmEnv) {
			e.sim.SetUser(slack.User{ID: daveSlack, Email: "dave.new@example.test", EmailConfirmed: true})
		},
		"a guest now": func(e *dmEnv) {
			e.sim.SetUser(slack.User{ID: daveSlack, Email: "dave@example.test", EmailConfirmed: true, Restricted: true})
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newDMEnv(t)
			l := e.link(t, e.dave.id, td.RoleApprover)
			e.hold(t, 3600e9)
			change(e)
			ds := e.dmDeliveries(t, e.dave.id)
			if len(ds) != 1 {
				t.Fatalf("%d DM deliveries", len(ds))
			}
			if err := e.svc.Deliver(context.Background(), e.org, ds[0]); err != nil {
				t.Fatal(err)
			}
			if n := len(e.sim.Messages()); n != 0 {
				t.Fatalf("%d messages posted: %+v", n, e.sim.Messages())
			}
			if got := e.str(t, "SELECT state FROM pc.chat_identity_links WHERE id = $1", l.ID); got != napp.LinkStale {
				t.Fatalf("link state %s", got)
			}
			if got := e.str(t, "SELECT count(*)::text FROM pc.ledger_entries WHERE kind = 'audit.notification.chat_link_stale'"); got != "1" {
				t.Fatalf("%s stale audits", got)
			}
			e.hold(t, 3600e9)
			if n := len(e.dmDeliveries(t, e.dave.id)); n != 1 {
				t.Fatalf("a stale link got %d DM deliveries", n)
			}
		})
	}
}

// TestT228_AnUnverifiedEmailGetsNoLink: Slack's own flag is not PantherClaw's:
// a link needs an account holding the email as verified (D265). pc.users.email
// is what the last sign-in claimed, so someone whose provider passes an
// unverified colleague's address, or who has no account, gets no link.
//
// Covers: F161
func TestT228_AnUnverifiedEmailGetsNoLink(t *testing.T) {
	e := newDMEnv(t)
	e.d.AdminExec(t, "UPDATE pc.accounts SET email_verified = false WHERE email = 'erin@example.test'")
	if _, err := e.svc.ProposeSlackLink(e.person(e.erin, td.RoleViewer)); !errors.Is(err, napp.ErrChatEmailUnverified) {
		t.Fatalf("an unverified email: %v", err)
	}
	frank := ids.NewV7()
	e.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject, email) VALUES ($1, $2, 'https://idp.test', 'frank', 'erin@example.test')", e.org, frank)
	if _, err := e.svc.ProposeSlackLink(e.person(frank, td.RoleViewer)); !errors.Is(err, napp.ErrChatEmailUnverified) {
		t.Fatalf("no account: %v", err)
	}
	if got := e.str(t, "SELECT count(*)::text FROM pc.chat_identity_links"); got != "0" {
		t.Fatalf("%s links", got)
	}
}

// TestT228_AnEmailNoLongerVerifiedStopsTheDM: the email is checked again at
// each DM. Once the account no longer holds it as verified, or a sign-in
// wrote another address, the link is stale and no DM goes (D265).
//
// Covers: F161
func TestT228_AnEmailNoLongerVerifiedStopsTheDM(t *testing.T) {
	for name, change := range map[string]func(*dmEnv){
		"no longer verified": func(e *dmEnv) {
			e.d.AdminExec(t, "UPDATE pc.accounts SET email_verified = false WHERE email = 'dave@example.test'")
		},
		"another address at sign-in": func(e *dmEnv) {
			e.exec(t, "UPDATE pc.users SET email = 'dave.new@example.test' WHERE org_id = $1 AND id = $2", e.org, e.dave.id)
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newDMEnv(t)
			l := e.link(t, e.dave.id, td.RoleApprover)
			e.hold(t, 3600e9)
			change(e)
			ds := e.dmDeliveries(t, e.dave.id)
			if len(ds) != 1 {
				t.Fatalf("%d DM deliveries", len(ds))
			}
			if err := e.svc.Deliver(context.Background(), e.org, ds[0]); err != nil {
				t.Fatal(err)
			}
			if n := len(e.sim.Messages()); n != 0 {
				t.Fatalf("%d messages posted: %+v", n, e.sim.Messages())
			}
			if got := e.str(t, "SELECT state FROM pc.chat_identity_links WHERE id = $1", l.ID); got != napp.LinkStale {
				t.Fatalf("link state %s", got)
			}
			if got := e.str(t, "SELECT count(*)::text FROM pc.ledger_entries WHERE kind = 'audit.notification.chat_link_stale'"); got != "1" {
				t.Fatalf("%s stale audits", got)
			}
		})
	}
}
