// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	notifapp "github.com/katocxl/pantherclaw/internal/notifications/app"
	notifdomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/waitlist/adapters/pgwaitlist"
	waitlist "github.com/katocxl/pantherclaw/internal/waitlist/app"
	wdomain "github.com/katocxl/pantherclaw/internal/waitlist/domain"
)

// fakeNotifier renders each message from its template, as the real
// service does, and records it.
type fakeNotifier struct {
	mu   sync.Mutex
	sent []notifapp.Message
	link []string
	// failed are the subjects whose notices failed to deliver.
	failed []ids.UUID
}

func (n *fakeNotifier) FailedSubjects(_ context.Context, _ db.TenantTx, _ ids.OrgID, _ string, subjects []ids.UUID) ([]ids.UUID, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []ids.UUID
	for _, s := range subjects {
		if slices.Contains(n.failed, s) {
			out = append(out, s)
		}
	}
	return out, nil
}

func (n *fakeNotifier) Enqueue(_ context.Context, _ db.TenantTx, m notifapp.Message) (notifapp.Enqueued, error) {
	r, err := notifdomain.Render(m.Type, m.Params)
	if err != nil {
		return notifapp.Enqueued{}, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sent, n.link = append(n.sent, m), append(n.link, r.Link)
	return notifapp.Enqueued{Notification: ids.NewV7()}, nil
}

// rfx adds a team in a business unit to the waitlist fixture, moves the
// agent there, and binds people at different scopes.
type rfx struct {
	*wfx
	team, bu, env ids.UUID
	n             *fakeNotifier
	router        *waitlist.Router
}

func newRFx(t *testing.T) *rfx {
	t.Helper()
	f := &rfx{wfx: newWFx(t), team: ids.NewV7(), bu: ids.NewV7(), n: &fakeNotifier{}}
	f.exec("INSERT INTO pc.business_units (org_id, id, slug, name) VALUES ($1, $2, 'payments', 'Payments')", f.org, f.bu)
	f.exec("INSERT INTO pc.teams (org_id, id, business_unit_id, slug, name) VALUES ($1, $2, $3, 'refunds', 'Refunds')", f.org, f.team, f.bu)
	f.d.AdminExec(t, `UPDATE pc.agents SET state = 'CLAIMED', team_id = $1, owner_user_id = $3, execution_context = 'service', claimed_at = now(),
		environment_id = (SELECT r.environment_id FROM pc.runs r WHERE r.org_id = $2 AND r.agent_id = pc.agents.id LIMIT 1)
		WHERE org_id = $2`, f.team, f.org, f.ann)
	f.router = &waitlist.Router{Pool: f.p, Notify: f.n}
	return f
}

// person adds an enabled user bound to role at scope ("ORG", "BUSINESS_UNIT"
// or "TEAM"), a month ago, with a month-old key.
func (f *rfx) person(role, scope string) ids.UUID {
	f.t.Helper()
	u := ids.NewV7()
	f.exec(`INSERT INTO pc.users (org_id, id, issuer, subject, created_at) VALUES ($1, $2, 'https://idp.test', $3, now() - interval '30 days')`,
		f.org, u, u.String())
	f.exec(`INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible, backup_state,
		attestation_fmt, name, created_at) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key', now() - interval '30 days')`,
		f.org, ids.NewV7(), u, u[:], append(append([]byte{}, u[:]...), u[:]...))
	f.bind(u, role, scope)
	return u
}

func (f *rfx) bind(u ids.UUID, role, scope string) {
	f.t.Helper()
	var bu, team any
	switch scope {
	case "BUSINESS_UNIT":
		bu = f.bu
	case "TEAM":
		team = f.team
	}
	f.exec(`INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, business_unit_id, team_id, created_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'test', now() - interval '30 days')`, f.org, ids.NewV7(), role, u, scope, bu, team)
}

// hold opens an ACTION_HOLD entry for a request needing one approver.
func (f *rfx) hold() (entry, request ids.UUID) {
	f.t.Helper()
	request, entry = ids.NewV7(), ids.NewV7()
	f.exec(`INSERT INTO pc.approval_requests (org_id, id, subject_kind, agent_id, transaction_id, evaluation, run_id, grant_id,
		grant_revision, variant_key, operation, binding, binding_input, requirements, display, display_hash, action_ir, deadline_at)
		SELECT $1, $2, 'ACTION', r.agent_id, $3, 1, r.id, $4, 1, $5, 'payments.refund.create', $5, '\x7b7d',
		'[{"kind":"approval","role":"approver","count":1,"sources":[]}]', '{}', $5, '\x7b7d', date_trunc('second', now()) + interval '1 hour'
		FROM pc.runs r WHERE r.id = $6`, f.org, request, f.txn, f.grant, append(append([]byte{}, request[:]...), request[:]...), f.run)
	f.exec(`INSERT INTO pc.waitlist_entries (org_id, id, kind, subject_type, subject_id, agent_id, run_id, transaction_id, deadline_at)
		SELECT $1, $2, 'ACTION_HOLD', 'approval_request', $3, agent_id, run_id, transaction_id, deadline_at
		FROM pc.approval_requests WHERE id = $3`, f.org, entry, request)
	return entry, request
}

func (f *rfx) route() int {
	f.t.Helper()
	n, err := f.router.RouteOrg(context.Background(), f.org)
	if err != nil {
		f.t.Fatal(err)
	}
	return n
}

// routes lists an entry's recorded recipients as "kind:user".
func (f *rfx) routes(entry ids.UUID) []string {
	f.t.Helper()
	var out []string
	f.tx(func(ctx context.Context, tx db.TenantTx) error {
		rows, err := tx.Query(ctx, "SELECT kind || ':' || user_id FROM pc.waitlist_routes WHERE entry_id = $1 ORDER BY 1", entry)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return err
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	return out
}

// TestHR173_RoutingReachesOnlyTheNearestEligibleDeciders (decision 8,
// T-061): a hold is routed to the approvers bound nearest the agent (the
// team), never to the run's launcher even when she holds the role, with a
// notice that links to the approval page; it is routed once, and the next
// step is due at half its time.
func TestHR173_RoutingReachesOnlyTheNearestEligibleDeciders(t *testing.T) {
	f := newRFx(t)
	near := f.person("approver", "TEAM")
	f.person("approver", "ORG")
	f.bind(f.ann, "approver", "TEAM") // the launcher
	entry, request := f.hold()
	if n := f.route(); n != 1 {
		t.Fatalf("routed %d entries", n)
	}
	if got := f.routes(entry); !slices.Equal(got, []string{"decider:" + near.String()}) {
		t.Fatalf("routes %v", got)
	}
	if len(f.n.sent) != 1 || f.n.sent[0].Type != "approval.requested" || !slices.Equal(f.n.sent[0].Personal, []ids.UUID{near}) ||
		f.n.link[0] != "/approvals/"+request.String() || f.n.sent[0].Params["operation"] != "payments.refund.create" {
		t.Fatalf("notice %+v %v", f.n.sent, f.n.link)
	}
	var health string
	var half bool
	f.d.AdminQueryRow(t, `SELECT routing_health, abs(extract(epoch FROM next_step_at - (created_at + (deadline_at - created_at) / 2))) < 0.001 AND escalation_step = 1
		FROM pc.waitlist_entries WHERE id = $1`,
		[]any{entry}, &health, &half)
	if health != "OK" || !half {
		t.Fatalf("health %s, next step at half %v", health, half)
	}
	if n := f.route(); n != 0 || len(f.n.sent) != 1 {
		t.Fatalf("routed again: %d", n)
	}
}

// TestHR173_NoEligibleDeciderTellsTheAdmins (F635): a hold no one may decide
// is marked NO_ELIGIBLE_DECIDER and the org's admins are told; nobody is
// made eligible.
func TestHR173_NoEligibleDeciderTellsTheAdmins(t *testing.T) {
	f := newRFx(t)
	admin := f.person("org_admin", "ORG")
	f.bind(f.ann, "approver", "TEAM") // only the launcher holds the role
	entry, _ := f.hold()
	f.route()
	var health string
	f.d.AdminQueryRow(t, "SELECT routing_health FROM pc.waitlist_entries WHERE id = $1", []any{entry}, &health)
	if health != "NO_ELIGIBLE_DECIDER" {
		t.Fatalf("health %s", health)
	}
	if len(f.n.sent) != 1 || f.n.sent[0].Type != "approval.unroutable" || !slices.Equal(f.n.sent[0].Personal, []ids.UUID{admin}) {
		t.Fatalf("notice %+v", f.n.sent)
	}
	if got := f.routes(entry); !slices.Equal(got, []string{"admin:" + admin.String()}) {
		t.Fatalf("routes %v", got)
	}
}

// TestHR173_OtherKindsReachTheirPermissionHolders: an unknown outcome is
// routed to the holders of incident.respond, nearest first, with a waitlist
// notice that names no amount or text.
func TestHR173_OtherKindsReachTheirPermissionHolders(t *testing.T) {
	f := newRFx(t)
	bu := f.person("responder", "BUSINESS_UNIT")
	f.person("security_admin", "ORG")
	var entry ids.UUID
	f.tx(func(ctx context.Context, tx db.TenantTx) error {
		var err error
		entry, err = pgwaitlist.OpenReconciliation(ctx, tx, f.org, f.txn, pgwaitlist.System)
		return err
	})
	f.route()
	if got := f.routes(entry); !slices.Equal(got, []string{"decider:" + bu.String()}) {
		t.Fatalf("routes %v", got)
	}
	if len(f.n.sent) != 1 || f.n.sent[0].Type != "waitlist.entry_created" || f.n.sent[0].Params["kind"] != "RECONCILIATION" {
		t.Fatalf("notice %+v", f.n.sent)
	}
}

// due makes an entry's next escalation step due now.
func (f *rfx) due(entry ids.UUID) {
	f.d.AdminExec(f.t, "UPDATE pc.waitlist_entries SET next_step_at = now() - interval '1 second' WHERE id = $1", entry)
}

// sentTo returns the notice types sent to u, in order.
func (f *rfx) sentTo(u ids.UUID) []string {
	var out []string
	for _, m := range f.n.sent {
		if slices.Contains(m.Personal, u) {
			out = append(out, m.Type)
		}
	}
	return out
}

// TestHR173_EscalationWidensRemindsAndTellsTheOwners (decision 8): at half
// the time the business unit's deciders are added and the first ones
// reminded; at three quarters the org's deciders are added and the agent's
// owner (the launcher, who gets no vote) is told; then nothing more.
func TestHR173_EscalationWidensRemindsAndTellsTheOwners(t *testing.T) {
	f := newRFx(t)
	near, bu, org := f.person("approver", "TEAM"), f.person("approver", "BUSINESS_UNIT"), f.person("approver", "ORG")
	entry, _ := f.hold()
	f.route()
	f.due(entry)
	f.route()
	f.due(entry)
	f.route()
	for u, want := range map[ids.UUID][]string{
		near:  {"approval.requested", "approval.reminder"},
		bu:    {"approval.escalated"},
		org:   {"approval.escalated"},
		f.ann: {"approval.escalated"},
	} {
		if got := f.sentTo(u); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", u, got, want)
		}
	}
	if got := f.routes(entry); !slices.Contains(got, "owner:"+f.ann.String()) || !slices.Contains(got, "decider:"+org.String()) {
		t.Fatalf("routes %v", got)
	}
	var step int
	var next *string
	f.d.AdminQueryRow(t, "SELECT escalation_step, next_step_at::text FROM pc.waitlist_entries WHERE id = $1", []any{entry}, &step, &next)
	if step != 3 || next != nil {
		t.Fatalf("after the last step: %d %v", step, next)
	}
	sent := len(f.n.sent)
	if f.route(); len(f.n.sent) != sent {
		t.Fatal("a finished chain sent more")
	}
}

// TestHR173_AChainIsReplacedOnlyByAnAdmin: setting a chain needs
// waitlist.manage, a valid chain and the current revision; a team without
// its own chain uses the org's; routing follows the team's chain.
func TestHR173_AChainIsReplacedOnlyByAnAdmin(t *testing.T) {
	f := newRFx(t)
	everyone := []wdomain.Step{{AtPercent: 0, Scope: wdomain.ScopeOrg, NotifyChannels: true}}
	if _, err := f.w.SetEscalationChain(f.as(f.ben, td.RoleApprover), nil, everyone, 0); err == nil {
		t.Fatal("an approver set the chain")
	}
	admin := f.as(f.ben, td.RoleOrgAdmin)
	if _, err := f.w.SetEscalationChain(admin, nil, []wdomain.Step{{AtPercent: 10, Scope: wdomain.ScopeOrg}}, 0); !errors.Is(err, waitlist.ErrChainInvalid) {
		t.Fatalf("an invalid chain: %v", err)
	}
	c, err := f.w.SetEscalationChain(admin, nil, wdomain.DefaultChain, 0)
	if err != nil || c.Revision != 1 || c.CreatedBy != "user:"+f.ben.String() {
		t.Fatalf("org chain: %+v, %v", c, err)
	}
	if _, err := f.w.SetEscalationChain(admin, nil, wdomain.DefaultChain, 0); !errors.Is(err, waitlist.ErrChainChanged) {
		t.Fatalf("a stale revision: %v", err)
	}
	rd := waitlist.NewReader(f.p)
	if got, err := rd.GetEscalationChain(f.as(f.ben, td.RoleApprover), &f.team); err != nil || got.Revision != 1 || !got.Team.IsZero() {
		t.Fatalf("a team without its own chain: %+v, %v", got, err)
	}
	if _, err := f.w.SetEscalationChain(admin, &f.team, everyone, 0); err != nil {
		t.Fatal(err)
	}
	near, org := f.person("approver", "TEAM"), f.person("approver", "ORG")
	entry, _ := f.hold()
	f.route()
	if !slices.Equal(f.sentTo(near), []string{"approval.requested"}) || !slices.Equal(f.sentTo(org), []string{"approval.requested"}) {
		t.Fatalf("the team's one-step chain: %v %v", f.sentTo(near), f.sentTo(org))
	}
	var step int
	var next *string
	f.d.AdminQueryRow(t, "SELECT escalation_step, next_step_at::text FROM pc.waitlist_entries WHERE id = $1", []any{entry}, &step, &next)
	if step != 1 || next != nil {
		t.Fatalf("after its only step: %d %v", step, next)
	}
	if n := f.route(); n != 0 {
		t.Fatalf("routed again: %d", n)
	}
}

// TestHR039_AFailedDeliveryMarksTheEntryAndDecidesNothing: an entry whose
// notice failed is DELIVERY_FAILING and still open.
func TestHR039_AFailedDeliveryMarksTheEntryAndDecidesNothing(t *testing.T) {
	f := newRFx(t)
	f.person("approver", "TEAM")
	entry, _ := f.hold()
	f.route()
	f.n.failed = []ids.UUID{entry}
	f.route()
	var health, state string
	f.d.AdminQueryRow(t, "SELECT routing_health, state FROM pc.waitlist_entries WHERE id = $1", []any{entry}, &health, &state)
	if health != "DELIVERY_FAILING" || state != "OPEN" {
		t.Fatalf("%s %s", health, state)
	}
}

// variant opens a hold of a new transaction of the run with variant key k.
func (f *rfx) variant(k []byte) ids.UUID {
	f.t.Helper()
	txn, request, entry := ids.NewV7(), ids.NewV7(), ids.NewV7()
	f.exec(`INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id, state)
		VALUES ($1, $2, $3, $4, $5, 'payments.refund.create', 'REQUIRE_APPROVAL', 'R', 'gw', 'OPEN')`, f.org, txn, f.run, ids.NewV7(), make([]byte, 32))
	binding := append(append([]byte{}, request[:]...), request[:]...)
	f.exec(`INSERT INTO pc.approval_requests (org_id, id, subject_kind, agent_id, transaction_id, evaluation, run_id, grant_id,
		grant_revision, variant_key, operation, binding, binding_input, requirements, display, display_hash, action_ir, deadline_at)
		SELECT $1, $2, 'ACTION', r.agent_id, $3, 1, r.id, $4, 1, $5, 'payments.refund.create', $6, '\x7b7d',
		'[{"kind":"approval","role":"approver","count":1,"sources":[]}]', '{}', $6, '\x7b7d', date_trunc('second', now()) + interval '1 hour'
		FROM pc.runs r WHERE r.id = $7`, f.org, request, txn, f.grant, k, binding, f.run)
	f.exec(`INSERT INTO pc.waitlist_entries (org_id, id, kind, subject_type, subject_id, agent_id, run_id, transaction_id, deadline_at)
		SELECT $1, $2, 'ACTION_HOLD', 'approval_request', $3, agent_id, run_id, transaction_id, deadline_at
		FROM pc.approval_requests WHERE id = $3`, f.org, entry, request)
	return request
}

// TestHR037_TheThirdVariantTellsTheSecurityAdmins (decision 7): routing the
// third hold of one grant, operation and target within 24 hours tells the
// Security Admins, once per request.
func TestHR037_TheThirdVariantTellsTheSecurityAdmins(t *testing.T) {
	f := newRFx(t)
	sec := f.person("security_admin", "ORG")
	f.person("approver", "TEAM")
	k := make([]byte, 32)
	k[0] = 7
	f.variant(k)
	f.variant(k)
	f.route()
	if len(f.sentTo(sec)) != 0 {
		t.Fatalf("two variants: %v", f.sentTo(sec))
	}
	third := f.variant(k)
	f.route()
	got := f.sentTo(sec)
	if !slices.Equal(got, []string{"security.variant_suspected"}) {
		t.Fatalf("the third variant: %v", got)
	}
	for _, m := range f.n.sent {
		if m.Type == "security.variant_suspected" && (m.Params["count"] != "3" || m.Params["request"] != third.String()) {
			t.Fatalf("notice %+v", m)
		}
	}
}
