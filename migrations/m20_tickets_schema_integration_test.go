// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// These tests check migrations 00242, 00243 and 00244 (G0 M20 D255, D256):
// another org neither reads nor changes ticket sync or approval-channel
// rows and cannot write any in an org's name, and the tables' guards hold.

// m20Tables are the tenant tables 00242-00244 add.
var m20Tables = []string{
	"external_refs", "ticket_field_owners", "ticket_sync_configs", "ticket_inbound_events", "ticket_outbound",
	"chat_identity_links", "slack_direct_messages", "teams_app_channels", "teams_cards",
}

// TestTenancy_m20_tables_rls: every new table has forced row security, the
// tenant policy and the org write guard.
func TestTenancy_m20_tables_rls(t *testing.T) {
	d := dbtest.New(t)
	for _, tbl := range m20Tables {
		var forced, policy, guard bool
		d.AdminQueryRow(t, `SELECT c.relforcerowsecurity,
			EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname = 'pc' AND p.tablename = c.relname AND p.policyname = 'tenant_isolation'),
			EXISTS (SELECT 1 FROM pg_trigger g WHERE g.tgrelid = c.oid AND g.tgname = 'org_write_guard')
			FROM pg_class c WHERE c.oid = ('pc.' || $1)::regclass`, []any{tbl}, &forced, &policy, &guard)
		if !forced || !policy || !guard {
			t.Errorf("pc.%s: forced RLS %v, tenant policy %v, org write guard %v", tbl, forced, policy, guard)
		}
	}
}

type m20Org struct {
	m5Fixture
	conn, kase, config string
}

func newM20Org(t *testing.T, f m5Fixture) m20Org {
	t.Helper()
	o := m20Org{m5Fixture: f, kase: m5ID(), config: m5ID()}
	o.conn = m15Connection(t, f, m15Gateway(t, f))
	f.mustExec(t, "INSERT INTO pc.cases (org_id, id, title, source, opened_by_type, opened_by_id) VALUES ($1, $2, 'c', 'manual', 'user', 'u')",
		f.org, o.kase)
	f.mustExec(t, `INSERT INTO pc.ticket_sync_configs (org_id, id, system, connection_id, project_key, webhook_secret, created_by)
		VALUES ($1, $2, 'jira', $3, 'SEC', $4, 'test')`, f.org, o.config, o.conn, m5Secret(1))
	return o
}

const (
	m20Ref = `INSERT INTO pc.external_refs (org_id, id, case_id, system, connection_id, external_key, created_by)
		VALUES ($1, $2, $3, 'jira', $4, 'SEC-1', 'test')`
	m20Inbound = `INSERT INTO pc.ticket_inbound_events (org_id, id, config_id, delivery_id, body_sha256, outcome)
		VALUES ($1, $2, $3, $4, $5, 'NOTED')`
	m20Link = `INSERT INTO pc.chat_identity_links (org_id, id, user_id, provider, team_id, external_user_id, email, proposed_by)
		VALUES ($1, $2, $3, 'slack', 'T0TEAM', 'U0USER', 'a@example.test', 'test')`
)

// TestTenancy_ticket_sync: another org sees no ref, configuration, owner or
// inbound event of an org, changes or deletes none, and cannot write any
// in its name or on its case.
func TestTenancy_ticket_sync(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a, b := newM20Org(t, newM5Fixture(t, p)), newM5Fixture(t, p)
	a.mustExec(t, m20Ref, a.org, m5ID(), a.kase, a.conn)
	a.mustExec(t, "INSERT INTO pc.ticket_field_owners (org_id, field, owner, changed_by) VALUES ($1, 'labels', 'PANTHERCLAW', 'test')", a.org)
	a.mustExec(t, m20Inbound, a.org, m5ID(), a.config, "delivery-1", m5Secret(2))
	for _, tbl := range []string{"external_refs", "ticket_field_owners", "ticket_sync_configs", "ticket_inbound_events"} {
		if n := m10Count(t, p, b.org, "SELECT count(*) FROM pc."+tbl); n != 0 {
			t.Errorf("another org sees %d rows of pc.%s", n, tbl)
		}
	}
	b.mustExec(t, "UPDATE pc.ticket_sync_configs SET state = 'PAUSED'")
	b.mustExec(t, "UPDATE pc.ticket_field_owners SET owner = 'TICKET'")
	b.mustExec(t, "UPDATE pc.external_refs SET remote_updated_at = now()")
	if n := m10Count(t, p, a.org, `SELECT (SELECT count(*) FROM pc.ticket_sync_configs WHERE state = 'ACTIVE')
		+ (SELECT count(*) FROM pc.ticket_field_owners WHERE owner = 'PANTHERCLAW')
		+ (SELECT count(*) FROM pc.external_refs WHERE remote_updated_at IS NULL)`); n != 3 {
		t.Fatalf("another org changed rows: %d left as they were", n)
	}
	b.want(t, "23514", "a ref in another org's name", m20Ref, a.org, m5ID(), a.kase, a.conn)
	b.want(t, "23503", "a ref to another org's case", m20Ref, b.org, m5ID(), a.kase, a.conn)
	b.want(t, "23503", "an inbound event of another org's configuration", m20Inbound, b.org, m5ID(), a.config, "delivery-2", m5Secret(3))
}

// TestM20_TicketSyncGuards: the authority fields stay PantherClaw's, the
// inbound log is append-only and unique per delivery, a ref's change time
// only moves forward, and an EXTERNAL entry needs a system author.
func TestM20_TicketSyncGuards(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a := newM20Org(t, newM5Fixture(t, p))
	for _, field := range []string{"containment", "restoration"} {
		a.want(t, "23514", field+" given to the ticket",
			"INSERT INTO pc.ticket_field_owners (org_id, field, owner, changed_by) VALUES ($1, $2, 'TICKET', 'test')", a.org, field)
	}
	a.mustExec(t, m20Inbound, a.org, m5ID(), a.config, "delivery-1", m5Secret(2))
	a.want(t, "23505", "a replayed delivery", m20Inbound, a.org, m5ID(), a.config, "delivery-1", m5Secret(2))
	a.want(t, "42501", "an inbound event changed", "UPDATE pc.ticket_inbound_events SET outcome = 'APPLIED'")
	a.want(t, "42501", "an inbound event deleted", "DELETE FROM pc.ticket_inbound_events")
	ref := m5ID()
	a.mustExec(t, m20Ref, a.org, ref, a.kase, a.conn)
	a.mustExec(t, "UPDATE pc.external_refs SET remote_updated_at = now() WHERE id = $1", ref)
	a.want(t, "23514", "a ref's change time moved back",
		"UPDATE pc.external_refs SET remote_updated_at = now() - interval '1 day' WHERE id = $1", ref)
	a.want(t, "42501", "a ref re-pointed", "UPDATE pc.external_refs SET external_key = 'SEC-2' WHERE id = $1", ref)
	var check string
	d.AdminQueryRow(t, `SELECT pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conrelid = 'pc.case_entries'::regclass AND conname = 'case_entries_external_author'`, nil, &check)
	if check == "" {
		t.Fatal("no EXTERNAL author check")
	}
}

// TestTenancy_approval_channels: another org sees no chat link of an org,
// changes none and cannot propose one for its people; a link moves only
// PROPOSED -> CONFIRMED -> REVOKED; a teams_app channel is inserted
// PENDING_ACTIVATION.
func TestTenancy_approval_channels(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a, b := newM5Fixture(t, p), newM5Fixture(t, p)
	link := m5ID()
	a.mustExec(t, m20Link, a.org, link, a.user)
	if n := m10Count(t, p, b.org, "SELECT count(*) FROM pc.chat_identity_links"); n != 0 {
		t.Fatalf("another org sees %d links", n)
	}
	b.mustExec(t, "UPDATE pc.chat_identity_links SET state = 'REVOKED'")
	if n := m10Count(t, p, a.org, "SELECT count(*) FROM pc.chat_identity_links WHERE state = 'PROPOSED'"); n != 1 {
		t.Fatal("another org revoked the link")
	}
	b.want(t, "23514", "a link in another org's name", m20Link, a.org, m5ID(), a.user)
	b.want(t, "23503", "a link for another org's person", m20Link, b.org, m5ID(), a.user)
	a.want(t, "23514", "a link inserted CONFIRMED",
		`INSERT INTO pc.chat_identity_links (org_id, id, user_id, provider, team_id, external_user_id, email, proposed_by, state, confirmed_at)
		 VALUES ($1, $2, $3, 'slack', 'T0TEAM', 'U0OTHER', 'b@example.test', 'test', 'CONFIRMED', now())`, a.org, m5ID(), a.user)
	a.mustExec(t, "UPDATE pc.chat_identity_links SET state = 'CONFIRMED' WHERE id = $1", link)
	a.want(t, "23514", "a confirmed link proposed again", "UPDATE pc.chat_identity_links SET state = 'PROPOSED' WHERE id = $1", link)
	a.want(t, "42501", "a link re-pointed", "UPDATE pc.chat_identity_links SET external_user_id = 'U0EVIL' WHERE id = $1", link)
	a.mustExec(t, "UPDATE pc.chat_identity_links SET state = 'REVOKED' WHERE id = $1", link)
	a.want(t, "23514", "a revoked link confirmed", "UPDATE pc.chat_identity_links SET state = 'CONFIRMED' WHERE id = $1", link)

	ch := m5ID()
	a.mustExec(t, `INSERT INTO pc.notification_channels (org_id, id, name, kind, event_types, secret, created_by)
		VALUES ($1, $2, 'teams', 'teams_app', '{approval.*}', $3, 'test')`, a.org, ch, m5Secret(4))
	a.want(t, "23514", "a teams_app channel inserted ACTIVE",
		`INSERT INTO pc.teams_app_channels (org_id, channel_record_id, tenant_id, team_id, teams_channel, app_id, service_url, state,
		 membership_type, activated_by, activated_credential, activated_at)
		 VALUES ($1, $2, $3, $3, '19:abc@thread.tacv2', $3, 'https://smba.trafficmanager.net/teams/', 'ACTIVE', 'standard', $4, $5, now())`,
		a.org, ch, m5ID(), a.user, a.cred)
	a.mustExec(t, `INSERT INTO pc.teams_app_channels (org_id, channel_record_id, tenant_id, team_id, teams_channel, app_id, service_url)
		VALUES ($1, $2, $3, $3, '19:abc@thread.tacv2', $3, 'https://smba.trafficmanager.net/teams/')`, a.org, ch, m5ID())
	a.want(t, "23514", "a shared Teams channel activated",
		`UPDATE pc.teams_app_channels SET state = 'ACTIVE', membership_type = 'shared', activated_by = $2, activated_credential = $3
		 WHERE channel_record_id = $1`, ch, a.user, a.cred)
	if n := m10Count(t, p, b.org, "SELECT count(*) FROM pc.teams_app_channels"); n != 0 {
		t.Fatalf("another org sees %d Teams channels", n)
	}
}
