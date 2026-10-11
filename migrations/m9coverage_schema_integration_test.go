// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// These tests check the coverage schema (G0 M9 slice A1, migration 00085):
// the second line of defense behind the coverage module. Names are
// prefixed m9c.

const (
	m9cDigest  = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	m9cClosure = `INSERT INTO pc.coverage_closures (org_id, id, agent_id, connection_id, sandbox_session_id, result, probes,
		positive_controls_passed, negative_controls_passed, canary_passed, signing_key_jkt, server_nonce, results_sha256,
		engine_version, api_version, runtime, image_digests, config_sha256, gateway_id, connection_revision,
		package_version_id, session_started_at, observed_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, '[{"name":"direct_https","role":"probe","expect":"blocked","observed":"blocked"}]',
		true, $7, true, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'nonce-0123456789abcdef', ` + m5Hash + `, '29.0.1',
		'1.51', 'runc', ARRAY[$8]::text[], ` + m5Hash + `, $9, 1, $10, now() - interval '1 minute', now() + $11::interval,
		now() + $12::interval)`
	m9cSnapshot = `INSERT INTO pc.coverage_snapshots (org_id, id, agent_id, connection_id, operation, state, reasons,
		closure_id, body, body_sha256, ledger_entry_id, expires_at)
		VALUES ($1, $2, $3, $4, 'payments.refund.create', $5, '{}', $6, '{}', ` + m5Hash + `, $7, now() + $8::interval)`
	m9cExclusion = `INSERT INTO pc.coverage_exclusions (org_id, id, connection_id, route_kind, reason, created_by, expires_at)
		VALUES ($1, $2, $3, 'browser', $4, $5, now() + $6::interval)`
)

type m9cFixture struct {
	m7Fixture
	version string
}

func newM9cFixture(t *testing.T) m9cFixture {
	t.Helper()
	d := dbtest.New(t)
	f := m9cFixture{m7Fixture: newM7Fixture(t, d.AppPool(t)), version: m5ID()}
	pkg := m5ID()
	f.mustExec(t, "INSERT INTO pc.tool_packages (org_id, id, name) VALUES ($1, $2, 'pc.mock-payments')", f.org, pkg)
	f.mustExec(t, `INSERT INTO pc.package_versions (org_id, id, package_id, version, file_digest, raw, state)
		VALUES ($1, $2, $3, '1.0.0', $4, '\x7b7d', 'ACTIVE')`, f.org, f.version, pkg, m9cDigest)
	f.mustExec(t, `INSERT INTO pc.package_pins (org_id, package_id, version_id, version, digest)
		VALUES ($1, $2, $3, '1.0.0', $4)`, f.org, pkg, f.version, m9cDigest)
	return f
}

// closure inserts a closure and returns its id; the error is the insert's.
func (f m9cFixture) closure(result string, negative bool, observedIn, expiresIn string) (string, error) {
	id := m5ID()
	session, err := f.sandboxSession()
	if err != nil {
		return id, err
	}
	return id, f.exec(m9cClosure, f.org, id, f.agent, f.connection, session, result, negative, m9cDigest, f.gateway,
		f.version, observedIn, expiresIn)
}

func m9cUUID(t *testing.T, s string) ids.UUID {
	t.Helper()
	u, err := ids.ParseUUID(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// TestHR210_ClosuresPassOnlyOnControlsAndEnforcedNeedsOneInSchema: a
// closure passes only with its positive and negative controls and the
// canary, a snapshot is ENFORCED only on a closure and with an expiry, and
// neither can be changed or deleted by the application.
func TestHR210_ClosuresPassOnlyOnControlsAndEnforcedNeedsOneInSchema(t *testing.T) {
	f := newM9cFixture(t)
	if _, err := f.closure("PASSED", false, "0 seconds", "24 hours"); m5State(err) != m5Check {
		t.Errorf("a pass with a failed negative control: SQLSTATE %q, want %q", m5State(err), m5Check)
	}
	if _, err := f.closure("FAILED", false, "0 seconds", "24 hours"); err != nil {
		t.Fatalf("a failed closure is evidence too: %v", err)
	}
	for name, at := range map[string][2]string{
		"an expiry past 7 days":      {"0 seconds", "8 days"},
		"probes run in the future":   {"10 minutes", "24 hours"},
		"probes run 2 hours earlier": {"-2 hours", "20 hours"},
	} {
		if _, err := f.closure("PASSED", true, at[0], at[1]); m5State(err) != m5Check {
			t.Errorf("%s: SQLSTATE %q, want %q", name, m5State(err), m5Check)
		}
	}
	closure, err := f.closure("PASSED", true, "0 seconds", "24 hours")
	if err != nil {
		t.Fatal(err)
	}
	f.want(t, m5Check, "an image by tag, not digest", m9cClosure, f.org, m5ID(), f.agent, f.connection, m5ID(), "PASSED", true,
		"alpine:latest", f.gateway, f.version, "0 seconds", "24 hours")
	f.want(t, m5Denied, "a closure changed", "UPDATE pc.coverage_closures SET result = 'PASSED'")
	f.want(t, m5Denied, "a closure deleted", "DELETE FROM pc.coverage_closures")

	f.want(t, m5Check, "ENFORCED without a closure", m9cSnapshot, f.org, m5ID(), f.agent, f.connection, "ENFORCED", nil,
		f.ledger(t), "24 hours")
	f.want(t, m5Check, "PARTIAL with an expiry", m9cSnapshot, f.org, m5ID(), f.agent, f.connection, "PARTIAL", nil,
		f.ledger(t), "24 hours")
	f.want(t, m5Check, "ENFORCED already expired", m9cSnapshot, f.org, m5ID(), f.agent, f.connection, "ENFORCED", closure,
		f.ledger(t), "-1 second")
	f.mustExec(t, m9cSnapshot, f.org, m5ID(), f.agent, f.connection, "ENFORCED", closure, f.ledger(t), "24 hours")
	ledger := f.ledger(t)
	f.mustExec(t, m9cSnapshot, f.org, m5ID(), f.agent, f.connection, "PARTIAL", nil, ledger, nil)
	f.want(t, m5Unique, "two snapshots in one ledger entry", m9cSnapshot, f.org, m5ID(), f.agent, f.connection, "UNKNOWN",
		nil, ledger, nil)
	f.want(t, m5Denied, "a snapshot changed", "UPDATE pc.coverage_snapshots SET state = 'ENFORCED'")
	f.want(t, m5Denied, "a snapshot deleted", "DELETE FROM pc.coverage_snapshots")
}

// TestHR211_InvalidationsOnlyGainTheirReassessmentInSchema: an invalidation
// event is kept as it happened; the reassess job only marks it.
func TestHR211_InvalidationsOnlyGainTheirReassessmentInSchema(t *testing.T) {
	f := newM9cFixture(t)
	const insert = `INSERT INTO pc.coverage_invalidations (org_id, id, kind, connection_id, subject_id)
		VALUES ($1, $2, $3, $4, $4)`
	f.want(t, m5Check, "an unknown kind", insert, f.org, m5ID(), "settings", f.connection)
	id := m5ID()
	f.mustExec(t, insert, f.org, id, "route_mode", f.connection)
	f.want(t, m5Denied, "an event's kind changed", "UPDATE pc.coverage_invalidations SET kind = 'gateway'")
	f.want(t, m5Denied, "an event moved in time", "UPDATE pc.coverage_invalidations SET occurred_at = now()")
	f.want(t, m5Denied, "an event deleted", "DELETE FROM pc.coverage_invalidations")
	ctx := context.Background()
	err := f.p.InTenantTx(ctx, f.org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		pending, err := q.PendingCoverageInvalidations(ctx, f.org, 10)
		if err != nil || len(pending) != 1 {
			t.Fatalf("pending = %d (%v), want 1", len(pending), err)
		}
		n, err := q.MarkCoverageInvalidationsReassessed(ctx, f.org, []ids.UUID{pending[0].ID})
		if err != nil || n != 1 {
			t.Fatalf("marked %d (%v), want 1", n, err)
		}
		if n, err = q.MarkCoverageInvalidationsReassessed(ctx, f.org, []ids.UUID{pending[0].ID}); err != nil || n != 0 {
			t.Fatalf("marked again %d (%v), want 0", n, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestHR212_ExclusionsArePersonsWithAReasonAndAnExpiryInSchema: only a
// user creates or revokes an exclusion, with a written reason and an expiry
// of at most 90 days, and its terms never change.
func TestHR212_ExclusionsArePersonsWithAReasonAndAnExpiryInSchema(t *testing.T) {
	f := newM9cFixture(t)
	const reason = "No browser exists in the build container."
	f.want(t, "23503", "created by a service, not a person", m9cExclusion, f.org, m5ID(), f.connection, reason, m5ID(), "30 days")
	f.want(t, m5Check, "a reason that says nothing", m9cExclusion, f.org, m5ID(), f.connection, "   ok      ", f.user, "30 days")
	f.want(t, m5Check, "an expiry past 90 days", m9cExclusion, f.org, m5ID(), f.connection, reason, f.user, "91 days")
	f.want(t, m5Check, "a mediated channel excluded", `INSERT INTO pc.coverage_exclusions (org_id, id, connection_id,
		route_kind, reason, created_by, expires_at) VALUES ($1, $2, $3, 'channel', $4, $5, now() + interval '1 day')`,
		f.org, m5ID(), f.connection, reason, f.user)
	f.mustExec(t, m9cExclusion, f.org, m5ID(), f.connection, reason, f.user, "90 days")
	f.want(t, m5Denied, "a reason rewritten", "UPDATE pc.coverage_exclusions SET reason = reason")
	f.want(t, m5Denied, "an expiry extended", "UPDATE pc.coverage_exclusions SET expires_at = expires_at + interval '1 day'")
	f.want(t, m5Denied, "an exclusion deleted", "DELETE FROM pc.coverage_exclusions")
	f.want(t, m5Check, "revoked by nobody", "UPDATE pc.coverage_exclusions SET state = 'REVOKED', revoked_at = now()")
	f.mustExec(t, "UPDATE pc.coverage_exclusions SET state = 'REVOKED', revoked_by = $1, revoked_at = now()", f.user)
}

// TestIntM9CoverageRoutesAndFindingsUpsert: a route or finding seen again is
// one row, an observed route stays observed, and a dismissed finding stays
// dismissed.
func TestIntM9CoverageRoutesAndFindingsUpsert(t *testing.T) {
	f := newM9cFixture(t)
	conn, agent, user := m9cUUID(t, f.connection), m9cUUID(t, f.agent), m9cUUID(t, f.user)
	ctx := context.Background()
	err := f.p.InTenantTx(ctx, f.org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		route := func(observation string) dbq.PcCoverageRoute {
			r, err := q.UpsertCoverageRoute(ctx, dbq.UpsertCoverageRouteParams{
				OrgID: f.org, ID: ids.NewV7(), ConnectionID: conn, Kind: "direct_api", Locator: new("api.example.com:443"),
				Observation: observation, Source: "scan", Attributes: []byte(`{}`),
			})
			if err != nil {
				t.Fatal(err)
			}
			return r
		}
		first, again := route("observed"), route("proposed")
		if first.ID != again.ID || again.SeenCount != 2 || again.Observation != "observed" {
			t.Fatalf("route seen again: %+v after %+v", again, first)
		}
		scoped, err := q.CoverageRoutesForScope(ctx, dbq.CoverageRoutesForScopeParams{
			OrgID: f.org, ConnectionID: conn, AgentID: &agent, Operation: "payments.refund.create",
		})
		if err != nil || len(scoped) != 1 {
			t.Fatalf("an every-agent route in an agent's scope: %d (%v)", len(scoped), err)
		}
		finding := func() dbq.PcCoverageFinding {
			r, err := q.UpsertCoverageFinding(ctx, dbq.UpsertCoverageFindingParams{
				OrgID: f.org, ID: ids.NewV7(), Kind: "credential_overreach", ConnectionID: &conn, Subject: "installation 4711",
				Declared: []string{"pull_requests:write"}, Held: []string{"administration:write", "pull_requests:write"},
				Used: []string{"pull_requests:write"}, Excess: []string{"administration:write"}, Severity: "high",
				Fingerprint: make([]byte, 32),
			})
			if err != nil {
				t.Fatal(err)
			}
			return r
		}
		open := finding()
		if _, err := q.DismissCoverageFinding(ctx, dbq.DismissCoverageFindingParams{
			OrgID: f.org, ID: open.ID, DismissedBy: &user, DismissReason: new("Accepted for the pilot."),
		}); err != nil {
			t.Fatal(err)
		}
		if again := finding(); again.ID != open.ID || again.State != "DISMISSED" {
			t.Fatalf("a dismissed finding seen again: %+v", again)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
