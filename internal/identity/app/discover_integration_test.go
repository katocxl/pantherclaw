// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/identity/app"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

const gatewayURL = "https://gw.example.test/v1/refunds"

// report builds a gateway report of a key-only request from wl.
func (w *world) report(t *testing.T, wl workload, gateway string, body []byte) app.DiscoverInput {
	t.Helper()
	n, err := w.svc.Nonce(context.Background(), w.org)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := pap.NewProof(wl.key, pap.ProofParams{Method: "POST", URL: gatewayURL, Body: body, Nonce: n, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	return app.DiscoverInput{
		Request: pap.Request{Method: "POST", URL: gatewayURL, BodySHA256: sha256.Sum256(body)}, Proof: proof,
		Gateway: gateway, Route: "payments-refund", ClientAddress: "198.51.100.7", UserAgent: strings.Repeat("ü", 200),
	}
}

// TestHR148_UnknownKeysBecomeOneDiscoveryEach: a verified key-only request
// from an unknown key becomes a DISCOVERED agent with an ADMISSION entry;
// later sightings are counted; known keys and bad proofs create nothing.
func TestHR148_UnknownKeysBecomeOneDiscoveryEach(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	stranger := newWorkload()
	id, err := w.svc.Discover(ctx, w.org, w.report(t, stranger, "gw-1", []byte(`{}`)))
	if err != nil || id.IsZero() {
		t.Fatalf("first sighting: %v, %v", id, err)
	}
	if n := w.count(t, `SELECT count(*) FROM pc.waitlist_entries e JOIN pc.agents a ON a.org_id = e.org_id AND a.id = e.subject_id
		WHERE e.org_id = $1 AND e.subject_type = 'agent' AND a.state = 'DISCOVERED'
		  AND e.evidence->'untrusted'->>'route' = 'payments-refund' AND e.evidence->'trusted'->>'fingerprint' IS NOT NULL`, w.org); n != 1 {
		t.Fatalf("discovered agents with an ADMISSION entry: %d", n)
	}
	if n := w.count(t, "SELECT max(octet_length(observed->>'user_agent')) FROM pc.discoveries WHERE org_id = $1", w.org); n > app.MaxObserved {
		t.Errorf("user agent stored with %d bytes", n)
	}
	again, err := w.svc.Discover(ctx, w.org, w.report(t, stranger, "gw-1", []byte(`{}`)))
	if err != nil || !again.IsZero() || w.count(t, "SELECT seen_count FROM pc.discoveries WHERE org_id = $1", w.org) != 2 {
		t.Fatalf("second sighting: %v, %v", again, err)
	}
	known, _, _ := w.admitted(t, adomain.ContextCI)
	if id, err := w.svc.Discover(ctx, w.org, w.report(t, known, "gw-1", []byte(`{}`))); err != nil || !id.IsZero() {
		t.Errorf("an admitted key was discovered: %v, %v", id, err)
	}
	bad := w.report(t, newWorkload(), "gw-1", []byte(`{}`))
	bad.Request.BodySHA256[0] ^= 1
	_, err = w.svc.Discover(ctx, w.org, bad)
	wantPAP(t, "proof over another body", err, pap.CodeBodyHashMismatch)
	if n := w.count(t, "SELECT count(*) FROM pc.discoveries WHERE org_id = $1", w.org); n != 1 {
		t.Errorf("discoveries %d, want 1", n)
	}
}

// TestT050_DiscoveryFloodsAreCapped: at most 60 new discoveries per gateway
// a minute and 200 open per org; past them sightings are dropped and one
// flood event is audited.
func TestT050_DiscoveryFloodsAreCapped(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	seed := func(n int, gateway string) {
		w.exec(t, `WITH a AS (INSERT INTO pc.agents (org_id, id, name, state, created_by)
			SELECT $1, gen_random_uuid(), 'd' || g, 'DISCOVERED', 'test' FROM generate_series(1, $2::int) g RETURNING id)
			INSERT INTO pc.discoveries (org_id, id, agent_id, source, key_jkt, public_jwk, observed)
			SELECT $1, gen_random_uuid(), id, 'gateway', substr(md5(id::text) || md5(id::text || 'x'), 1, 43), '{}',
				jsonb_build_object('gateway', $3::text) FROM a`, w.org, n, gateway)
	}
	seed(app.MaxNewDiscoveriesPerMinute-1, "gw-1")
	if id, err := w.svc.Discover(ctx, w.org, w.report(t, newWorkload(), "gw-1", []byte(`{}`))); err != nil || id.IsZero() {
		t.Fatalf("the 60th discovery: %v, %v", id, err)
	}
	for range 2 {
		if id, err := w.svc.Discover(ctx, w.org, w.report(t, newWorkload(), "gw-1", []byte(`{}`))); err != nil || !id.IsZero() {
			t.Fatalf("over the gateway rate: %v, %v", id, err)
		}
	}
	if id, err := w.svc.Discover(ctx, w.org, w.report(t, newWorkload(), "gw-2", []byte(`{}`))); err != nil || id.IsZero() {
		t.Fatalf("another gateway: %v, %v", id, err)
	}
	seed(app.MaxOpenDiscoveries, "seeded")
	if id, err := w.svc.Discover(ctx, w.org, w.report(t, newWorkload(), "gw-3", []byte(`{}`))); err != nil || !id.IsZero() {
		t.Fatalf("over the org cap: %v, %v", id, err)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.security.discovery_flood'", w.org); n != 2 {
		t.Errorf("flood events %d, want one per gateway", n)
	}
}

// TestHR090_JanitorEmptiesExpiredReplaySlots: replay rows and nonces go
// once their nonce has been expired for 60 seconds; pending instances past
// their deadline and runs past their expiry are recorded EXPIRED.
func TestHR090_JanitorEmptiesExpiredReplaySlots(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	// The sweep compares nonce minutes with the database clock, so the test
	// starts early in a minute: a minute boundary between reading the clock
	// and sweeping would expire one more nonce than expected.
	var minute int64
	var second float64
	for {
		if err := w.pool.InTenantTx(ctx, w.org, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, `SELECT floor(extract(epoch FROM clock_timestamp()) / 60)::bigint,
				extract(second FROM clock_timestamp())::float8`).Scan(&minute, &second)
		}); err != nil {
			t.Fatal(err)
		}
		if second < 40 {
			break
		}
		time.Sleep(time.Duration((61 - second) * float64(time.Second)))
	}
	for _, m := range []int64{minute - 20, minute - 7, minute - 6, minute} {
		w.exec(t, "INSERT INTO pc.dpop_nonces (org_id, minute, nonce) VALUES ($1, $2, $3)", w.org, m, strings.Repeat("n", 22)+string(rune('a'+m%26)))
		w.exec(t, "INSERT INTO pc.dpop_jti (org_id, slot, jkt, jti, nonce_minute) VALUES ($1, $2, $3, $4, $5)",
			w.org, pap.Slot(m), strings.Repeat("k", 43), strings.Repeat("j", 22)+string(rune('a'+m%26)), m)
	}
	agent := w.agent(t, adomain.ContextCI)
	pending, err := w.enroll(t, newWorkload(), w.enrollmentToken(t, agent))
	if err != nil {
		t.Fatal(err)
	}
	w.d.AdminExec(t, "UPDATE pc.agent_instances SET expires_at = now() - interval '1 minute' WHERE id = $1", pending.Instance.Instance)
	run := ids.NewV7()
	w.d.AdminExec(t, `INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_user_id, principal_user_id,
		principal_source, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $5, 'launcher', now() - interval '2 hours', now() - interval '1 hour')`,
		w.org, run, agent, w.env, w.owner)
	sw, err := app.SweepOrg(ctx, w.pool, w.org)
	if err != nil || sw.Proofs != 2 || sw.Nonces != 2 || sw.Instances != 1 || sw.Runs != 1 {
		t.Fatalf("sweep: %+v, %v", sw, err)
	}
	if n := w.count(t, `SELECT count(*) FROM pc.waitlist_entries WHERE org_id = $1 AND subject_id = $2 AND state = 'EXPIRED'`,
		w.org, pending.Instance.Instance); n != 1 {
		t.Errorf("the expired instance's ADMISSION entry is still open")
	}
	if n := w.count(t, "SELECT count(*) FROM pc.runs WHERE org_id = $1 AND state = 'EXPIRED'", w.org); n != 1 {
		t.Errorf("run not recorded EXPIRED")
	}
}

// TestT050_ScanFindingsNeverFillTheGatewaysRoom: the org cap on open
// discoveries counts the gateway's own; findings of people's scans and of
// org scans have caps of their own, so a full room of them never stops an
// unknown key from being recorded (HR-148, HR-209).
func TestT050_ScanFindingsNeverFillTheGatewaysRoom(t *testing.T) {
	w := newWorld(t)
	for i, source := range []string{"scan", "github_scan"} {
		w.exec(t, `WITH a AS (INSERT INTO pc.agents (org_id, id, name, state, created_by)
			SELECT $1, gen_random_uuid(), 'f' || $3::int || '-' || g, 'DISCOVERED', 'test' FROM generate_series(1, $2::int) g RETURNING id)
			INSERT INTO pc.discoveries (org_id, id, agent_id, source, scan_key)
			SELECT $1, gen_random_uuid(), id, $4, sha256(id::text::bytea) FROM a`, w.org, app.MaxOpenDiscoveries, i, source)
	}
	if id, err := w.svc.Discover(context.Background(), w.org, w.report(t, newWorkload(), "gw-1", []byte(`{}`))); err != nil || id.IsZero() {
		t.Fatalf("an unknown key with the scans' rooms full: %v, %v", id, err)
	}
}
