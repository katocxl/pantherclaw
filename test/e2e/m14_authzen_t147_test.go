// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"strings"
	"testing"
	"time"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/enforcementpoints"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestT147_EnforcementPointAbuse: an AuthZEN caller cannot impersonate an
// agent (a name-only subject, a forged, cross-URL or replayed proof),
// cannot ask about a connection not bound to it or without being an
// ACTIVE point, cannot replay an evaluation to spend a budget twice, and
// cannot flood the endpoint past its caps (G0 M14 D26-D29; HR-317..321).
func TestT147_EnforcementPointAbuse(t *testing.T) {
	s := start(t, options{budget: "1000.00"})
	p := authzenPoint(t, s, "agent_held", s.simURL)
	charges := []string{"ch_t147a", "ch_t147b", "ch_t147c", "ch_t147d", "ch_t147e", "ch_t147f"}
	refundableMore(t, s, charges...)
	refund := func(charge string) []byte {
		return []byte(`{"charge":"` + charge + `","amount":"10.00","currency":"USD","reason":"duplicate"}`)
	}
	req := func(charge string) azRequest {
		return azRequest{Method: http.MethodPost, Path: "/v1/refunds", Body: refund(charge), Action: ids.NewV7()}
	}
	refused := func(name string, a azAnswer, code string) {
		t.Helper()
		if a.Decision || (code != "" && a.Context.PantherClaw.Code != code) {
			t.Errorf("%s: %+v, want decision false %s", name, a.Context.PantherClaw, code)
		}
	}

	// HR-317: no bearer, a bad one, an unbound connection (a disabled point
	// at the end; a person.s or an API key.s bearer: the endpoint unit tests).
	if st, _ := p.post(t, "/access/v1/evaluation", p.evaluation(t, req("ch_t147a")), "-"); st != http.StatusUnauthorized {
		t.Fatalf("no bearer: %d", st)
	}
	if st, _ := p.post(t, "/access/v1/evaluation", p.evaluation(t, req("ch_t147a")), "not-a-token"); st != http.StatusUnauthorized {
		t.Fatalf("a bad bearer: %d", st)
	}
	other := p.evaluation(t, req("ch_t147a"))
	other["resource"].(map[string]any)["id"] = "github"
	if st, _ := p.post(t, "/access/v1/evaluation", other, ""); st != http.StatusForbidden {
		t.Fatalf("an unbound connection: %d", st)
	}

	// HR-318: impersonation.
	nameOnly := p.evaluation(t, req("ch_t147a"))
	nameOnly["subject"] = map[string]any{"type": "user", "id": "alice"}
	refused("a name-only subject", p.evaluate(t, nameOnly), "SUBJECT_NOT_A_WORKLOAD")
	_, thief, _ := ed25519.GenerateKey(rand.Reader)
	forged := req("ch_t147a")
	forged.Key, forged.Token = thief, s.token
	refused("a forged proof", p.evaluate(t, p.evaluation(t, forged)), "IDENTITY_UNVERIFIED")
	cross := req("ch_t147a")
	cross.ProofURL = p.base + "/v1/charges"
	refused("a proof for another URL", p.evaluate(t, p.evaluation(t, cross)), "IDENTITY_UNVERIFIED")
	another := req("ch_t147a")
	another.Agent = ids.NewV7().String()
	refused("a subject naming another agent", p.evaluate(t, p.evaluation(t, another)), "SUBJECT_MISMATCH")
	outside := p.evaluation(t, req("ch_t147a"))
	outside["resource"].(map[string]any)["properties"].(map[string]any)["url"] = "https://evil.example.test/v1/refunds"
	refused("a URL outside the connection", p.evaluate(t, outside), "URL_OUTSIDE_CONNECTION")
	missing := p.evaluation(t, req("ch_t147a"))
	delete(missing["subject"].(map[string]any)["properties"].(map[string]any), "pap_proof")
	refused("no proof", p.evaluate(t, missing), "PAP_CREDENTIALS_REQUIRED")
	if n := s.row(t, "SELECT count(*) FROM pc.transactions WHERE org_id = $1 AND channel = 'authzen'", s.org); n != "0" {
		t.Fatalf("impersonation recorded %s transactions", n)
	}

	// HR-319: a replayed evaluation and a resubmission never spend twice.
	r := req("ch_t147b")
	ev := p.evaluation(t, r)
	first := p.evaluate(t, ev)
	if !first.Decision || first.Context.PantherClaw.Coverage != "PARTIAL" {
		t.Fatalf("allowed: %+v", first.Context.PantherClaw)
	}
	refused("the same evaluation again", p.evaluate(t, ev), "IDENTITY_UNVERIFIED")
	refused("the same action, a fresh proof", p.evaluate(t, p.evaluation(t, r)), "DUPLICATE")
	if n := s.row(t, "SELECT count(*) FROM pc.execution_attempts WHERE org_id = $1 AND outcome = 'delegated'", s.org); n != "1" {
		t.Fatalf("delegated attempts in the org: %s", n)
	}
	s.waitSettled(t, "10")
	if v := s.row(t, "SELECT decided_via || ' ' || enforcement_point_id FROM pc.transactions WHERE org_id = $1 AND id = $2",
		s.org, first.Context.PantherClaw.TransactionID); v != "authzen "+p.id.String() {
		t.Fatalf("decided via: %q", v)
	}

	// HR-321: caps.
	if st, _ := p.post(t, "/access/v1/evaluation", map[string]any{"x": strings.Repeat("a", 128<<10)}, ""); st != http.StatusRequestEntityTooLarge {
		t.Fatalf("a body over 128 KiB: %d", st)
	}
	var many []any
	for range 11 {
		many = append(many, map[string]any{})
	}
	if st, _ := p.post(t, "/access/v1/evaluations", map[string]any{"evaluations": many}, ""); st != http.StatusBadRequest {
		t.Fatalf("a batch of 11: %d", st)
	}

	// A disabled point is answered no more.
	if _, err := enforcementpoints.New(s.pool).Disable(p.admin.ctx, p.id); err != nil {
		t.Fatal(err)
	}
	if st, _ := p.post(t, "/access/v1/evaluation", p.evaluation(t, req("ch_t147c")), ""); st != http.StatusUnauthorized {
		t.Fatalf("a disabled point: %d", st)
	}
}

// TestHR320_TargetEnforcedDecisionsCarryTheActionToken: on a
// target_enforced connection an allowed evaluation's context carries the
// action token binding exactly the forwarded request; the target accepts
// the request with it, once, and refuses it without (D28).
func TestHR320_TargetEnforcedDecisionsCarryTheActionToken(t *testing.T) {
	s := start(t, options{budget: "1000.00", access: capp.AccessTargetEnforced, actionTokens: true})
	p := authzenPoint(t, s, "target_enforced", s.simURL)
	refundableMore(t, s, "ch_te1")
	body := []byte(`{"charge":"ch_te1","amount":"10.00","currency":"USD","reason":"duplicate"}`)
	a := p.evaluate(t, p.evaluation(t, azRequest{Method: http.MethodPost, Path: "/v1/refunds", Body: body, Action: ids.NewV7()}))
	tok := a.Context.PantherClaw.ActionToken
	if !a.Decision || tok == "" || a.Context.PantherClaw.Coverage != "PARTIAL" {
		t.Fatalf("decision: %+v", a.Context.PantherClaw)
	}
	send := func(token string) int {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, s.simURL+"/v1/refunds", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "agent-te1")
		if token != "" {
			req.Header.Set("PAP-Action", token)
		}
		resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if st := send(""); st < 400 {
		t.Fatalf("without the action token: %d", st)
	}
	if st := send(tok); st != http.StatusOK || s.sim.Stats().Refunds != 1 {
		t.Fatalf("with it: %d, %d refunds", st, s.sim.Stats().Refunds)
	}
	if st := send(tok); st < 400 || s.sim.Stats().Refunds != 1 {
		t.Fatalf("the action token used twice: %d", st)
	}
	// A token for one body never carries another.
	refundableMore(t, s, "ch_te2")
	b2 := p.evaluate(t, p.evaluation(t, azRequest{Method: http.MethodPost, Path: "/v1/refunds", Action: ids.NewV7(),
		Body: []byte(`{"charge":"ch_te2","amount":"10.00","currency":"USD","reason":"duplicate"}`)}))
	if !b2.Decision || b2.Context.PantherClaw.ActionToken == "" {
		t.Fatalf("second decision: %+v", b2.Context.PantherClaw)
	}
	if st := send(b2.Context.PantherClaw.ActionToken); st < 400 || s.sim.Stats().Refunds != 1 {
		t.Fatalf("a token for another body: %d", st)
	}
}

// TestHR321_APointPastItsRateIsRefused: the endpoint answers 429 with
// Retry-After once a point passes its evaluations a second.
func TestHR321_APointPastItsRateIsRefused(t *testing.T) {
	s := start(t, options{budget: "1000.00"})
	p := authzenPoint(t, s, "agent_held", s.simURL)
	s.db.AdminExec(t, "UPDATE pc.enforcement_points SET rate_per_second = 1 WHERE org_id = $1 AND id = $2", s.org, p.id)
	codes, retry := map[int]int{}, ""
	for range 3 {
		st, h, _ := p.postH(t, "/access/v1/evaluation", map[string]any{}, "")
		codes[st]++
		if st == http.StatusTooManyRequests {
			retry = h.Get("Retry-After")
		}
	}
	if codes[http.StatusTooManyRequests] == 0 || retry == "" {
		t.Fatalf("statuses %v, want a 429", codes)
	}
}
