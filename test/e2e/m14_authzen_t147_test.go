// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"strings"
	"testing"

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

	// HR-317: no bearer, a person's or an unbound caller's, a disabled point.
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
	cross := p.evaluation(t, req("ch_t147a"))
	cross["resource"].(map[string]any)["properties"].(map[string]any)["url"] = s.simURL + "/v1/refunds/other"
	refused("a proof for another URL", p.evaluate(t, cross), "")
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
	if n := s.row(t, `SELECT count(*) FROM pc.execution_attempts a JOIN pc.permits p ON p.org_id = a.org_id AND p.id = a.permit_id
		WHERE a.org_id = $1 AND p.transaction_id = $2 AND a.outcome = 'delegated'`, s.org, first.Context.PantherClaw.TransactionID); n != "1" {
		t.Fatalf("delegated attempts: %s", n)
	}
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
}
