// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// exception stores an ACTIVE exception of rule for agent that the database
// clock ends after ends (an interval, negative for one already ended).
func (w *world) exception(agent ids.UUID, rule pdomain.Rule, ends string) ids.UUID {
	w.t.Helper()
	id, d := ids.NewV7(), pdomain.RuleDigest(rule)
	w.db.AdminExec(w.t, `INSERT INTO pc.policy_exceptions (org_id, id, bundle_id, rule_id, rule_digest, agent_id, operations, reason,
		owner_id, requested_by, requested_expiry, state, activated_at, expires_at, created_at)
		VALUES ($1, $2, 'org-policy', $3, $4, $5, ARRAY['payments.refund.create'], 'quarter end', $6, $6,
			now() + $7::interval, 'ACTIVE', now() - interval '2 hours', now() + $7::interval, now() - interval '2 hours')`,
		w.org, id, rule.ID, d[:], agent, w.alice, ends)
	return id
}

// TestHR235_TheAuthorityReadsOnlyTheAgentsActiveExceptions: the policy read
// gives the decision only the agent's exceptions the database clock has
// not ended; the decision then names the exception in its receipt, and
// its recording keeps it for replay. Another agent's, an ended or a
// revoked exception waives nothing.
func TestHR235_TheAuthorityReadsOnlyTheAgentsActiveExceptions(t *testing.T) {
	w := newWorld(t)
	w.keepInputs()
	w.refundable("ch_1", "ch_2", "ch_3", "ch_4")
	run := w.run(w.grant("500").ID, ids.UUID{})
	rule := pgForbidOver20
	rule.Exceptable = true
	w.publishPolicy(1, false, rule)

	other := ids.NewV7()
	exec(t, w.pool, w.org, `INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'other', 'DISCOVERED', 'test')`, w.org, other)
	w.exception(other, rule, "1 hour")
	w.exception(w.agent, rule, "-1 hour")
	if r := w.authorize(w.request(run, ids.NewV7(), "ch_1", "30.00")); r.Decision != adomain.Deny || decisive(r) != "REFUND_TOO_LARGE" {
		t.Fatalf("without an active exception of its own: %s %s", r.Decision, decisive(r))
	}

	x := w.exception(w.agent, rule, "1 hour")
	r := w.authorize(w.request(run, ids.NewV7(), "ch_2", "30.00"))
	if r.Decision != adomain.Allow {
		t.Fatalf("with an active exception: %s %s", r.Decision, decisive(r))
	}
	if body := string(payload(t, r.Receipt)); !strings.Contains(body, "EXCEPTION_APPLIED") || !strings.Contains(body, x.String()) {
		t.Fatalf("the receipt does not name the exception: %s", body)
	}
	rec, err := w.replayEngine().RecordedInputs(context.Background(), w.org, r.TransactionID, r.Evaluation)
	if err != nil {
		t.Fatal(err)
	}
	d := pdomain.RuleDigest(rule)
	if xs := rec.Reads.Policy.Exceptions; len(xs) != 1 || xs[0].ID != x.String() || xs[0].RuleDigest != hex.EncodeToString(d[:]) {
		t.Fatalf("recorded exceptions %+v", xs)
	}

	w.db.AdminExec(t, `UPDATE pc.policy_exceptions SET state = 'REVOKED', revoked_by = $2, revoked_reason = 'done' WHERE id = $1`, x, w.alice)
	if r := w.authorize(w.request(run, ids.NewV7(), "ch_3", "30.00")); r.Decision != adomain.Deny {
		t.Fatalf("after revocation: %s", r.Decision)
	}
}
