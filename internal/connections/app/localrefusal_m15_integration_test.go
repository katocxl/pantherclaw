// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR421_AnElicitationRefusalIsAuditedWithoutTheQuestion (G0 M15 D40):
// a gateway's elicitation_refused refusal is audited as
// connection.elicitation_refused, denied, with its reason and the
// question's SHA-256, never the question; a reason outside the list, a
// digest of another length, or details on another code are refused and
// record nothing.
// Covers: PN-015.2
func TestHR421_AnElicitationRefusalIsAuditedWithoutTheQuestion(t *testing.T) {
	e := newEnv(t)
	c := e.payments(t, "payments")
	ctx := context.Background()
	run := ids.NewV7()
	sum := bytes.Repeat([]byte{0xab}, 32)
	for name, bad := range map[string]struct {
		code   string
		detail app.RefusalDetail
	}{
		"an unknown reason":        {app.RefusalElicitationRefused, app.RefusalDetail{ElicitationReason: "felt_like_it"}},
		"a short digest":           {app.RefusalElicitationRefused, app.RefusalDetail{QuestionSHA256: sum[:16]}},
		"details on another code":  {app.RefusalSecretInPayload, app.RefusalDetail{ElicitationReason: "url_mode"}},
		"a digest on another code": {app.RefusalSecretInPayload, app.RefusalDetail{QuestionSHA256: sum}},
	} {
		if err := e.svc.ReportLocalRefusal(ctx, e.org, e.gateway, c.ID, bad.code, "payments.refund.create", run, bad.detail); !is(err, app.ErrRefusalDetail) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := e.svc.ReportLocalRefusal(ctx, e.org, e.gateway, c.ID, app.RefusalElicitationRefused, "payments.refund.create", run,
		app.RefusalDetail{ElicitationReason: "url_mode", QuestionSHA256: sum}); err != nil {
		t.Fatal(err)
	}
	n := e.int64(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.connection.elicitation_refused'
		AND actor_type = 'gateway' AND actor_id = $2
		AND convert_from(body, 'UTF8')::jsonb ->> 'outcome' = 'denied'
		AND convert_from(body, 'UTF8')::jsonb ->> 'reason_code' = 'ELICITATION_REFUSED'
		AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'elicitation_reason' = 'url_mode'
		AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'question_sha256' = $3
		AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'run_id' = $4`, e.org, e.gateway.String(), hex.EncodeToString(sum), run.String())
	if n != 1 {
		t.Fatalf("%d audit events, want 1", n)
	}
	if n := e.int64(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind LIKE 'audit.connection.%_refused'`, e.org); n != 1 {
		t.Fatalf("the refused reports recorded %d events", n-1)
	}
}
