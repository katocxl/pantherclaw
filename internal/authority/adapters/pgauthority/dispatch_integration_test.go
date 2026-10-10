// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

func (w *world) actionTokens() {
	w.t.Helper()
	reg := keys.NewRegistry()
	k, _ := keys.GenerateSigningKey(keys.PurposeActionTokens)
	if err := reg.Put(k); err != nil {
		w.t.Fatal(err)
	}
	s, err := reg.Signer(keys.PurposeActionTokens)
	if err != nil {
		w.t.Fatal(err)
	}
	w.auth.ActionTokens = s
}

func payload(t *testing.T, jws string) []byte {
	t.Helper()
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %q", jws)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestHR188_BeginDispatchRecordsTheOutboundRequestAndItsToken: in
// PostgreSQL, the commit point records the method, URL and body hash on
// the permit and the id of the action token minted for a target-enforced
// connection; a refused mint leaves the permit ISSUED.
func TestHR188_BeginDispatchRecordsTheOutboundRequestAndItsToken(t *testing.T) {
	w := newWorld(t)
	w.refundable("ch_1")
	g := w.grant("500")
	run := w.run(g.ID, ids.UUID{})
	conn := w.withAccess(pipeline.ModeEnforce, finalize.AccessTargetEnforced)
	w.actionTokens()
	ctx := context.Background()

	res := w.authorize(w.through(conn, run, "ch_1", "30.00"))
	if !res.Decision.Permits() {
		t.Fatalf("authorize: %s (%s)", res.Decision, decisive(res))
	}
	if _, err := w.auth.BeginDispatch(ctx, w.gw, res.PermitID, res.Epoch, finalize.Outbound{}); !errors.Is(err, finalize.ErrOutboundRequired) {
		t.Fatalf("no body hash: %v", err)
	}
	if st := w.scalar("SELECT state FROM pc.permits WHERE id = $1", res.PermitID); st != "ISSUED" {
		t.Fatalf("a refused mint left the permit %s", st)
	}
	body := []byte(`{"amount":"30.00","charge":"ch_1","currency":"USD","reason":"duplicate"}`)
	sum := sha256.Sum256(body)
	out := finalize.Outbound{Method: "POST", URL: "https://payments.example.test/v1/refunds", BodySHA256: sum[:]}
	tok, err := w.auth.BeginDispatch(ctx, w.gw, res.PermitID, res.Epoch, out)
	if err != nil || tok == "" {
		t.Fatalf("begin dispatch: %q %v", tok, err)
	}
	var claims struct {
		Aud string `json:"aud"`
		Jti string `json:"jti"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
		Pap struct {
			Txn    string `json:"txn"`
			BH     string `json:"bh"`
			Target struct {
				ID string `json:"id"`
			} `json:"target"`
		} `json:"pap"`
	}
	if err := json.Unmarshal(payload(t, tok), &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Aud != conn.String() || claims.Exp-claims.Iat > 60 || claims.Pap.BH != hex.EncodeToString(sum[:]) ||
		claims.Pap.Txn != res.TransactionID.String() || claims.Pap.Target.ID != "ch_1" {
		t.Fatalf("token %+v", claims)
	}
	got := w.scalar(`SELECT outbound_method || ' ' || outbound_url || ' ' || encode(outbound_body_sha256, 'hex') || ' ' || action_token_jti::text
		FROM pc.permits WHERE id = $1`, res.PermitID)
	if got != "POST https://payments.example.test/v1/refunds "+hex.EncodeToString(sum[:])+" "+claims.Jti {
		t.Fatalf("permit records %q", got)
	}
	if _, err := w.auth.RecordExecution(ctx, w.gw, finalize.Execution{Permit: res.PermitID, Outcome: finalize.Accepted, TargetStatus: 200}); err != nil {
		t.Fatal(err)
	}
	if am := w.scalar("SELECT access_mode FROM pc.execution_attempts WHERE permit_id = $1", res.PermitID); am != "target_enforced" {
		t.Fatalf("attempt access mode %q", am)
	}
}

// TestHR186_DelegatedSettlesOnlyCooperativeChannelsInPostgres: an sdk
// action records delegated with agent_held and commits its reservation;
// delegated on mcp is refused and changes nothing.
func TestHR186_DelegatedSettlesOnlyCooperativeChannelsInPostgres(t *testing.T) {
	w := newWorld(t)
	w.refundable("ch_1", "ch_2")
	g := w.grant("500")
	run := w.run(g.ID, ids.UUID{})
	ctx := context.Background()

	req := w.request(run, ids.NewV7(), "ch_1", "30.00")
	a := req.Action.Action
	a.Channel = "sdk"
	p, err := actionir.Encode(a)
	if err != nil {
		t.Fatal(err)
	}
	req.Action = p
	res := w.authorize(req)
	if _, err := w.auth.BeginDispatch(ctx, w.gw, res.PermitID, res.Epoch, finalize.Outbound{}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.auth.RecordExecution(ctx, w.gw, finalize.Execution{Permit: res.PermitID, Outcome: finalize.Delegated, DispatchMS: -1}); err != nil {
		t.Fatal(err)
	}
	if got := w.scalar(`SELECT a.outcome || '/' || a.access_mode || '/' || p.state FROM pc.execution_attempts a
		JOIN pc.permits p ON p.org_id = a.org_id AND p.id = a.permit_id WHERE a.permit_id = $1`, res.PermitID); got != "delegated/agent_held/DISPATCHED" {
		t.Fatalf("delegated records %q", got)
	}
	w.settle()
	if spent := w.scalar("SELECT coalesce(sum(spent), 0)::text FROM pc.budget_accounts"); spent == "0" || spent == "0.00000000" {
		t.Fatal("a delegated action did not commit its reservation")
	}

	mcp := w.authorize(w.request(run, ids.NewV7(), "ch_2", "30.00"))
	if _, err := w.auth.BeginDispatch(ctx, w.gw, mcp.PermitID, mcp.Epoch, finalize.Outbound{}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.auth.RecordExecution(ctx, w.gw, finalize.Execution{Permit: mcp.PermitID, Outcome: finalize.Delegated}); !errors.Is(err, finalize.ErrNotCooperative) {
		t.Fatalf("delegated on mcp: %v", err)
	}
	if st := w.scalar("SELECT state FROM pc.permits WHERE id = $1", mcp.PermitID); st != "DISPATCHING" {
		t.Fatalf("a refused delegated left the permit %s", st)
	}
}
