// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net/http"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// enforced is a scenario whose gateway serves one connection, every route
// enforced, with the given access mode, and can mint action tokens.
func enforced(t *testing.T, access string) (*pipelinetest.Scenario, ids.UUID, ids.UUID) {
	t.Helper()
	s := pipelinetest.NewScenario(t, nil)
	s.Authority.ActionTokens = pipelinetest.FakeSigner{}
	gw := ids.NewV7()
	s.Gateway.ID = gw.String()
	g := s.Grant(pipelinetest.RootBounds, s.Alice)
	run := s.Run(g.ID, s.Alice)
	conn := pipeline.Connection{
		ID: ids.NewV7(), Gateway: gw, Kind: "http", Package: "pc.mock-payments", State: "ACTIVE", AccessMode: access,
		DefaultMode: pipeline.ModeEnforce, Modes: map[string]string{},
	}
	s.W.PutConnection(conn)
	return s, run, conn.ID
}

func outbound(body string) finalize.Outbound {
	sum := sha256.Sum256([]byte(body))
	return finalize.Outbound{Method: http.MethodPost, URL: "https://payments.example.test/v1/refunds", BodySHA256: sum[:]}
}

type actionToken struct {
	Aud string `json:"aud"`
	Jti string `json:"jti"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Pap struct {
		V      int    `json:"v"`
		Txn    string `json:"txn"`
		Act    string `json:"act"`
		BH     string `json:"bh"`
		Op     string `json:"op"`
		Target struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"target"`
	} `json:"pap"`
}

// TestHR188_ActionTokensBindTheExactOutboundBody: for a target-enforced
// connection, BeginDispatch returns a token whose audience is the
// connection, which lives at most 60 seconds, has its own id, and binds the
// transaction, the effective action, the hash of the exact body, the
// operation and the target. Without the body hash nothing is minted and
// the permit stays unused.
func TestHR188_ActionTokensBindTheExactOutboundBody(t *testing.T) {
	s, run, conn := enforced(t, finalize.AccessTargetEnforced)
	ctx := context.Background()
	res := s.Authorize(throughConnection(t, s, run, conn, pipelinetest.Refund("ch_1", "30.00")))
	if !res.Decision.Permits() || res.AccessMode != finalize.AccessTargetEnforced {
		t.Fatalf("authorize: %s %s", res.Decision, res.AccessMode)
	}
	if _, err := s.Authority.BeginDispatch(ctx, s.Gateway, res.PermitID, res.Epoch, finalize.Outbound{}); !errors.Is(err, finalize.ErrOutboundRequired) {
		t.Fatalf("no outbound request: %v", err)
	}
	if _, err := s.Authority.BeginDispatch(ctx, s.Gateway, res.PermitID, res.Epoch,
		finalize.Outbound{Method: "POST", URL: "ftp://payments.example.test/x"}); !errors.Is(err, finalize.ErrOutbound) {
		t.Fatalf("a non-http URL: %v", err)
	}
	body := `{"amount":"30.00","charge":"ch_1","currency":"USD","reason":"duplicate"}`
	out := outbound(body)
	tok, err := s.Authority.BeginDispatch(ctx, s.Gateway, res.PermitID, res.Epoch, out)
	if err != nil || tok == "" {
		t.Fatalf("begin dispatch after a refused one: %q %v", tok, err)
	}
	var claims actionToken
	if err := json.Unmarshal(pipelinetest.Payload(tok), &claims); err != nil {
		t.Fatal(err)
	}
	p := claims.Pap
	if claims.Aud != conn.String() || claims.Exp-claims.Iat != 60 || claims.Jti == "" || p.V != 1 || p.Txn != res.TransactionID.String() ||
		p.Act != res.EffectiveHash || p.BH != hex.EncodeToString(out.BodySHA256) || p.Op != "payments.refund.create" ||
		p.Target.Type != "payments.charge" || p.Target.ID != "ch_1" {
		t.Fatalf("token claims %+v", claims)
	}
	d := s.W.Dispatch(res.PermitID)
	if d.TokenID == nil || d.TokenID.String() != claims.Jti || d.Outbound.URL != out.URL {
		t.Fatalf("recorded %+v", d)
	}
	if _, err := s.Authority.BeginDispatch(ctx, s.Gateway, res.PermitID, res.Epoch, out); !errors.Is(err, finalize.ErrPermitUsed) {
		t.Fatalf("a second BeginDispatch: %v", err)
	}
}

// TestHR188_OnlyTargetEnforcedConnectionsGetActionTokens: a
// pantherclaw_held connection's dispatch records the outbound request and
// gets no token.
func TestHR188_OnlyTargetEnforcedConnectionsGetActionTokens(t *testing.T) {
	s, run, conn := enforced(t, "pantherclaw_held")
	res := s.Authorize(throughConnection(t, s, run, conn, pipelinetest.Refund("ch_1", "30.00")))
	tok, err := s.Authority.BeginDispatch(context.Background(), s.Gateway, res.PermitID, res.Epoch, outbound("{}"))
	if err != nil || tok != "" {
		t.Fatalf("pantherclaw_held: %q %v", tok, err)
	}
	if d := s.W.Dispatch(res.PermitID); d.Outbound.Method != http.MethodPost || d.TokenID != nil {
		t.Fatalf("recorded %+v", d)
	}
}

// cooperative maps a refund as the /sdk face does for an SDK's call: through
// an agent-held http connection, on the sdk channel (HR-201).
func cooperative(t *testing.T, s *pipelinetest.Scenario, run ids.UUID) pipeline.Request {
	t.Helper()
	base, err := s.W.Connection(context.Background(), s.Org, s.Connection)
	if err != nil {
		t.Fatal(err)
	}
	held := ids.NewV7()
	s.W.PutConnection(pipeline.Connection{
		ID: held, Gateway: base.Gateway, Kind: "http", Package: base.Package, State: "ACTIVE", AccessMode: "agent_held",
		DefaultMode: pipeline.ModeEnforce, Modes: map[string]string{},
	})
	p, err := s.Mapper.MCP(context.Background(), mapping.Context{
		Org: s.Org.String(), Env: s.Env.String(), RunID: run.String(), ActionID: ids.NewV7().String(), AgentInstance: s.Instance.String(),
		Connection: held.String(),
	}, "create_refund", jsontext.Value(pipelinetest.Refund("ch_1", "30.00")))
	if err != nil {
		t.Fatal(err)
	}
	a := p.Action
	a.Channel = "sdk"
	p, err = actionir.Encode(a)
	if err != nil {
		t.Fatal(err)
	}
	return pipeline.Request{Org: s.Org, Action: p, Identity: pipeline.Identity{InstanceID: s.Instance, AgentID: s.Agent, AttestationLevel: 1, JKT: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"}}
}

type executionReceipt struct {
	Pap struct {
		Outcome    string `json:"outcome"`
		AccessMode string `json:"access_mode"`
		Monitor    bool   `json:"monitor"`
	} `json:"pap"`
}

// TestHR186_DelegatedIsForCooperativeChannelsOnly: a cooperative channel
// records delegated with access mode agent_held; a channel where the
// gateway dispatches cannot, and its receipt names its connection's access
// mode.
func TestHR186_DelegatedIsForCooperativeChannelsOnly(t *testing.T) {
	s := pipelinetest.NewScenario(t, nil)
	g := s.Grant(pipelinetest.RootBounds, s.Alice)
	run := s.Run(g.ID, s.Alice)
	ctx := context.Background()

	res := s.Authorize(cooperative(t, s, run))
	if !res.Decision.Permits() {
		t.Fatalf("sdk action: %s", res.Decision)
	}
	if _, err := s.Authority.BeginDispatch(ctx, s.Gateway, res.PermitID, res.Epoch, finalize.Outbound{}); err != nil {
		t.Fatal(err)
	}
	r, err := s.Authority.RecordExecution(ctx, s.Gateway, finalize.Execution{Permit: res.PermitID, Outcome: finalize.Delegated, DispatchMS: -1})
	if err != nil {
		t.Fatal(err)
	}
	var er executionReceipt
	if err := json.Unmarshal(pipelinetest.Payload(r), &er); err != nil || er.Pap.Outcome != "delegated" || er.Pap.AccessMode != "agent_held" {
		t.Fatalf("delegated receipt %+v %v", er.Pap, err)
	}
	if st := s.W.PermitState(res.PermitID); st != "DISPATCHED" {
		t.Fatalf("a delegated permit is %s", st)
	}

	gw := s.Authorize(s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund("ch_2", "30.00")))
	if _, err := s.Authority.BeginDispatch(ctx, s.Gateway, gw.PermitID, gw.Epoch, finalize.Outbound{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authority.RecordExecution(ctx, s.Gateway, finalize.Execution{Permit: gw.PermitID, Outcome: finalize.Delegated}); !errors.Is(err, finalize.ErrNotCooperative) {
		t.Fatalf("delegated on mcp: %v", err)
	}
	r, err = s.Authority.RecordExecution(ctx, s.Gateway, finalize.Execution{Permit: gw.PermitID, Outcome: finalize.Accepted, TargetStatus: 200})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(pipelinetest.Payload(r), &er); err != nil || er.Pap.AccessMode != "none" || er.Pap.Monitor {
		t.Fatalf("accepted receipt %+v %v", er.Pap, err)
	}
}

// TestHR184_ExecutionReceiptsOfMonitorPermitsSayMonitor: nothing a
// monitor-mode dispatch did is reported as prevented.
func TestHR184_ExecutionReceiptsOfMonitorPermitsSayMonitor(t *testing.T) {
	s, run, conn := monitored(t)
	ctx := context.Background()
	res := s.Authorize(throughConnection(t, s, run, conn, pipelinetest.Refund("ch_1", "500.00")))
	if _, err := s.Authority.BeginDispatch(ctx, s.Gateway, res.PermitID, res.Epoch, outbound("{}")); err != nil {
		t.Fatal(err)
	}
	r, err := s.Authority.RecordExecution(ctx, s.Gateway, finalize.Execution{Permit: res.PermitID, Outcome: finalize.Accepted, TargetStatus: 200})
	if err != nil {
		t.Fatal(err)
	}
	var er executionReceipt
	if err := json.Unmarshal(pipelinetest.Payload(r), &er); err != nil || !er.Pap.Monitor || er.Pap.AccessMode != "pantherclaw_held" {
		t.Fatalf("monitor execution receipt %+v %v", er.Pap, err)
	}
}
