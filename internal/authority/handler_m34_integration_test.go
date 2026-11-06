// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package authority_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/authority"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	runsapp "github.com/katocxl/pantherclaw/internal/runs/app"
)

const (
	m34Account = "123456789012"
	m34Target  = "agentcore:arn:aws:bedrock-agentcore:us-east-1:" + m34Account + ":gateway/orders-gw/orders"
)

// m34Issuer inserts an active issuer revision of kind for the fixture's
// agent, bound to account (aws_iam only), with the fixture's grant as its
// run grant, and returns its revision and entry ids.
func (f fixture) m34Issuer(t *testing.T, kind, account string) (rev, entry ids.UUID) {
	t.Helper()
	rev, entry = ids.NewV7(), ids.NewV7()
	issuer, binding := issuers.AWSIssuer, map[string]any{"aws": map[string]string{"account_id": account, "role_name": "interceptor"}}
	if kind != "aws_iam" {
		issuer, binding = "https://accounts.google.com", map[string]any{"gcp": map[string]string{"project_id": "my-project"}}
	}
	b, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	g := f.grant.UUID()
	f.exec(t, `INSERT INTO pc.trusted_issuers (org_id, id, entry_id, revision, agent_id, kind, issuer, audience, algorithms,
		binding, state, proposed_by, activated_by, activated_at, run_grant_id) VALUES ($1, $2, $3, 1, $4, $5, $6, $7,
		'{RS256}', $8, 'ACTIVE', 'test', 'test', now(), $9)`,
		f.gw.Org, rev, entry, f.wl.inst.Agent, kind, issuer, "pantherclaw:"+f.gw.Org.String(), b, g)
	return rev, entry
}

// m34Run starts a run of the fixture's instance launched by the issuer
// revision, as StartRuntimeRun does.
func (f fixture) m34Run(t *testing.T, rev, entry ids.UUID) ids.UUID {
	t.Helper()
	var run runsapp.Run
	if err := f.pool.InTenantTx(context.Background(), f.gw.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		run, err = f.runs.StartForWorkloadTx(ctx, tx, runsapp.WorkloadStart{
			Org: f.gw.Org, AgentID: f.wl.inst.Agent, Instance: f.wl.inst.Instance, IssuerRevision: rev, IssuerEntry: entry,
			RunGrant: f.grant.UUID(), PodName: "agentcore:interceptor:stream-1", Runtime: true,
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return run.ID
}

// m34RuntimeAction is a refund on run with channel runtime, as the gateway's
// runtime face maps it.
func (f fixture) m34RuntimeAction(t *testing.T, run ids.UUID) []byte {
	t.Helper()
	p, err := actionir.Parse(f.action(t, "10.00", run, ids.NewV7()))
	if err != nil {
		t.Fatal(err)
	}
	a := p.Action
	a.Channel = "runtime"
	out, err := actionir.Encode(a)
	if err != nil {
		t.Fatal(err)
	}
	return out.Canonical
}

// TestHR765_TheAuthorityRefusesARuntimeActionOfAnotherAccount: over the
// gateway RPC, a runtime action passes the account check only when its
// connection's runtime target names an AgentCore gateway in the AWS account
// that the aws_iam issuer entry launching its run is bound to; another
// account, an issuer of another kind, a connection without a runtime target
// and a run a person started are CANNOT_AUTHORIZE RUNTIME_ACCOUNT_MISMATCH
// with the agent-safe sentence, before the pipeline: no transaction (G0 M34
// D994a).
//
// Covers: F1040, HR-765, T-346
func TestHR765_TheAuthorityRefusesARuntimeActionOfAnotherAccount(t *testing.T) {
	f := setupIdentity(t)
	f.exec(t, "UPDATE pc.connections SET runtime_target = $3 WHERE org_id = $1 AND id = $2", f.gw.Org, f.conn, m34Target)
	h := authority.NewHandler(f.svc)
	ctx := authority.WithGateway(context.Background(), f.gw)
	authorize := func(raw []byte) *pantherclawv1.AuthorizeResponse {
		t.Helper()
		c := f.creds(t, f.wl, f.wl.token) //nolint:contextcheck // the fixture's nonce read takes no context
		res, err := h.Authorize(ctx, &pantherclawv1.AuthorizeRequest{ActionIr: raw, Workload: &pantherclawv1.WorkloadCredentials{
			WorkloadToken: c.Token, Proof: c.Proof, BodySha256: c.BodySHA256[:], Htm: c.Method, Htu: c.URL,
		}})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	mismatch := func(what string, res *pantherclawv1.AuthorizeResponse) {
		t.Helper()
		rs := res.GetReasons()
		if res.GetDecision() != pantherclawv1.Decision_DECISION_CANNOT_AUTHORIZE || len(rs) != 1 ||
			rs[0].GetCode() != authority.ReasonRuntimeAccountMismatch || res.GetTransactionId() != "" || res.GetPermit() != "" ||
			rs[0].GetDetail() != "PantherClaw refuses this tool call: the AgentCore gateway's AWS account does not match the account its interceptor proved." {
			t.Errorf("%s: %v", what, res)
		}
	}
	txns := func() int {
		return f.count(t, "SELECT count(*) FROM pc.transactions WHERE org_id = $1 AND channel = 'runtime'")
	}

	// The account the interceptor proved: the pipeline decides.
	rev, entry := f.m34Issuer(t, "aws_iam", m34Account)
	run := f.m34Run(t, rev, entry)
	res := authorize(f.m34RuntimeAction(t, run))
	for _, r := range res.GetReasons() {
		if r.GetCode() == authority.ReasonRuntimeAccountMismatch {
			t.Fatalf("the matching account: %v", res)
		}
	}
	if res.GetTransactionId() == "" {
		t.Fatalf("the matching account was not decided by the pipeline: %v", res)
	}
	decided := txns()

	other, otherEntry := f.m34Issuer(t, "aws_iam", "210987654321")
	mismatch("another account", authorize(f.m34RuntimeAction(t, f.m34Run(t, other, otherEntry))))
	gcp, gcpEntry := f.m34Issuer(t, "gcp_workload", "")
	mismatch("a gcp_workload issuer", authorize(f.m34RuntimeAction(t, f.m34Run(t, gcp, gcpEntry))))
	mismatch("a run a person started", authorize(f.m34RuntimeAction(t, f.run)))
	f.exec(t, "UPDATE pc.connections SET runtime_target = NULL WHERE org_id = $1 AND id = $2", f.gw.Org, f.conn)
	mismatch("a connection without a runtime target", authorize(f.m34RuntimeAction(t, run)))
	if n := txns(); n != decided {
		t.Errorf("%d runtime transactions after the refusals, want %d", n, decided)
	}

	// Another channel never meets the check.
	res = authorize(f.action(t, "10.00", f.run, ids.NewV7()))
	for _, r := range res.GetReasons() {
		if r.GetCode() == authority.ReasonRuntimeAccountMismatch {
			t.Fatalf("an mcp action: %v", res)
		}
	}
}
