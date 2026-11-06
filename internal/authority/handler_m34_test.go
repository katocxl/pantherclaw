// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package authority

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// runtimeStore answers the runtime account check (D994a); nothing else of
// the store is reached on these paths.
type runtimeStore struct {
	finalize.Store
	target, kind, account string
	found                 bool
	err                   error
	asked                 int
}

func (r *runtimeStore) RuntimeAccount(_ context.Context, _ ids.OrgID, _, _ ids.UUID) (string, string, string, bool, error) {
	r.asked++
	return r.target, r.kind, r.account, r.found, r.err
}

const m34Target = "agentcore:arn:aws:bedrock-agentcore:us-east-1:111122223333:gateway/payments-gw-1/payments-target"

// TestHR765_TheAuthorityRefusesARuntimeAccountMismatch: an action on
// channel runtime passes the check only when its connection has a runtime
// target, its run was launched by an aws_iam issuer entry, and that entry's
// account is the target ARN's; anything else and a store that cannot tell
// are CANNOT_AUTHORIZE
// RUNTIME_ACCOUNT_MISMATCH before the pipeline, with the agent-safe
// sentence. Other channels are not checked.
func TestHR765_TheAuthorityRefusesARuntimeAccountMismatch(t *testing.T) {
	s := pipelinetest.NewScenario(t, nil)
	g := s.Grant(pipelinetest.RootBounds, s.Alice)
	req := s.Request(s.Run(g.ID, s.Alice), ids.NewV7(), "create_refund", pipelinetest.Refund("ch_1", "10.00"))
	encode := func(t *testing.T, channel string, edit func(*actionir.ActionIR)) []byte {
		t.Helper()
		a := req.Action.Action
		a.Channel = channel
		if edit != nil {
			edit(&a)
		}
		p, err := actionir.Encode(a)
		if err != nil {
			t.Fatal(err)
		}
		return p.Canonical
	}
	gw := Gateway{ID: s.Gateway.ID, Org: s.Org}
	ctx := WithGateway(context.Background(), gw)
	match := runtimeStore{target: m34Target, kind: "aws_iam", account: "111122223333", found: true}

	st := match
	h := NewHandler(&Service{decider: &finalize.Authority{Store: &st}})
	if out, err := h.refusedRuntime(ctx, gw, encode(t, "runtime", nil)); out != nil || err != nil || st.asked != 1 {
		t.Fatalf("matching account: %v %v (asked %d)", out, err, st.asked)
	}
	if out, err := h.refusedRuntime(ctx, gw, encode(t, "mcp", nil)); out != nil || err != nil || st.asked != 1 {
		t.Fatalf("an mcp action was checked: %v %v", out, err)
	}

	for name, tc := range map[string]struct {
		store finalize.Store
		edit  func(*actionir.ActionIR)
	}{
		"other account":    {&runtimeStore{target: m34Target, kind: "aws_iam", account: "444455556666", found: true}, nil},
		"no target":        {&runtimeStore{kind: "aws_iam", account: "111122223333", found: true}, nil},
		"not agentcore":    {&runtimeStore{target: "other:" + m34Target, kind: "aws_iam", account: "111122223333", found: true}, nil},
		"gcp issuer":       {&runtimeStore{target: m34Target, kind: "gcp_workload", account: "111122223333", found: true}, nil},
		"no issuer launch": {&runtimeStore{target: m34Target}, nil},
		"short account":    {&runtimeStore{target: m34Target, kind: "aws_iam", account: "", found: true}, nil},
		"store cannot":     {struct{ finalize.Store }{}, nil},
	} {
		h := NewHandler(&Service{decider: &finalize.Authority{Store: tc.store}})
		raw := encode(t, "runtime", tc.edit)
		res, err := h.Authorize(ctx, &pantherclawv1.AuthorizeRequest{ActionIr: raw})
		if err != nil || res.GetDecision() != pantherclawv1.Decision_DECISION_CANNOT_AUTHORIZE || res.GetTransactionId() != "" || res.GetPermit() != "" ||
			len(res.GetReasons()) != 1 || res.GetReasons()[0].GetCode() != ReasonRuntimeAccountMismatch || res.GetReasons()[0].GetDetail() != runtimeAccountDetail ||
			res.GetAgentExplanation().GetDecisiveCode() != ReasonRuntimeAccountMismatch {
			t.Errorf("%s: %v %v", name, res, err)
		}
	}

	// A store error is the caller's error, never a pass.
	bad := &runtimeStore{err: errors.New("db down")}
	h = NewHandler(&Service{decider: &finalize.Authority{Store: bad}})
	if out, err := h.refusedRuntime(ctx, gw, encode(t, "runtime", nil)); out != nil || err == nil {
		t.Fatalf("store error: %v %v", out, err)
	}
}

// TestHR765_RuntimeTargetAccount reads the 12-digit account of the gateway
// ARN in an AgentCore runtime target, and nothing from anything else.
func TestHR765_RuntimeTargetAccount(t *testing.T) {
	for in, want := range map[string]string{
		m34Target: "111122223333",
		"agentcore:arn:aws-us-gov:bedrock-agentcore:us-gov-west-1:123456789012:gateway/g/t": "123456789012",
		"arn:aws:bedrock-agentcore:us-east-1:111122223333:gateway/g/t":                      "",
		"agentcore:arn:aws:bedrock:us-east-1:111122223333:gateway/g/t":                      "",
		"agentcore:arn:aws:bedrock-agentcore:us-east-1:11112222333:gateway/g/t":             "",
		"agentcore:arn:aws:bedrock-agentcore:us-east-1:111122223333:runtime/g/t":            "",
		"agentcore:":     "",
		"":               "",
		"agentcore:arn:": "",
	} {
		if got := runtimeTargetAccount(in); got != want {
			t.Errorf("runtimeTargetAccount(%q) = %q, want %q", in, got, want)
		}
	}
}
