// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package authority

import (
	"context"
	"regexp"
	"strings"

	"github.com/katocxl/pantherclaw/internal/actionir"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// The runtime channel's account check (G0 M34 D994a, HR-765, server half): a
// cloud agent runtime's gateway is decided through a connection only when
// the AWS account of the AgentCore gateway its runtime target names is the
// account the interceptor proved by aws_iam attestation. It runs before the
// pipeline, as the authzen refusal does, so a refused action reserves
// nothing and starts no transaction.

// ReasonRuntimeAccountMismatch refuses a runtime action whose connection has
// no runtime target, whose run was not launched by an aws_iam issuer entry,
// or whose entry's account is not the target gateway's.
const ReasonRuntimeAccountMismatch = "RUNTIME_ACCOUNT_MISMATCH"

// runtimeAccountDetail is the agent-safe reason (D994a).
const runtimeAccountDetail = "PantherClaw refuses this tool call: the AgentCore gateway's AWS account does not match the account its interceptor proved."

// channelRuntime is a cloud agent runtime gateway's channel (D990).
const channelRuntime = "runtime"

// issuerKindAWS is the aws_iam attestation preset.
const issuerKindAWS = "aws_iam"

var awsAccountRe = regexp.MustCompile(`^[0-9]{12}$`)

// RuntimeAccounts reads what the check needs; the Authority's store
// implements it.
type RuntimeAccounts interface {
	RuntimeAccount(ctx context.Context, org ids.OrgID, connection, run ids.UUID) (target, issuerKind, issuerAccount string, found bool, err error)
}

// runtimeTargetAccount is the 12-digit account of the gateway ARN in an
// AgentCore runtime target ("agentcore:arn:<partition>:bedrock-agentcore:
// <region>:<account>:gateway/<id>/<target>"); "" when it names none.
func runtimeTargetAccount(target string) string {
	arn, ok := strings.CutPrefix(target, "agentcore:")
	if !ok {
		return ""
	}
	f := strings.SplitN(arn, ":", 6)
	if len(f) != 6 || f[0] != "arn" || f[2] != "bedrock-agentcore" || !strings.HasPrefix(f[5], "gateway/") || !awsAccountRe.MatchString(f[4]) {
		return ""
	}
	return f[4]
}

// refusedRuntime answers a gateway's Authorize of a runtime action that
// fails the account check: CANNOT_AUTHORIZE RUNTIME_ACCOUNT_MISMATCH. It
// returns nil for any other channel, for an action that passes, and for a
// body that does not parse (the Service refuses it as before).
func (h *Handler) refusedRuntime(ctx context.Context, gw Gateway, raw []byte) (*pantherclawv1.AuthorizeResponse, error) {
	p, err := actionir.Parse(raw)
	if err != nil || p.Action.Channel != channelRuntime {
		return nil, nil
	}
	ok, err := h.runtimeAccountMatches(ctx, gw, p.Action)
	if err != nil {
		return nil, err
	}
	if ok {
		return nil, nil
	}
	return &pantherclawv1.AuthorizeResponse{
		Decision: pantherclawv1.Decision_DECISION_CANNOT_AUTHORIZE,
		Reasons: []*pantherclawv1.Reason{{
			Code: ReasonRuntimeAccountMismatch, Check: "scope", Decisive: true, Detail: runtimeAccountDetail,
		}},
	}, nil
}

func (h *Handler) runtimeAccountMatches(ctx context.Context, gw Gateway, a actionir.ActionIR) (bool, error) {
	ra, ok := h.svc.decider.Store.(RuntimeAccounts)
	if !ok {
		return false, nil // a store that cannot tell refuses (fail closed)
	}
	conn, err := ids.ParseUUID(a.Connection)
	if err != nil {
		return false, nil
	}
	run, err := ids.ParseUUID(a.RunID)
	if err != nil {
		return false, nil
	}
	target, kind, account, found, err := ra.RuntimeAccount(ctx, gw.Org, conn, run)
	if err != nil {
		return false, err
	}
	want := runtimeTargetAccount(target)
	return found && kind == issuerKindAWS && want != "" && awsAccountRe.MatchString(account) && account == want, nil
}
