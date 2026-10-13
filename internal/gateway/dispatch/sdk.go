// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"crypto/sha256"
	"log/slog"
	"strings"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Delegated is the exact request an SDK sends itself to a target-enforced
// connection: the gateway's re-serialization of the action (HR-075) and
// the action token whose bh binds its body (HR-188, HR-201). The SDK sends
// it unchanged.
type Delegated struct {
	Method, URL string
	Headers     map[string]string
	Body        []byte
	ActionToken string
}

// cooperative reports whether a call comes from a cooperative SDK (the
// /sdk face), whose agent performs the action itself (HR-186).
func cooperative(c Call) bool { return c.Action.Action.Channel == string(defs.ChannelSDK) }

// delegateSDK commits and records an SDK call the agent performs itself
// (HR-186, HR-201). On a target-enforced connection the gateway builds the
// outbound request from the action and the definition's template, reports
// its body hash at BeginDispatch so the action token binds exactly those
// bytes, and hands request and token to the agent; anywhere else it
// commits like the hook. Either way the gateway sends nothing, and the
// outcome is DELEGATED.
func (e *Engine) delegateSDK(ctx context.Context, r Result, conn *control.Connection, def *defs.Definition, a actionir.Parsed,
	want permitWant, t *timer,
) Result {
	if conn.GetAccessMode() != "target_enforced" {
		return e.delegate(ctx, r, want, t)
	}
	if conn.GetKind() != "http" {
		// Only an HTTP dispatch template gives bytes a token can bind.
		return r.fail(EnforcementFailed, CodeRequest)
	}
	out, err := egress.Build(conn.GetBaseUrl(), def, a.Action, want.Txn)
	if err != nil {
		e.log.WarnContext(ctx, "gateway.request_not_built", slog.String("transaction_id", want.Txn), pclog.Err(err))
		return r.fail(EnforcementFailed, CodeRequest)
	}
	sum := sha256.Sum256(out.Body)
	bd, err := e.authority.BeginDispatch(ctx, &pb.BeginDispatchRequest{
		PermitId: want.PermitID, Epoch: want.Epoch, OutboundMethod: out.Method, OutboundUrl: out.URL.String(), OutboundBodySha256: sum[:],
	})
	t.lap("begin")
	if err != nil {
		r.Reasons = append(r.Reasons, strings.ToUpper(connect.CodeOf(err).String()))
		return r.fail(EnforcementFailed, CodeDispatchRefused)
	}
	ctx = context.WithoutCancel(ctx)
	if bd.GetActionToken() == "" {
		// Committed, but the target would refuse the request: nothing is
		// sent, so the outcome is FAILED.
		return e.record(ctx, r, want, pb.Outcome_OUTCOME_FAILED, 0, nil, 0, EnforcementFailed, CodeRequest, t)
	}
	headers := map[string]string{HeaderAction: bd.GetActionToken()}
	if out.Body != nil {
		headers["Content-Type"] = "application/json"
	}
	if out.IdempotencyHeader != "" {
		headers[out.IdempotencyHeader] = out.IdempotencyKey
	}
	r.Delegated = &Delegated{Method: out.Method, URL: out.URL.String(), Headers: headers, Body: out.Body, ActionToken: bd.GetActionToken()}
	return e.record(ctx, r, want, pb.Outcome_OUTCOME_DELEGATED, 0, nil, 0, "", "", t)
}
