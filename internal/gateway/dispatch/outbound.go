// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"log/slog"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/outbound"
	"github.com/katocxl/pantherclaw/internal/gateway/simcheck"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

const (
	// CodeSimulatorUnverified: a simulated connection's target did not
	// answer the simulator handshake, or its base URL is not a loopback or
	// private IP literal; nothing was sent to it (HR-221).
	CodeSimulatorUnverified = simcheck.Code
	// CodeSecretInPayload: the action carries a secret the gateway holds;
	// nothing was sent (HR-225).
	CodeSecretInPayload = "secret_in_payload"
)

// simulatorRefusal verifies a simulated connection's target before anything
// is sent to it (HR-221). It returns "" for a real connection or a verified
// simulator.
func (e *Engine) simulatorRefusal(ctx context.Context, conn *control.Connection) string {
	if !conn.GetSimulated() {
		return ""
	}
	switch conn.GetKind() {
	case "local":
		return "" // no target to send to
	case "postgres":
		return e.pgSimVerify(ctx, conn) // D110
	case "http", "mcp", "a2a":
		// An a2a simulator answers the handshake at its interface URL
		// (G0 M14 D100); a postgres target has no HTTP handshake, so a
		// simulated one stays unverified (fail closed).
		ce, err := e.entry(conn)
		if err != nil {
			return CodeSimulatorUnverified
		}
		if err := e.sims.Verify(ctx, conn.GetId(), conn.GetBaseUrl(), ce.client); err != nil {
			e.log.WarnContext(ctx, "gateway.simulator_unverified", slog.String("connection_id", conn.GetId()), slog.String("reason", err.Error()))
			return CodeSimulatorUnverified
		}
		return ""
	}
	return CodeSimulatorUnverified
}

// outboundCheck scans the action's payload (HR-225): a secret the gateway
// holds for the connection refuses it; credential-shaped values come back
// as findings for the Authority, which can only add a requirement for them.
func (e *Engine) outboundCheck(ctx context.Context, conn *control.Connection, a actionir.ActionIR) (refused bool, findings []*pb.PayloadFinding) {
	var held [][]byte
	if secret, err := e.openStatic(ctx, conn); err == nil {
		defer clear(secret)
		held = append(held, secret)
	} else if conn.Credential != nil {
		// Nothing to compare against (an App key is never opened here); the
		// error names no value.
		e.log.DebugContext(ctx, "gateway.held_secret_unavailable", slog.String("connection_id", conn.GetId()), pclog.Err(err))
	}
	res := outbound.Scan(outbound.Input{Args: a.Params, Path: a.Target.ID}, held)
	if res.HeldSecret {
		e.log.WarnContext(ctx, "gateway.secret_in_payload", slog.String("connection_id", conn.GetId()), slog.String("run_id", a.RunID), slog.String("operation", a.Operation))
		e.reportLocalRefusal(ctx, conn, CodeSecretInPayload, a, RefusalDetail{})
		return true, nil
	}
	for _, f := range res.Findings {
		findings = append(findings, &pb.PayloadFinding{Kind: f.Kind, Location: f.Location})
	}
	return false, findings
}

// reportLocalRefusal tells the server of a local refusal, so M10's
// detections see it (G0 M12): the connection, the code, the operation and
// the run, never the payload or the secret. The refusal stands whatever
// the report does; a report that fails is only logged.
func (e *Engine) reportLocalRefusal(ctx context.Context, conn *control.Connection, code string, a actionir.ActionIR, detail RefusalDetail) {
	if e.localRefusals == nil {
		return
	}
	operation, run := a.Operation, a.RunID
	if !actionir.ValidOperation(operation) {
		operation = ""
	}
	if _, err := ids.ParseUUID(run); err != nil {
		run = ""
	}
	if err := e.localRefusals(context.WithoutCancel(ctx), conn.GetId(), code, operation, run, detail); err != nil {
		e.log.WarnContext(ctx, "gateway.local_refusal_not_reported", slog.String("connection_id", conn.GetId()),
			slog.String("code", code), pclog.Err(err))
	}
}
