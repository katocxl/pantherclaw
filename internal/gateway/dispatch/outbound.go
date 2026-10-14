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
	case "http", "mcp":
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
	if secret, err := e.openStatic(conn); err == nil {
		defer clear(secret)
		held = append(held, secret)
	}
	res := outbound.Scan(outbound.Input{Args: a.Params, Path: a.Target.ID}, held)
	if res.HeldSecret {
		e.log.WarnContext(ctx, "gateway.secret_in_payload", slog.String("connection_id", conn.GetId()), slog.String("run_id", a.RunID), slog.String("operation", a.Operation))
		return true, nil
	}
	for _, f := range res.Findings {
		findings = append(findings, &pb.PayloadFinding{Kind: f.Kind, Location: f.Location})
	}
	return false, findings
}
