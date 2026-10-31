// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"encoding/json/v2"
	"log/slog"
	"slices"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/ecsfacts"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// ecsServiceRead is the DescribeServices read of pc.aws.ecs.
const ecsServiceRead = "aws.ecs.service.read"

// needsECSFacts reports whether def's prerequisites name the service's
// deployment controller.
func needsECSFacts(def *defs.Definition) bool {
	return slices.ContainsFunc(def.Prerequisites, func(p defs.Prerequisite) bool { return p.Fact == ecsfacts.ServiceController })
}

// reportECSFacts reads aws.ecs.service.controller for an action's service,
// in a session narrowed to DescribeServices, within the fact timeout, and
// reports it before the decision (G0 M20 D284, HR-160). What it could not
// read is reported unread, so the server counts the fact missing. It reports
// whether it tried, and unreported when the report itself failed (as
// reportSlackFacts).
func (e *Engine) reportECSFacts(ctx context.Context, conn *control.Connection, a actionir.ActionIR) (tried bool, unreported error) {
	if e.reportFacts == nil || conn.Package == nil || conn.GetKind() != "http" {
		return false, nil
	}
	def, ok := conn.Package.Definition(a.Operation)
	if !ok || !needsECSFacts(def) {
		return false, nil
	}
	read, cancel := context.WithTimeout(ctx, e.factTimeout)
	defer cancel()
	raw, err := json.Marshal(map[string]any{"object": e.readECSController(read, conn, a.Target)}, json.Deterministic(true))
	if err != nil {
		return true, nil
	}
	obs := []*pb.FactObservation{{
		Name: ecsfacts.ServiceController, SubjectType: a.Target.Type, SubjectId: a.Target.ID, Value: raw, ObserveTime: timestamppb.New(time.Now()),
	}}
	if err := e.reportFacts(ctx, conn.GetId(), obs); err != nil {
		e.log.WarnContext(ctx, "gateway.facts_not_reported", slog.String("connection_id", conn.GetId()), slog.String("operation", a.Operation),
			pclog.Err(err))
		return true, err
	}
	return true, nil
}

// readECSController is the fact's value for target; any failure is unread.
func (e *Engine) readECSController(ctx context.Context, conn *control.Connection, target actionir.Target) map[string]any {
	read, ok := conn.Package.Definition(ecsServiceRead)
	if !ok || !read.Target.MatchID(target.ID) {
		return ecsfacts.Unread("not an ECS service")
	}
	status, body, ok := e.read(ctx, conn, read, actionir.Target{Type: target.Type, ID: target.ID}, nil)
	if !ok {
		return ecsfacts.Unread("the service could not be read")
	}
	return ecsfacts.Parse(status, body)
}
