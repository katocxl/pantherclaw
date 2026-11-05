// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"regexp"
	"strings"

	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// A connection's runtime target (G0 M34 D991, HR-762): the target of a cloud
// agent runtime's gateway whose tool calls the PantherClaw gateway's runtime
// face decides through the connection. Only an mcp connection whose
// credential the agent holds may have one, since the runtime's gateway
// calls the tool itself; a target names one live connection per org
// (migration 00381).

// RuntimeTargetAgentCore is the prefix of an AgentCore gateway target.
const RuntimeTargetAgentCore = "agentcore:"

var (
	// agentCoreGatewayARN is an AgentCore gateway's ARN.
	agentCoreGatewayARN = regexp.MustCompile(`^arn:aws[a-z-]*:bedrock-agentcore:[a-z0-9-]+:\d{12}:gateway/[A-Za-z0-9-]{1,100}$`)
	// agentCoreTargetName is a target's name within its gateway.
	agentCoreTargetName = regexp.MustCompile(`^[A-Za-z0-9-]{1,100}$`)
)

// Errors of the runtime target calls.
var (
	ErrRuntimeTarget = pcerr.New(pcerr.InvalidArgument, "RUNTIME_TARGET_INVALID",
		"a runtime target is agentcore:<AgentCore gateway ARN>/<target name>")
	ErrRuntimeTargetKind = pcerr.New(pcerr.FailedPrecondition, "RUNTIME_TARGET_CONNECTION",
		"only an mcp connection whose credential the agent holds can have a runtime target")
	ErrRuntimeTargetTaken = pcerr.New(pcerr.AlreadyExists, "RUNTIME_TARGET_TAKEN",
		"another connection of the organization already has this runtime target")
)

// ParseRuntimeTarget splits an AgentCore runtime target into its gateway ARN
// and target name, checking both.
func ParseRuntimeTarget(target string) (arn, name string, err error) {
	rest, ok := strings.CutPrefix(target, RuntimeTargetAgentCore)
	if !ok || len(target) > 512 {
		return "", "", ErrRuntimeTarget
	}
	i := strings.LastIndexByte(rest, '/')
	if i < 0 {
		return "", "", ErrRuntimeTarget
	}
	arn, name = rest[:i], rest[i+1:]
	if !agentCoreGatewayARN.MatchString(arn) || !agentCoreTargetName.MatchString(name) {
		return "", "", ErrRuntimeTarget
	}
	return arn, name, nil
}

// SetRuntimeTarget binds a live mcp, agent-held connection to a runtime
// target (connection.manage), replacing any earlier one (audit
// connection.runtime_target_set). Its gateway refetches its configuration.
func (s *Service) SetRuntimeTarget(ctx context.Context, id ids.UUID, target string) (Connection, error) {
	arn, name, err := ParseRuntimeTarget(target)
	if err != nil {
		return Connection{}, err
	}
	return s.setRuntimeTarget(ctx, id, &target, auditkind.ConnectionRuntimeTargetSet, map[string]string{
		"runtime_target": target, "gateway_arn": arn, "target_name": name,
	})
}

// ClearRuntimeTarget removes a connection's runtime target (connection.manage,
// audit connection.runtime_target_cleared): the runtime face then finds no
// connection for it.
func (s *Service) ClearRuntimeTarget(ctx context.Context, id ids.UUID) (Connection, error) {
	return s.setRuntimeTarget(ctx, id, nil, auditkind.ConnectionRuntimeTargetCleared, map[string]string{})
}

func (s *Service) setRuntimeTarget(ctx context.Context, id ids.UUID, target *string, event string, details map[string]string) (Connection, error) {
	c, err := s.caller(ctx, td.PermConnectionManage)
	if err != nil {
		return Connection{}, err
	}
	var out Connection
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		conn, err := lock(ctx, q, c.Org, id)
		if err != nil {
			return err
		}
		if target != nil {
			if conn.Kind != KindMCP || conn.AccessMode != AccessAgentHeld || conn.ModelRelay {
				return ErrRuntimeTargetKind
			}
			other, err := q.ConnectionByRuntimeTarget(ctx, c.Org, *target)
			if err == nil && other.ID != conn.ID {
				return ErrRuntimeTargetTaken
			} else if err != nil && !db.IsNoRows(err) {
				return err
			}
		}
		if old := deref(conn.RuntimeTarget); old != "" {
			details["runtime_target_old"] = old
		}
		after, err := q.SetConnectionRuntimeTarget(ctx, dbq.SetConnectionRuntimeTargetParams{
			RuntimeTarget: target, UpdatedBy: c.By, OrgID: c.Org, ID: conn.ID,
		})
		if db.IsNoRows(err) {
			return ErrState
		} else if err != nil {
			return err
		}
		if _, err := q.BumpGatewayConfig(ctx, c.Org, after.GatewayID); err != nil {
			return err
		}
		if err := record(ctx, tx, c, event, after.ID, details); err != nil {
			return err
		}
		out, err = load(ctx, q, after)
		return err
	})
	return out, err
}
