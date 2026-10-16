// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// Production promotion commands (G0 M11 part 2, D39, HR-290): readiness per
// operation, promotions and their revocation. A production grant needs a
// promotion for each operation it lists. Promoting needs a security-key
// step-up on a browser session, so pclaw shows readiness and lists or
// revokes promotions; the promotion itself is made in the browser.

func init() {
	commands["promote"] = group("promote", promoteCommands())
}

// m11GovernClients are the promotion, cohort and pack service clients.
type m11GovernClients struct {
	promotions pantherclawv1connect.PromotionServiceClient
	cohorts    pantherclawv1connect.CohortServiceClient
	packs      pantherclawv1connect.PackServiceClient
}

func governClients(c *connect.Client) m11GovernClients {
	return m11GovernClients{
		promotions: pantherclawv1connect.NewPromotionServiceClient(c),
		cohorts:    pantherclawv1connect.NewCohortServiceClient(c),
		packs:      pantherclawv1connect.NewPackServiceClient(c),
	}
}

var failureBehaviors = map[string]pantherclawv1.FailureBehavior{
	"fail-closed":       pantherclawv1.FailureBehavior_FAILURE_BEHAVIOR_FAIL_CLOSED,
	"queue":             pantherclawv1.FailureBehavior_FAILURE_BEHAVIOR_QUEUE,
	"degrade-read-only": pantherclawv1.FailureBehavior_FAILURE_BEHAVIOR_DEGRADE_READ_ONLY,
}

var promotionStates = map[string]pantherclawv1.PromotionState{
	"provisional": pantherclawv1.PromotionState_PROMOTION_STATE_PROVISIONAL,
	"expired":     pantherclawv1.PromotionState_PROMOTION_STATE_EXPIRED,
	"active":      pantherclawv1.PromotionState_PROMOTION_STATE_ACTIVE,
	"revoked":     pantherclawv1.PromotionState_PROMOTION_STATE_REVOKED,
}

func promoteCommands() map[string]command {
	return map[string]command{
		"readiness": rpc("promote readiness AGENT_ID ENVIRONMENT_ID [--operation OP]... [--failure-behavior fail-closed|queue|degrade-read-only]", 2,
			func(fs *flag.FlagSet) call {
				var ops list
				fs.Var(&ops, "operation", "an operation or a prefix such as payments.* (repeatable; none: those the agent's promotions, grants and coverage name)")
				fb := fs.String("failure-behavior", "", "the failure behavior to check as declared")
				return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
					req := &pantherclawv1.GetReadinessRequest{AgentId: a[0], EnvironmentId: a[1], Operations: ops}
					if *fb != "" {
						b, ok := failureBehaviors[*fb]
						if !ok {
							return nil, fmt.Errorf("--failure-behavior must be fail-closed, queue or degrade-read-only")
						}
						req.FailureBehavior = b
					}
					return c.promotions.GetReadiness(ctx, req)
				}
			}),
		"agent": rpc("promote agent AGENT_ID ENVIRONMENT_ID --operation OP... --failure-behavior fail-closed|queue|degrade-read-only "+
			"(needs a security-key step-up on a browser session)", 2, func(fs *flag.FlagSet) call {
			var ops list
			fs.Var(&ops, "operation", "an operation or a prefix such as payments.* (repeatable)")
			fb := fs.String("failure-behavior", "", "what the agent's work does when PantherClaw cannot decide")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				b, ok := failureBehaviors[*fb]
				switch {
				case len(ops) == 0:
					return nil, fmt.Errorf("--operation is required")
				case !ok:
					return nil, fmt.Errorf("--failure-behavior must be fail-closed, queue or degrade-read-only")
				}
				return c.promotions.PromoteAgent(ctx, &pantherclawv1.PromoteAgentRequest{
					AgentId: a[0], EnvironmentId: a[1], Operations: ops, FailureBehavior: b,
				})
			}
		}),
		"revoke": rpc("promote revoke PROMOTION_ID --reason TEXT (existing grants keep working until they expire)", 1, func(fs *flag.FlagSet) call {
			reason := fs.String("reason", "", "why (1 to 500 characters)")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				if strings.TrimSpace(*reason) == "" {
					return nil, fmt.Errorf("--reason is required")
				}
				return c.promotions.RevokePromotion(ctx, &pantherclawv1.RevokePromotionRequest{PromotionId: a[0], Reason: *reason})
			}
		}),
		"list": rpc("promote list [--agent ID] [--environment ID] [--state active|provisional|revoked|expired] [--page-size N] [--page-token T]", 0, func(fs *flag.FlagSet) call {
			agent := fs.String("agent", "", "only this agent's")
			env := fs.String("environment", "", "only in this environment")
			state := fs.String("state", "", "active, provisional, revoked or expired")
			size := fs.Int("page-size", 0, "results per page (at most 200)")
			token := fs.String("page-token", "", "the next page's token")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				req := &pantherclawv1.ListPromotionsRequest{AgentId: *agent, EnvironmentId: *env, PageSize: int32(*size), PageToken: *token} //nolint:gosec // validated by the server
				if *state != "" {
					s, ok := promotionStates[*state]
					if !ok {
						return nil, fmt.Errorf("--state must be active, provisional, revoked or expired")
					}
					req.State = s
				}
				return c.promotions.ListPromotions(ctx, req)
			}
		}),
	}
}
