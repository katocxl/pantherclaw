// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"maps"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// Policy rollout commands (G0 M11.1, D12, D13): shadow a version, pilot it
// on cohorts of agents, follow each agent's status, and complete or cancel
// the rollout. Every change is made by a person holding policy.publish;
// shadow, pilots and cohorts need the Team edition.

func init() {
	commands["policy rollout"] = group("policy rollout", policyRolloutCommands())
	commands["policy cohort"] = group("policy cohort", policyCohortCommands())
	commands["policy shadow"] = group("policy shadow", policyShadowCommands())
}

// m11RolloutClients are the policy rollout service clients.
type m11RolloutClients struct {
	rollouts pantherclawv1connect.PolicyRolloutServiceClient
}

// shadowLabel is printed with every shadow result (D13).
const shadowLabel = "shadow prediction, not enforcement"

// group is a command whose first argument names one of subs.
func group(name string, subs map[string]command) command {
	verbs := slices.Sorted(maps.Keys(subs))
	return command{usage: name + " " + strings.Join(verbs, "|") + " ...", run: func(ctx context.Context, a *app, args []string) error {
		if len(args) == 0 {
			return errUsage
		}
		sub, ok := subs[args[0]]
		if !ok {
			return errUsage
		}
		err := sub.run(ctx, a, args[1:])
		if errors.Is(err, errUsage) {
			return &exitError{code: 2, msg: "usage: pclaw " + sub.usage}
		}
		return err
	}}
}

var targetStates = map[string]pantherclawv1.PolicyRolloutTargetState{
	"configured":   pantherclawv1.PolicyRolloutTargetState_POLICY_ROLLOUT_TARGET_STATE_CONFIGURED,
	"acknowledged": pantherclawv1.PolicyRolloutTargetState_POLICY_ROLLOUT_TARGET_STATE_ACKNOWLEDGED,
	"verified":     pantherclawv1.PolicyRolloutTargetState_POLICY_ROLLOUT_TARGET_STATE_VERIFIED,
	"failed":       pantherclawv1.PolicyRolloutTargetState_POLICY_ROLLOUT_TARGET_STATE_FAILED,
	"exception":    pantherclawv1.PolicyRolloutTargetState_POLICY_ROLLOUT_TARGET_STATE_EXCEPTION,
}

// waiting prints the change request a pilot or a completion waits for.
func waiting(a *app, cr *pantherclawv1.PolicyChangeRequestRef) {
	if cr != nil {
		_, _ = fmt.Fprintf(a.stderr, "waiting for confirmation: this version loosens the published policy; confirm it at %s\n", cr.GetUrl())
	}
}

func policyRolloutCommands() map[string]command {
	return map[string]command{
		"start": rpc("policy rollout start VERSION_ID [--shadow-cohort NAME]... (no cohort: every agent)", 1, func(fs *flag.FlagSet) call {
			var cohorts list
			fs.Var(&cohorts, "shadow-cohort", "a cohort whose agents' decisions are shadowed (repeatable)")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.rollouts.StartPolicyRollout(ctx, &pantherclawv1.StartPolicyRolloutRequest{VersionId: a[0], ShadowCohorts: cohorts})
			}
		}),
		"pilot": {usage: "policy rollout pilot ROLLOUT_ID --cohort NAME [--cohort NAME]...", run: func(ctx context.Context, a *app, args []string) error {
			return withCohorts(ctx, a, args, "policy rollout pilot", func(ctx context.Context, c clients, id string, cohorts []string) (proto.Message, error) {
				res, err := c.rollouts.StartPolicyPilot(ctx, &pantherclawv1.StartPolicyPilotRequest{RolloutId: id, Cohorts: cohorts})
				if err == nil {
					waiting(a, res.GetChangeRequest())
				}
				return res, err
			})
		}},
		"expand": {usage: "policy rollout expand ROLLOUT_ID --cohort NAME [--cohort NAME]...", run: func(ctx context.Context, a *app, args []string) error {
			return withCohorts(ctx, a, args, "policy rollout expand", func(ctx context.Context, c clients, id string, cohorts []string) (proto.Message, error) {
				return c.rollouts.ExpandPolicyPilot(ctx, &pantherclawv1.ExpandPolicyPilotRequest{RolloutId: id, Cohorts: cohorts})
			})
		}},
		"exclude": rpc("policy rollout exclude ROLLOUT_ID AGENT_ID --reason TEXT (the agent stays on the published version)", 2, func(fs *flag.FlagSet) call {
			reason := fs.String("reason", "", "why the agent is excluded (1 to 500 characters)")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				if strings.TrimSpace(*reason) == "" {
					return nil, fmt.Errorf("--reason is required")
				}
				return c.rollouts.ExcludePolicyRolloutTarget(ctx, &pantherclawv1.ExcludePolicyRolloutTargetRequest{
					RolloutId: a[0], AgentId: a[1], Reason: *reason,
				})
			}
		}),
		"complete": {usage: "policy rollout complete ROLLOUT_ID (publishes the version for everyone)", run: func(ctx context.Context, a *app, args []string) error {
			if len(args) != 1 {
				return errUsage
			}
			c, err := a.clients()
			if err != nil {
				return err
			}
			res, err := c.rollouts.CompletePolicyRollout(ctx, &pantherclawv1.CompletePolicyRolloutRequest{RolloutId: args[0]})
			if err != nil {
				return err
			}
			waiting(a, res.GetChangeRequest())
			return a.print(res)
		}},
		"cancel": rpc("policy rollout cancel ROLLOUT_ID (its agents return to the published version)", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.rollouts.CancelPolicyRollout(ctx, &pantherclawv1.CancelPolicyRolloutRequest{RolloutId: a[0]})
			}
		}),
		"show": {usage: "policy rollout show [ROLLOUT_ID] (none: list the rollouts)", run: func(ctx context.Context, a *app, args []string) error {
			if len(args) > 1 {
				return errUsage
			}
			c, err := a.clients()
			if err != nil {
				return err
			}
			var res proto.Message
			if len(args) == 1 {
				res, err = c.rollouts.GetPolicyRollout(ctx, &pantherclawv1.GetPolicyRolloutRequest{RolloutId: args[0]})
			} else {
				res, err = c.rollouts.ListPolicyRollouts(ctx, &pantherclawv1.ListPolicyRolloutsRequest{})
			}
			if err != nil {
				return err
			}
			return a.print(res)
		}},
		"targets": rpc("policy rollout targets ROLLOUT_ID [--state configured|acknowledged|verified|failed|exception] [--page-size N] [--page-token T]", 1,
			func(fs *flag.FlagSet) call {
				state := fs.String("state", "", "only targets in this state")
				n, token := paging(fs)
				return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
					st, ok := targetStates[*state]
					if *state != "" && !ok {
						return nil, fmt.Errorf("--state must be configured, acknowledged, verified, failed or exception")
					}
					return c.rollouts.ListPolicyRolloutTargets(ctx, &pantherclawv1.ListPolicyRolloutTargetsRequest{
						RolloutId: a[0], State: st, PageSize: size(n), PageToken: *token,
					})
				}
			}),
	}
}

// withCohorts runs a command that takes one id and repeated --cohort flags.
func withCohorts(ctx context.Context, a *app, args []string, usage string,
	fn func(ctx context.Context, c clients, id string, cohorts []string) (proto.Message, error),
) error {
	if len(args) < 1 {
		return errUsage
	}
	fs := flag.NewFlagSet(usage, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	var cohorts list
	fs.Var(&cohorts, "cohort", "a cohort whose agents are decided by the version (repeatable)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || len(cohorts) == 0 {
		return errUsage
	}
	c, err := a.clients()
	if err != nil {
		return err
	}
	res, err := fn(ctx, c, args[0], cohorts)
	if err != nil {
		return err
	}
	return a.print(res)
}

func policyCohortCommands() map[string]command {
	members := func(remove bool) func(fs *flag.FlagSet) call {
		return func(fs *flag.FlagSet) call {
			var agents list
			fs.Var(&agents, "agent", "an agent id (repeatable)")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				if len(agents) == 0 {
					return nil, fmt.Errorf("--agent is required")
				}
				if remove {
					return c.rollouts.RemovePolicyCohortMembers(ctx, &pantherclawv1.RemovePolicyCohortMembersRequest{Name: a[0], AgentIds: agents})
				}
				return c.rollouts.AddPolicyCohortMembers(ctx, &pantherclawv1.AddPolicyCohortMembersRequest{Name: a[0], AgentIds: agents})
			}
		}
	}
	return map[string]command{
		"create": rpc("policy cohort create NAME", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.rollouts.CreatePolicyCohort(ctx, &pantherclawv1.CreatePolicyCohortRequest{Name: a[0]})
			}
		}),
		"add":    rpc("policy cohort add NAME --agent ID [--agent ID]...", 1, members(false)),
		"remove": rpc("policy cohort remove NAME --agent ID [--agent ID]...", 1, members(true)),
		"list": rpc("policy cohort list", 0, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.rollouts.ListPolicyCohorts(ctx, &pantherclawv1.ListPolicyCohortsRequest{})
			}
		}),
	}
}

func policyShadowCommands() map[string]command {
	return map[string]command{
		"summary": {usage: "policy shadow summary ROLLOUT_ID (a " + shadowLabel + ")", run: func(ctx context.Context, a *app, args []string) error {
			if len(args) != 1 {
				return errUsage
			}
			c, err := a.clients()
			if err != nil {
				return err
			}
			res, err := c.rollouts.GetShadowSummary(ctx, &pantherclawv1.GetShadowSummaryRequest{RolloutId: args[0]})
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(a.stderr, "# "+shadowLabel)
			return a.print(res)
		}},
	}
}
