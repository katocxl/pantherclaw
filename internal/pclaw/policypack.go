// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// Reference pack commands (G0 M11 part 2, D41, HR-291): list the packs and
// apply one, which only drafts a policy version with its rules and tests
// and returns the agents' grant baselines; publishing, issuing and
// promoting stay separate steps. Team edition. They are "policy pack":
// "pack" is the evidence packs' (G0 M7).

func init() {
	commands["policy pack"] = group("policy pack", map[string]command{
		"list": rpc("policy pack list", 0, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.packs.ListPacks(ctx, &pantherclawv1.ListPacksRequest{})
			}
		}),
		"show": rpc("policy pack show NAME", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.packs.GetPack(ctx, &pantherclawv1.GetPackRequest{Name: a[0]})
			}
		}),
		"apply": rpc("policy pack apply NAME --environment ID [--agent ID... | --cohort ID] [--param KEY=VALUE]... "+
			"(params: repos, default_branch, workspace, time_zone, payees, customers, slack_channels; drafts only)", 1, func(fs *flag.FlagSet) call {
			env := fs.String("environment", "", "the environment id")
			var agents, params list
			fs.Var(&agents, "agent", "an agent id (repeatable)")
			cohort := fs.String("cohort", "", "a fleet cohort whose agents the pack is for")
			fs.Var(&params, "param", "a parameter, KEY=VALUE (repeatable)")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				if *env == "" {
					return nil, fmt.Errorf("--environment is required")
				}
				req := &pantherclawv1.ApplyPackRequest{Name: a[0], EnvironmentId: *env, AgentIds: agents, CohortId: *cohort, Parameters: map[string]string{}}
				for _, p := range params {
					k, v, ok := strings.Cut(p, "=")
					if !ok || k == "" {
						return nil, fmt.Errorf("--param %q is not KEY=VALUE", p)
					}
					req.Parameters[k] = v
				}
				return c.packs.ApplyPack(ctx, req)
			}
		}),
	})
}
