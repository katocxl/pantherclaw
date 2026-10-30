// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// Fleet cohort commands (G0 M11 part 2, D40, HR-291): group agents by
// static membership or a rule, give the group an owner and a grant
// baseline, and read its queue, its changes and the fleet overview.
// Cohorts organize only; they grant nothing. Team edition.

func init() {
	commands["cohort"] = group("cohort", cohortCommands())
	commands["fleet"] = group("fleet", map[string]command{
		"overview": rpc("fleet overview [--page-size N] [--page-token T]", 0, func(fs *flag.FlagSet) call {
			size := fs.Int("page-size", 0, "agents per page (at most 200)")
			token := fs.String("page-token", "", "the next page's token")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.cohorts.GetFleetOverview(ctx, &pantherclawv1.GetFleetOverviewRequest{PageSize: int32(*size), PageToken: *token}) //nolint:gosec // validated by the server
			}
		}),
	})
}

// cohortInputFlags are a cohort's content flags.
func cohortInputFlags(fs *flag.FlagSet) func(name string) (*pantherclawv1.FleetCohortInput, error) {
	desc := fs.String("description", "", "what the cohort is for")
	owner := fs.String("owner", "", "the owner's user id")
	team := fs.String("rule-team", "", "rule: agents of this team")
	env := fs.String("rule-environment", "", "rule: agents in this environment")
	task := fs.String("rule-task-type", "", "rule: agents of this task type")
	baseline := fs.String("baseline-file", "", "a grant baseline, JSON {bounds, limits, ttl_seconds}")
	return func(name string) (*pantherclawv1.FleetCohortInput, error) {
		if *owner == "" {
			return nil, fmt.Errorf("--owner is required")
		}
		in := &pantherclawv1.FleetCohortInput{Name: name, Description: *desc, OwnerUserId: *owner}
		if *team != "" || *env != "" || *task != "" {
			in.Rule = &pantherclawv1.FleetCohortRule{TeamId: *team, EnvironmentId: *env, TaskType: *task}
		}
		if *baseline != "" {
			b, err := os.ReadFile(*baseline)
			if err != nil {
				return nil, err
			}
			in.Baseline = b
		}
		return in, nil
	}
}

func cohortCommands() map[string]command {
	members := func(remove bool) func(fs *flag.FlagSet) call {
		return func(fs *flag.FlagSet) call {
			var agents list
			fs.Var(&agents, "agent", "an agent id (repeatable)")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				if len(agents) == 0 {
					return nil, fmt.Errorf("--agent is required")
				}
				if remove {
					return c.cohorts.RemoveFleetCohortMembers(ctx, &pantherclawv1.RemoveFleetCohortMembersRequest{CohortId: a[0], AgentIds: agents})
				}
				return c.cohorts.AddFleetCohortMembers(ctx, &pantherclawv1.AddFleetCohortMembersRequest{CohortId: a[0], AgentIds: agents})
			}
		}
	}
	return map[string]command{
		"create": rpc("cohort create NAME --owner USER_ID [--description D] [--rule-team ID] [--rule-environment ID] [--rule-task-type T] "+
			"[--baseline-file FILE]", 1, func(fs *flag.FlagSet) call {
			in := cohortInputFlags(fs)
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				cohort, err := in(a[0])
				if err != nil {
					return nil, err
				}
				return c.cohorts.CreateFleetCohort(ctx, &pantherclawv1.CreateFleetCohortRequest{Cohort: cohort})
			}
		}),
		"update": rpc("cohort update COHORT_ID NAME --owner USER_ID [--description D] [--rule-team ID] [--rule-environment ID] "+
			"[--rule-task-type T] [--baseline-file FILE] (replaces everything)", 2, func(fs *flag.FlagSet) call {
			in := cohortInputFlags(fs)
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				cohort, err := in(a[1])
				if err != nil {
					return nil, err
				}
				return c.cohorts.UpdateFleetCohort(ctx, &pantherclawv1.UpdateFleetCohortRequest{CohortId: a[0], Cohort: cohort})
			}
		}),
		"delete": rpc("cohort delete COHORT_ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.cohorts.DeleteFleetCohort(ctx, &pantherclawv1.DeleteFleetCohortRequest{CohortId: a[0]})
			}
		}),
		"show": rpc("cohort show COHORT_ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.cohorts.GetFleetCohort(ctx, &pantherclawv1.GetFleetCohortRequest{CohortId: a[0]})
			}
		}),
		"list": rpc("cohort list [--page-size N] [--page-token T]", 0, func(fs *flag.FlagSet) call {
			size := fs.Int("page-size", 0, "cohorts per page (at most 200)")
			token := fs.String("page-token", "", "the next page's token")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.cohorts.ListFleetCohorts(ctx, &pantherclawv1.ListFleetCohortsRequest{PageSize: int32(*size), PageToken: *token}) //nolint:gosec // validated by the server
			}
		}),
		"members": rpc("cohort members COHORT_ID [--page-size N] [--page-token T]", 1, func(fs *flag.FlagSet) call {
			size := fs.Int("page-size", 0, "agents per page (at most 200)")
			token := fs.String("page-token", "", "the next page's token")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.cohorts.ListFleetCohortMembers(ctx, &pantherclawv1.ListFleetCohortMembersRequest{
					CohortId: a[0], PageSize: int32(*size), PageToken: *token, //nolint:gosec // validated by the server
				})
			}
		}),
		"add":    rpc("cohort add COHORT_ID --agent ID...", 1, members(false)),
		"remove": rpc("cohort remove COHORT_ID --agent ID...", 1, members(true)),
		"task-type": rpc("cohort task-type AGENT_ID TASK_TYPE (\"\" clears it)", 2, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.cohorts.SetAgentTaskType(ctx, &pantherclawv1.SetAgentTaskTypeRequest{AgentId: a[0], TaskType: a[1]})
			}
		}),
		"queue": rpc("cohort queue COHORT_ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.cohorts.GetCohortQueue(ctx, &pantherclawv1.GetCohortQueueRequest{CohortId: a[0]})
			}
		}),
		"findings": rpc("cohort findings COHORT_ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.cohorts.GetCohortFindings(ctx, &pantherclawv1.GetCohortFindingsRequest{CohortId: a[0]})
			}
		}),
		"changes": rpc("cohort changes COHORT_ID [--since DURATION] (default and at most 744h)", 1, func(fs *flag.FlagSet) call {
			since := fs.Duration("since", 0, "how far back")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				req := &pantherclawv1.GetCohortChangesRequest{CohortId: a[0]}
				if *since > 0 {
					req.Since = timestamppb.New(time.Now().Add(-*since))
				}
				return c.cohorts.GetCohortChanges(ctx, req)
			}
		}),
	}
}
