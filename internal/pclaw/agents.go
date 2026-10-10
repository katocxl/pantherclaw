// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

var execContexts = map[string]pantherclawv1.ExecutionContext{
	"desktop":    pantherclawv1.ExecutionContext_EXECUTION_CONTEXT_DESKTOP,
	"ci":         pantherclawv1.ExecutionContext_EXECUTION_CONTEXT_CI,
	"kubernetes": pantherclawv1.ExecutionContext_EXECUTION_CONTEXT_KUBERNETES,
	"service":    pantherclawv1.ExecutionContext_EXECUTION_CONTEXT_SERVICE,
}

func execContext(s string) (pantherclawv1.ExecutionContext, error) {
	if c, ok := execContexts[strings.ToLower(s)]; ok {
		return c, nil
	}
	return 0, fmt.Errorf("--context must be desktop, ci, kubernetes or service")
}

// enumList parses a repeated enum flag ("claimed,verified") with prefix.
func enumList[E ~int32](values list, prefix string, names map[string]int32) ([]E, error) {
	var out []E
	for _, v := range values {
		for s := range strings.SplitSeq(v, ",") {
			n, ok := names[prefix+strings.ToUpper(strings.TrimSpace(s))]
			if !ok {
				return nil, fmt.Errorf("unknown state %q", s)
			}
			out = append(out, E(n))
		}
	}
	return out, nil
}

func optStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func agentCommands() map[string]command {
	return map[string]command{
		"agent create": rpc("agent create --name N --team ID --env ID --owner USER --context desktop|ci|kubernetes|service [--backup-owner USER] [--purpose P]", 0, func(fs *flag.FlagSet) call {
			name, purpose, team, env := fs.String("name", "", "display name"), fs.String("purpose", "", "what the agent is for"),
				fs.String("team", "", "team id"), fs.String("env", "", "environment id")
			owner, backup, ctxName := fs.String("owner", "", "owner user id"), fs.String("backup-owner", "", "backup owner user id"),
				fs.String("context", "", "where it runs (fixed for its life)")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				ec, err := execContext(*ctxName)
				if err != nil {
					return nil, err
				}
				return c.agents.CreateAgent(ctx, &pantherclawv1.CreateAgentRequest{
					Name: *name, Purpose: *purpose, TeamId: *team, EnvironmentId: *env, OwnerUserId: *owner,
					BackupOwnerUserId: optStr(*backup), ExecutionContext: ec,
				})
			}
		}),
		"agent get": rpc("agent get ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.agents.GetAgent(ctx, &pantherclawv1.GetAgentRequest{Id: a[0]})
			}
		}),
		"agent list": rpc("agent list [--state S,...] [--team ID]", 0, func(fs *flag.FlagSet) call {
			var states list
			fs.Var(&states, "state", "only these states (discovered, claimed, verified, observed, suspended, retired)")
			team := fs.String("team", "", "only this team")
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				st, err := enumList[pantherclawv1.AgentState](states, "AGENT_STATE_", pantherclawv1.AgentState_value)
				if err != nil {
					return nil, err
				}
				return c.agents.ListAgents(ctx, &pantherclawv1.ListAgentsRequest{PageSize: size(n), PageToken: *tok, States: st, TeamId: optStr(*team)})
			}
		}),
		"agent update": rpc("agent update ID [--name N] [--purpose P]", 1, func(fs *flag.FlagSet) call {
			var name, purpose optional
			fs.Var(&name, "name", "new display name")
			fs.Var(&purpose, "purpose", "new purpose")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.agents.UpdateAgent(ctx, &pantherclawv1.UpdateAgentRequest{Id: a[0], Name: name.ptr(), Purpose: purpose.ptr()})
			}
		}),
		"agent transfer": rpc("agent transfer ID --owner USER --backup-owner USER --reason R", 1, func(fs *flag.FlagSet) call {
			owner, backup, reason := fs.String("owner", "", "new owner"), fs.String("backup-owner", "", "new backup owner"), fs.String("reason", "", "why")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.agents.TransferOwnership(ctx, &pantherclawv1.TransferOwnershipRequest{
					Id: a[0], OwnerUserId: *owner, BackupOwnerUserId: *backup, Reason: *reason,
				})
			}
		}),
		"agent claim": rpc("agent claim ID --reason R (--merge-into AGENT | --name N --team ID --env ID --owner USER --context C [--backup-owner USER] [--purpose P])", 1, func(fs *flag.FlagSet) call {
			reason, merge := fs.String("reason", "", "why"), fs.String("merge-into", "", "merge into this existing agent")
			name, purpose, team, env := fs.String("name", "", "display name"), fs.String("purpose", "", "purpose"),
				fs.String("team", "", "team id"), fs.String("env", "", "environment id")
			owner, backup, ctxName := fs.String("owner", "", "owner"), fs.String("backup-owner", "", "backup owner"), fs.String("context", "", "execution context")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				req := &pantherclawv1.ClaimAgentRequest{Id: a[0], Reason: *reason}
				if *merge != "" {
					req.Target = &pantherclawv1.ClaimAgentRequest_MergeIntoAgentId{MergeIntoAgentId: *merge}
				} else {
					ec, err := execContext(*ctxName)
					if err != nil {
						return nil, err
					}
					req.Target = &pantherclawv1.ClaimAgentRequest_AsNewAgent{AsNewAgent: &pantherclawv1.ClaimDetails{
						Name: *name, Purpose: *purpose, TeamId: *team, EnvironmentId: *env, OwnerUserId: *owner,
						BackupOwnerUserId: optStr(*backup), ExecutionContext: ec,
					}}
				}
				return c.agents.ClaimAgent(ctx, req)
			}
		}),
		"agent suspend": rpc("agent suspend ID --reason R", 1, func(fs *flag.FlagSet) call {
			reason := fs.String("reason", "", "why")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.agents.SuspendAgent(ctx, &pantherclawv1.SuspendAgentRequest{Id: a[0], Reason: *reason})
			}
		}),
		"agent retire": rpc("agent retire ID --reason R", 1, func(fs *flag.FlagSet) call {
			reason := fs.String("reason", "", "why")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.agents.RetireAgent(ctx, &pantherclawv1.RetireAgentRequest{Id: a[0], Reason: *reason})
			}
		}),
		"agent history": rpc("agent history ID", 1, func(fs *flag.FlagSet) call {
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.agents.ListAgentChanges(ctx, &pantherclawv1.ListAgentChangesRequest{AgentId: a[0], PageSize: size(n), PageToken: *tok})
			}
		}),
		"agent enroll-token": {"agent enroll-token AGENT --out FILE [--ttl MINUTES]", enrollToken},
		"waitlist list": rpc("waitlist list [--state S,...] [--agent ID] [--kind K,...] [--priority 1-4,...] [--assigned-to-me] [--overdue]", 0, func(fs *flag.FlagSet) call {
			var states, kinds, priorities list
			fs.Var(&states, "state", "only these states (open, approved, rejected, expired, cancelled)") //nolint:misspell // API value
			agent := fs.String("agent", "", "only this agent")
			fs.Var(&kinds, "kind", "only these kinds (admission, access_request, action_hold, tool_review, restoration, reconciliation)")
			fs.Var(&priorities, "priority", "only these priorities (1 most urgent to 4)")
			mine, overdue := fs.Bool("assigned-to-me", false, "only entries assigned to you"), fs.Bool("overdue", false, "only open entries past their next escalation or near their deadline")
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				st, err := enumList[pantherclawv1.WaitlistState](states, "WAITLIST_STATE_", pantherclawv1.WaitlistState_value)
				if err != nil {
					return nil, err
				}
				k, err := enumList[pantherclawv1.WaitlistKind](kinds, "WAITLIST_KIND_", pantherclawv1.WaitlistKind_value)
				if err != nil {
					return nil, err
				}
				var prio []int32
				for _, v := range priorities {
					for s := range strings.SplitSeq(v, ",") {
						p, err := strconv.Atoi(strings.TrimSpace(s))
						if err != nil || p < 1 || p > 4 {
							return nil, fmt.Errorf("--priority: %q is not 1 to 4", s)
						}
						prio = append(prio, int32(p)) //nolint:gosec // 1..4
					}
				}
				return c.waitlist.ListWaitlistEntries(ctx, &pantherclawv1.ListWaitlistEntriesRequest{
					PageSize: size(n), PageToken: *tok, States: st, AgentId: optStr(*agent), Kinds: k, Priorities: prio,
					AssignedToMe: *mine, Overdue: *overdue,
				})
			}
		}),
		"waitlist get": rpc("waitlist get ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.waitlist.GetWaitlistEntry(ctx, &pantherclawv1.GetWaitlistEntryRequest{Id: a[0]})
			}
		}),
	}
}

// enrollToken mints a single-use enrollment token for an agent and writes
// only the secret to a new 0600 file, for the workload's
// `pclaw workload enroll --enrollment-token-file`.
func enrollToken(ctx context.Context, a *app, args []string) error {
	if len(args) < 1 {
		return errUsage
	}
	fs := flag.NewFlagSet("agent enroll-token", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	out, ttl := fs.String("out", "", "write the token here (0600, never overwritten)"), fs.Int("ttl", 15, "minutes the token stays valid (at most 15)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *out == "" || fs.NArg() != 0 {
		return errUsage
	}
	c, err := a.clients()
	if err != nil {
		return err
	}
	res, err := c.identity.CreateEnrollmentToken(ctx, &pantherclawv1.CreateEnrollmentTokenRequest{
		AgentId: args[0], TtlMinutes: int32(min(max(*ttl, 1), 15)),
	})
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(res.GetToken() + "\n"); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	_, err = fmt.Fprintf(a.stdout, "enrollment token %s written to %s; single use, valid until %s\n",
		res.GetId(), *out, res.GetExpireTime().AsTime().Format("15:04:05 MST"))
	return err
}
