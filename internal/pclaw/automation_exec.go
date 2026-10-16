// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"flag"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// Automation execution commands (G0 M11 part 2 D28, D29): inspect an
// execution (its trigger, version, authority, steps, grants, runs,
// launches, gates and result), find the execution behind a run, grant or
// transaction, and cancel executions. Reading needs automation.read,
// cancelling automation.manage.

func init() {
	commands["automation exec"] = group("automation exec", automationExecCommands())
}

// execCall is one ExecutionService call.
type execCall func(ctx context.Context, c pantherclawv1connect.ExecutionServiceClient, args []string) (proto.Message, error)

// execRPC is rpc for ExecutionService.
func execRPC(usage string, nargs int, setup func(fs *flag.FlagSet) execCall) command {
	return command{usage: usage, run: func(ctx context.Context, a *app, args []string) error {
		if len(args) < nargs {
			return errUsage
		}
		fs := flag.NewFlagSet(usage, flag.ContinueOnError)
		fs.SetOutput(a.stderr)
		fn := setup(fs)
		if err := fs.Parse(args[nargs:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errUsage
		}
		s, err := a.session()
		if err != nil {
			return err
		}
		res, err := fn(ctx, pantherclawv1connect.NewExecutionServiceClient(s.connect()), args[:nargs])
		if err != nil {
			return err
		}
		return a.print(res)
	}}
}

var execStates = map[string]pantherclawv1.AutomationExecutionState{}

func init() {
	for name, v := range pantherclawv1.AutomationExecutionState_value {
		if v != 0 {
			execStates[strings.ToLower(strings.TrimPrefix(name, "AUTOMATION_EXECUTION_STATE_"))] = pantherclawv1.AutomationExecutionState(v)
		}
	}
}

func automationExecCommands() map[string]command {
	return map[string]command{
		"get": execRPC("automation exec get <execution-id>", 1, func(*flag.FlagSet) execCall {
			return func(ctx context.Context, c pantherclawv1connect.ExecutionServiceClient, args []string) (proto.Message, error) {
				return c.GetExecution(ctx, &pantherclawv1.GetExecutionRequest{Id: args[0]})
			}
		}),
		"list": execRPC("automation exec list [--automation ID] [--state S]... [--mode live|shadow] [--since RFC3339] [--until RFC3339] [--size N] [--page TOKEN]", 0,
			func(fs *flag.FlagSet) execCall {
				automation := fs.String("automation", "", "only this automation's executions")
				var states list
				fs.Var(&states, "state", "pending, running, waiting, succeeded, partially_completed, failed, cancelled or needs_reconciliation (repeatable)")
				mode := fs.String("mode", "", "live or shadow")
				since := fs.String("since", "", "created at or after (RFC 3339)")
				until := fs.String("until", "", "created before (RFC 3339)")
				size := fs.Int("size", 50, "page size")
				token := fs.String("page", "", "page token")
				return func(ctx context.Context, c pantherclawv1connect.ExecutionServiceClient, _ []string) (proto.Message, error) {
					req := &pantherclawv1.ListExecutionsRequest{AutomationId: *automation, PageSize: int32(*size), PageToken: *token} //nolint:gosec // validated by the server
					for _, s := range states {
						st, ok := execStates[strings.ToLower(s)]
						if !ok {
							return nil, errUsage
						}
						req.States = append(req.States, st)
					}
					switch strings.ToLower(*mode) {
					case "":
					case "live":
						req.Mode = pantherclawv1.AutomationExecutionMode_AUTOMATION_EXECUTION_MODE_LIVE
					case "shadow":
						req.Mode = pantherclawv1.AutomationExecutionMode_AUTOMATION_EXECUTION_MODE_SHADOW
					default:
						return nil, errUsage
					}
					for _, p := range []struct {
						s   string
						dst **timestamppb.Timestamp
					}{{*since, &req.Since}, {*until, &req.Until}} {
						if p.s == "" {
							continue
						}
						t, err := time.Parse(time.RFC3339, p.s)
						if err != nil {
							return nil, errUsage
						}
						*p.dst = timestamppb.New(t)
					}
					return c.ListExecutions(ctx, req)
				}
			}),
		"lookup": execRPC("automation exec lookup run|grant|transaction <id>", 2, func(*flag.FlagSet) execCall {
			return func(ctx context.Context, c pantherclawv1connect.ExecutionServiceClient, args []string) (proto.Message, error) {
				req := &pantherclawv1.LookupExecutionRequest{}
				switch args[0] {
				case "run":
					req.Subject = &pantherclawv1.LookupExecutionRequest_RunId{RunId: args[1]}
				case "grant":
					req.Subject = &pantherclawv1.LookupExecutionRequest_GrantId{GrantId: args[1]}
				case "transaction":
					req.Subject = &pantherclawv1.LookupExecutionRequest_TransactionId{TransactionId: args[1]}
				default:
					return nil, errUsage
				}
				return c.LookupExecution(ctx, req)
			}
		}),
		"cancel": execRPC("automation exec cancel <execution-id> [--reason TEXT]", 1, func(fs *flag.FlagSet) execCall {
			reason := fs.String("reason", "", "why (at most 500 characters)")
			return func(ctx context.Context, c pantherclawv1connect.ExecutionServiceClient, args []string) (proto.Message, error) {
				return c.CancelExecution(ctx, &pantherclawv1.CancelExecutionRequest{Id: args[0], Reason: *reason})
			}
		}),
		"cancel-active": execRPC("automation exec cancel-active <automation-id> [--reason TEXT]", 1, func(fs *flag.FlagSet) execCall {
			reason := fs.String("reason", "", "why (at most 500 characters)")
			return func(ctx context.Context, c pantherclawv1connect.ExecutionServiceClient, args []string) (proto.Message, error) {
				return c.CancelActiveExecutions(ctx, &pantherclawv1.CancelActiveExecutionsRequest{AutomationId: args[0], Reason: *reason})
			}
		}),
	}
}
