// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// pclaw policy exception (G0 M11.1 D14, HR-235): ask for, read and revoke
// policy exceptions. An exception waives one exceptable rule for one agent
// and the listed operations, for at most 30 days, once its change request
// is confirmed; it is never extended (ask again).

type exceptionCall func(ctx context.Context, c pantherclawv1connect.PolicyExceptionServiceClient, args []string) (proto.Message, error)

type exceptionVerb struct {
	usage string
	nargs int
	setup func(fs *flag.FlagSet) exceptionCall
}

var exceptionVerbs = map[string]exceptionVerb{
	"request": {"request RULE --agent ID --operation OP [--operation OP]... --reason TEXT --expires-in DURATION [--owner USER_ID]", 1,
		func(fs *flag.FlagSet) exceptionCall {
			var ops list
			agent := fs.String("agent", "", "the agent it applies to (required)")
			fs.Var(&ops, "operation", "an exact operation inside the rule's scope (repeat, 1 to 16; required)")
			reason := fs.String("reason", "", "why the rule should not apply (1 to 500 characters; required)")
			expires := fs.Duration("expires-in", 0, "how long it lasts, a minute to 720h (30 days; required)")
			owner := fs.String("owner", "", "the person accountable for it (default: you)")
			return func(ctx context.Context, c pantherclawv1connect.PolicyExceptionServiceClient, args []string) (proto.Message, error) {
				switch {
				case *agent == "" || len(ops) == 0 || strings.TrimSpace(*reason) == "":
					return nil, errors.New("--agent, --operation and --reason are required")
				case *expires < time.Minute || *expires > 30*24*time.Hour:
					return nil, errors.New("--expires-in must be between 1m and 720h (30 days)")
				}
				return c.RequestPolicyException(ctx, &pantherclawv1.RequestPolicyExceptionRequest{
					RuleId: args[0], AgentId: *agent, Operations: ops, Reason: *reason,
					ExpiresInSeconds: int64(*expires / time.Second), OwnerId: optString(*owner),
				})
			}
		}},
	"list": {"list [--agent ID] [--rule RULE] [--state pending|active|declined|revoked|expired]", 0,
		func(fs *flag.FlagSet) exceptionCall {
			agent, rule := fs.String("agent", "", "only this agent"), fs.String("rule", "", "only this rule")
			state := fs.String("state", "", "only this state")
			n, tok := paging(fs)
			return func(ctx context.Context, c pantherclawv1connect.PolicyExceptionServiceClient, _ []string) (proto.Message, error) {
				return c.ListPolicyExceptions(ctx, &pantherclawv1.ListPolicyExceptionsRequest{
					AgentId: optString(*agent), RuleId: optString(*rule), State: optString(strings.ToUpper(*state)),
					PageSize: size(n), PageToken: *tok,
				})
			}
		}},
	"get": {"get ID", 1, func(*flag.FlagSet) exceptionCall {
		return func(ctx context.Context, c pantherclawv1connect.PolicyExceptionServiceClient, args []string) (proto.Message, error) {
			return c.GetPolicyException(ctx, &pantherclawv1.GetPolicyExceptionRequest{Id: args[0]})
		}
	}},
	"revoke": {"revoke ID --reason TEXT", 1, func(fs *flag.FlagSet) exceptionCall {
		reason := fs.String("reason", "", "why (1 to 500 characters; required)")
		return func(ctx context.Context, c pantherclawv1connect.PolicyExceptionServiceClient, args []string) (proto.Message, error) {
			if strings.TrimSpace(*reason) == "" {
				return nil, errors.New("--reason is required")
			}
			return c.RevokePolicyException(ctx, &pantherclawv1.RevokePolicyExceptionRequest{Id: args[0], Reason: *reason})
		}
	}},
}

func exceptionUsage() string {
	verbs := []string{"request", "list", "get", "revoke"}
	lines := make([]string, 0, len(verbs))
	for _, v := range verbs {
		lines = append(lines, "policy exception "+exceptionVerbs[v].usage)
	}
	return strings.Join(lines, "\n  pclaw ")
}

func init() {
	commands["policy exception"] = command{usage: exceptionUsage(), run: runPolicyException}
}

func runPolicyException(ctx context.Context, a *app, args []string) error {
	if len(args) == 0 {
		return errUsage
	}
	v, ok := exceptionVerbs[args[0]]
	if !ok || len(args)-1 < v.nargs {
		return errUsage
	}
	args = args[1:]
	fs := flag.NewFlagSet("policy exception "+v.usage, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	fn := v.setup(fs)
	if err := fs.Parse(args[v.nargs:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errUsage
	}
	s, err := a.session()
	if err != nil {
		return err
	}
	res, err := fn(ctx, pantherclawv1connect.NewPolicyExceptionServiceClient(s.connect()), args[:v.nargs])
	if err != nil {
		return err
	}
	if r, ok := res.(*pantherclawv1.RequestPolicyExceptionResponse); ok && r.GetChangeRequestUrl() != "" {
		_, _ = fmt.Fprintln(a.stderr, "Waiting for confirmation: the exception applies once its change request is confirmed at "+r.GetChangeRequestUrl())
	}
	return a.print(res)
}
