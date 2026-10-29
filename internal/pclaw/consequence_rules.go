// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// pclaw consequence-rules (G0 M17 D112): the org's customer consequence
// rules. propose reads a rule as JSON (a ConsequenceRuleSpec) from a file
// and stores it PROPOSED; it and retire print the protected change a
// second person confirms on its change request's page before anything
// takes effect (D107).

type rulesCall func(ctx context.Context, a *app, c pantherclawv1connect.ConsequenceRuleServiceClient, args []string) (proto.Message, error)

type rulesVerb struct {
	usage string
	nargs int
	setup func(fs *flag.FlagSet) rulesCall
}

var rulesVerbs = map[string]rulesVerb{
	"propose": {"propose FILE", 1, func(*flag.FlagSet) rulesCall {
		return func(ctx context.Context, a *app, c pantherclawv1connect.ConsequenceRuleServiceClient, args []string) (proto.Message, error) {
			raw, err := os.ReadFile(args[0])
			if err != nil {
				return nil, err
			}
			spec := &pantherclawv1.ConsequenceRuleSpec{}
			if err := protojson.Unmarshal(raw, spec); err != nil {
				return nil, fmt.Errorf("%s: %w", args[0], err)
			}
			res, err := c.ProposeConsequenceRule(ctx, &pantherclawv1.ProposeConsequenceRuleRequest{Rule: spec})
			if err == nil {
				ruleWaiting(a, res.GetPending(), "activates "+spec.GetId())
			}
			return res, err
		}
	}},
	"list": {"list", 0, func(*flag.FlagSet) rulesCall {
		return func(ctx context.Context, _ *app, c pantherclawv1connect.ConsequenceRuleServiceClient, _ []string) (proto.Message, error) {
			return c.ListConsequenceRules(ctx, &pantherclawv1.ListConsequenceRulesRequest{})
		}
	}},
	"show": {"show RULE_ID", 1, func(*flag.FlagSet) rulesCall {
		return func(ctx context.Context, _ *app, c pantherclawv1connect.ConsequenceRuleServiceClient, args []string) (proto.Message, error) {
			return c.GetConsequenceRule(ctx, &pantherclawv1.GetConsequenceRuleRequest{RuleId: args[0]})
		}
	}},
	"retire": {"retire RULE_ID", 1, func(*flag.FlagSet) rulesCall {
		return func(ctx context.Context, a *app, c pantherclawv1connect.ConsequenceRuleServiceClient, args []string) (proto.Message, error) {
			res, err := c.RetireConsequenceRule(ctx, &pantherclawv1.RetireConsequenceRuleRequest{RuleId: args[0]})
			if err == nil {
				ruleWaiting(a, res.GetPending(), "retires "+args[0])
			}
			return res, err
		}
	}},
}

// ruleWaiting says that nothing took effect yet.
func ruleWaiting(a *app, p *pantherclawv1.PendingRuleChange, what string) {
	_, _ = fmt.Fprintf(a.stderr, "waiting for a second person: change request %s %s once someone else holding "+
		"consequence_rule.manage confirms it with a security key\n", p.GetChangeRequestId(), what)
}

func rulesUsage() string {
	lines := []string{}
	for _, v := range []string{"propose", "list", "show", "retire"} {
		lines = append(lines, "consequence-rules "+rulesVerbs[v].usage)
	}
	return strings.Join(lines, "\n  pclaw ")
}

func init() {
	commands["consequence-rules"] = command{usage: rulesUsage(), run: runRules}
}

func runRules(ctx context.Context, a *app, args []string) error {
	if len(args) == 0 {
		return errUsage
	}
	v, ok := rulesVerbs[args[0]]
	if !ok {
		return errUsage
	}
	fs := flag.NewFlagSet("consequence-rules "+v.usage, flag.ContinueOnError)
	fn := v.setup(fs)
	pos, err := verbArgs(a, v.nargs, args[1:], fs)
	if err != nil {
		return err
	}
	s, err := a.session()
	if err != nil {
		return err
	}
	res, err := fn(ctx, a, pantherclawv1connect.NewConsequenceRuleServiceClient(s.connect()), pos)
	if err != nil {
		return err
	}
	return a.print(res)
}
