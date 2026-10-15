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

// pclaw policy validate|test|diff|rollback|changes (G0 M11.1 design
// decisions 6, 9 and 11): the publish gate from the command line. A
// publish or rollback that loosens the published policy prints the page
// where people confirm it with security keys; nothing here confirms one.

func init() {
	for k, v := range policyGateCommands() {
		commands[k] = v
	}
}

// rpcThen is rpc, and after printing the response it runs then with it.
func rpcThen(usage string, nargs int, setup func(fs *flag.FlagSet) call, then func(a *app, m proto.Message) error) command {
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
		c, err := a.clients()
		if err != nil {
			return err
		}
		res, err := fn(ctx, c, args[:nargs])
		if err != nil {
			return err
		}
		if err := a.print(res); err != nil {
			return err
		}
		return then(a, res)
	}}
}

// changeNote tells, after a publish or rollback, whether the version is in
// effect or waits for confirmations, and where.
func changeNote(a *app, m proto.Message) error {
	var cr *pantherclawv1.PolicyChangeRequest
	var v *pantherclawv1.PolicyVersion
	var b strings.Builder
	switch r := m.(type) {
	case *pantherclawv1.PublishPolicyVersionResponse:
		cr, v = r.GetChangeRequest(), r.GetVersion()
	case *pantherclawv1.RollbackPolicyResponse:
		cr, v = r.GetChangeRequest(), r.GetVersion()
		if ids := r.GetCarriedRuleIds(); len(ids) > 0 {
			fmt.Fprintf(&b, "emergency rules carried forward from the published version: %s\n", strings.Join(ids, ", "))
		}
		b.WriteString("containment, grants and envelopes (org guardrails) are separate records: the rollback did not change them\n")
	}
	if cr != nil {
		fmt.Fprintf(&b, "waiting for confirmation: this version loosens the published policy, so %d %s holding policy.publish must confirm it with a security key within 24 hours at\n  %s\n",
			cr.GetRequired(), people(cr.GetRequired()), cr.GetUrl())
	} else if v.GetState() == "PUBLISHED" {
		fmt.Fprintf(&b, "published version %d (%s)\n", v.GetVersion(), v.GetId())
	}
	_, err := fmt.Fprint(a.stderr, b.String())
	return err
}

func people(n int32) string {
	if n == 1 {
		return "person"
	}
	return "people"
}

func policyGateCommands() map[string]command {
	return map[string]command{
		"policy validate": rpc("policy validate VERSION_ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.policies.ValidatePolicyVersion(ctx, &pantherclawv1.ValidatePolicyVersionRequest{Id: a[0]})
			}
		}),
		"policy test": rpc("policy test VERSION_ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.policies.TestPolicyVersion(ctx, &pantherclawv1.TestPolicyVersionRequest{Id: a[0]})
			}
		}),
		"policy diff": rpc("policy diff VERSION_ID [--from VERSION_ID]", 1, func(fs *flag.FlagSet) call {
			from := fs.String("from", "", "the base version (default: the published one)")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				req := &pantherclawv1.DiffPolicyVersionsRequest{ToId: a[0]}
				if *from != "" {
					req.FromId = from
				}
				return c.policies.DiffPolicyVersions(ctx, req)
			}
		}),
		"policy rollback": rpcThen("policy rollback VERSION_ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.policies.RollbackPolicy(ctx, &pantherclawv1.RollbackPolicyRequest{ToVersionId: a[0]})
			}
		}, changeNote),
		"policy changes": {usage: "policy changes [list [--state STATE] | get ID]", run: changes},
	}
}

// changes dispatches pclaw policy changes [list | get ID].
func changes(ctx context.Context, a *app, args []string) error {
	sub := changesCommands["list"]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		c, ok := changesCommands[args[0]]
		if !ok {
			return errUsage
		}
		sub, args = c, args[1:]
	}
	return sub.run(ctx, a, args)
}

var changesCommands = map[string]command{
	"list": rpc("policy changes list [--state STATE]", 0, func(fs *flag.FlagSet) call {
		state := fs.String("state", "", "only PENDING, APPROVED, DECLINED, EXPIRED or VOIDED")
		return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
			return c.policies.ListPolicyChangeRequests(ctx, &pantherclawv1.ListPolicyChangeRequestsRequest{State: strings.ToUpper(*state)})
		}
	}),
	"get": rpc("policy changes get ID", 1, func(*flag.FlagSet) call {
		return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
			return c.policies.GetPolicyChangeRequest(ctx, &pantherclawv1.GetPolicyChangeRequestRequest{Id: a[0]})
		}
	}),
}
