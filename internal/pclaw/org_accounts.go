// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"flag"
	"fmt"

	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// `pclaw org accounts` (G0 M30 D933) reads and changes the org's owned
// accounts. An action that shares to an account not on the list holds for
// a person. Adding an account files a protected change: it applies only
// when a second person confirms it with a security key. Removing one
// applies at once.

func init() {
	commands["org accounts"] = group("org accounts", orgAccountCommands())
}

// accountCall is one OwnedAccountService call.
type accountCall func(ctx context.Context, c pantherclawv1connect.OwnedAccountServiceClient, args []string) (proto.Message, error)

// accountRPC builds a command on OwnedAccountService with nargs positional
// arguments before any flags.
func accountRPC(usage string, nargs int, setup func(fs *flag.FlagSet) accountCall) command {
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
		res, err := fn(ctx, pantherclawv1connect.NewOwnedAccountServiceClient(s.connect()), args[:nargs])
		if err != nil {
			return err
		}
		if err := a.print(res); err != nil {
			return err
		}
		if r, ok := res.(*pantherclawv1.AddOwnedAccountResponse); ok {
			_, _ = fmt.Fprintf(a.stderr, "protected change %s filed: the account is added when a second person confirms it with a security key\n",
				r.GetProtectedChangeId())
		}
		return nil
	}}
}

func orgAccountCommands() map[string]command {
	return map[string]command{
		"list": accountRPC("org accounts list", 0, func(*flag.FlagSet) accountCall {
			return func(ctx context.Context, c pantherclawv1connect.OwnedAccountServiceClient, _ []string) (proto.Message, error) {
				return c.ListOwnedAccounts(ctx, &pantherclawv1.ListOwnedAccountsRequest{})
			}
		}),
		"add": accountRPC("org accounts add KIND VALUE --reason TEXT (KIND: aws_account, github_org, email_domain, gcp_project, azure_tenant)", 2,
			func(fs *flag.FlagSet) accountCall {
				reason := fs.String("reason", "", "why the org owns this account (1 to 500 characters)")
				return func(ctx context.Context, c pantherclawv1connect.OwnedAccountServiceClient, a []string) (proto.Message, error) {
					return c.AddOwnedAccount(ctx, &pantherclawv1.AddOwnedAccountRequest{Kind: a[0], Value: a[1], Reason: *reason})
				}
			}),
		"remove": accountRPC("org accounts remove ID --reason TEXT", 1, func(fs *flag.FlagSet) accountCall {
			reason := fs.String("reason", "", "why the account is removed (1 to 500 characters)")
			return func(ctx context.Context, c pantherclawv1connect.OwnedAccountServiceClient, a []string) (proto.Message, error) {
				return c.RemoveOwnedAccount(ctx, &pantherclawv1.RemoveOwnedAccountRequest{Id: a[0], Reason: *reason})
			}
		}),
	}
}
