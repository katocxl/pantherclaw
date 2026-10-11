// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"flag"

	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// sandboxCall is one SandboxService call.
type sandboxCall func(ctx context.Context, sb pantherclawv1connect.SandboxServiceClient, args []string) (proto.Message, error)

// sandboxRPC builds a sandbox command like rpc, with the SandboxService
// client.
func sandboxRPC(usage string, nargs int, setup func(fs *flag.FlagSet) sandboxCall) command {
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
		res, err := fn(ctx, pantherclawv1connect.NewSandboxServiceClient(s.connect()), args[:nargs])
		if err != nil {
			return err
		}
		return a.print(res)
	}}
}

func init() {
	commands["sandbox get"] = sandboxRPC("sandbox get SESSION", 1, func(*flag.FlagSet) sandboxCall {
		return func(ctx context.Context, sb pantherclawv1connect.SandboxServiceClient, a []string) (proto.Message, error) {
			return sb.GetSession(ctx, &pantherclawv1.SandboxServiceGetSessionRequest{SessionId: a[0]})
		}
	})
	commands["sandbox list"] = sandboxRPC("sandbox list [--agent ID]", 0, func(fs *flag.FlagSet) sandboxCall {
		agent := fs.String("agent", "", "only this agent's sessions")
		n, tok := paging(fs)
		return func(ctx context.Context, sb pantherclawv1connect.SandboxServiceClient, _ []string) (proto.Message, error) {
			return sb.ListSessions(ctx, &pantherclawv1.SandboxServiceListSessionsRequest{AgentId: *agent, PageSize: size(n), PageToken: *tok})
		}
	})
	// sandbox end ends a session that pclaw sandbox run could not end (it
	// was killed): its instance is revoked at once rather than at expiry.
	commands["sandbox end"] = sandboxRPC("sandbox end SESSION", 1, func(*flag.FlagSet) sandboxCall {
		return func(ctx context.Context, sb pantherclawv1connect.SandboxServiceClient, a []string) (proto.Message, error) {
			return sb.EndSession(ctx, &pantherclawv1.SandboxServiceEndSessionRequest{SessionId: a[0]})
		}
	})
}
