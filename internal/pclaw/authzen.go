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

// AuthZEN enforcement point commands (G0 M14 D29): register the
// third-party enforcement points that ask the AuthZEN decision endpoint,
// change the connections they front, read and disable them. Activating a
// point, or widening its connections, needs a security key: the commands
// print the confirm page where a person does that.

func init() {
	commands["authzen point"] = group("authzen point", authzenPointCommands())
}

// pointCall is one EnforcementPointService call.
type pointCall func(ctx context.Context, c pantherclawv1connect.EnforcementPointServiceClient, args []string) (proto.Message, error)

// pointRPC builds a command on EnforcementPointService with nargs
// positional arguments before any flags.
func pointRPC(usage string, nargs int, setup func(fs *flag.FlagSet) pointCall) command {
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
		res, err := fn(ctx, pantherclawv1connect.NewEnforcementPointServiceClient(s.connect()), args[:nargs])
		if err != nil {
			return stepUpHint(a, err)
		}
		if err := a.print(res); err != nil {
			return err
		}
		confirmHint(a, res)
		return nil
	}}
}

// confirmHint points at the confirm page when proposed connections wait
// for a person's security key.
func confirmHint(a *app, res proto.Message) {
	var p *pantherclawv1.EnforcementPoint
	switch r := res.(type) {
	case *pantherclawv1.CreateEnforcementPointResponse:
		p = r.GetPoint()
	case *pantherclawv1.UpdateEnforcementPointConnectionsResponse:
		p = r.GetPoint()
	}
	if len(p.GetProposedConnectionIds()) > 0 && p.GetConfirmUrl() != "" {
		_, _ = fmt.Fprintf(a.stderr, "confirm the proposed connections with your security key at %s\n", p.GetConfirmUrl())
	}
}

func authzenPointCommands() map[string]command {
	byID := func(usage string, fn func(ctx context.Context, c pantherclawv1connect.EnforcementPointServiceClient, id string) (proto.Message, error)) command {
		return pointRPC(usage, 1, func(*flag.FlagSet) pointCall {
			return func(ctx context.Context, c pantherclawv1connect.EnforcementPointServiceClient, a []string) (proto.Message, error) {
				return fn(ctx, c, a[0])
			}
		})
	}
	return map[string]command{
		"create": pointRPC("authzen point create NAME --service-account ID --connection ID [--connection ID]... [--description TEXT] [--rate N]", 1,
			func(fs *flag.FlagSet) pointCall {
				sa := fs.String("service-account", "", "the service account it authenticates as (holding the Enforcement Point role)")
				var conns list
				fs.Var(&conns, "connection", "a connection id it fronts (repeatable; agent_held or target_enforced)")
				desc := fs.String("description", "", "what it is for")
				rate := fs.Int("rate", 0, "evaluations a second (1 to 1000, default 50)")
				return func(ctx context.Context, c pantherclawv1connect.EnforcementPointServiceClient, a []string) (proto.Message, error) {
					return c.CreateEnforcementPoint(ctx, &pantherclawv1.CreateEnforcementPointRequest{
						Name: a[0], Description: *desc, ServiceAccountId: *sa, ConnectionIds: conns, RatePerSecond: int32(*rate), //nolint:gosec // validated ≤ 1000
					})
				}
			}),
		"connections": pointRPC("authzen point connections POINT_ID --connection ID [--connection ID]...", 1, func(fs *flag.FlagSet) pointCall {
			var conns list
			fs.Var(&conns, "connection", "a connection id it should front (repeatable): the whole new set")
			return func(ctx context.Context, c pantherclawv1connect.EnforcementPointServiceClient, a []string) (proto.Message, error) {
				return c.UpdateEnforcementPointConnections(ctx, &pantherclawv1.UpdateEnforcementPointConnectionsRequest{Id: a[0], ConnectionIds: conns})
			}
		}),
		"activate": byID("authzen point activate POINT_ID (needs your security key: use the confirm page)",
			func(ctx context.Context, c pantherclawv1connect.EnforcementPointServiceClient, id string) (proto.Message, error) {
				return c.ActivateEnforcementPoint(ctx, &pantherclawv1.ActivateEnforcementPointRequest{Id: id})
			}),
		"disable": byID("authzen point disable POINT_ID", func(ctx context.Context, c pantherclawv1connect.EnforcementPointServiceClient, id string) (proto.Message, error) {
			return c.DisableEnforcementPoint(ctx, &pantherclawv1.DisableEnforcementPointRequest{Id: id})
		}),
		"get": byID("authzen point get POINT_ID", func(ctx context.Context, c pantherclawv1connect.EnforcementPointServiceClient, id string) (proto.Message, error) {
			return c.GetEnforcementPoint(ctx, &pantherclawv1.GetEnforcementPointRequest{Id: id})
		}),
		"list": pointRPC("authzen point list", 0, func(*flag.FlagSet) pointCall {
			return func(ctx context.Context, c pantherclawv1connect.EnforcementPointServiceClient, _ []string) (proto.Message, error) {
				return c.ListEnforcementPoints(ctx, &pantherclawv1.ListEnforcementPointsRequest{})
			}
		}),
	}
}
