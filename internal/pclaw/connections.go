// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
	"flag"
	"strconv"

	"google.golang.org/protobuf/proto"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// Connection commands (G0 M6). Every change needs a person holding
// connection.manage; weakening ones are audited and notified (HR-183).

var (
	connectionKinds = map[string]pb.ConnectionKind{
		"http": pb.ConnectionKind_CONNECTION_KIND_HTTP, "mcp": pb.ConnectionKind_CONNECTION_KIND_MCP,
		"local": pb.ConnectionKind_CONNECTION_KIND_LOCAL,
	}
	routeModes  = map[string]pb.RouteMode{"monitor": pb.RouteMode_ROUTE_MODE_MONITOR, "enforce": pb.RouteMode_ROUTE_MODE_ENFORCE}
	accessModes = map[string]pb.AccessMode{
		"pantherclaw_held": pb.AccessMode_ACCESS_MODE_PANTHERCLAW_HELD, "agent_held": pb.AccessMode_ACCESS_MODE_AGENT_HELD,
		"target_enforced": pb.AccessMode_ACCESS_MODE_TARGET_ENFORCED, "none": pb.AccessMode_ACCESS_MODE_NONE,
	}
	destinationClasses = map[string]pb.DestinationClass{
		"public": pb.DestinationClass_DESTINATION_CLASS_PUBLIC, "internal": pb.DestinationClass_DESTINATION_CLASS_INTERNAL,
	}
)

func init() {
	for k, v := range connectionCommands() {
		commands[k] = v
	}
}

// enumFlag maps a flag value through m; empty stays the zero value.
func enumFlag[T any](m map[string]T, flagName, v string) (T, error) {
	var zero T
	if v == "" {
		return zero, nil
	}
	out, ok := m[v]
	if !ok {
		return zero, errors.New("--" + flagName + ": unknown value " + strconv.Quote(v))
	}
	return out, nil
}

func connectionCommands() map[string]command {
	return map[string]command{
		"connection create": rpc("connection create NAME --kind http|mcp|local --gateway ID --package NAME [--base-url URL] "+
			"[--allowed-host HOST...] --access pantherclaw_held|agent_held|target_enforced|none [--header NAME [--scheme S]] "+
			"[--class public|internal] [--default-mode monitor|enforce] [--max-response-bytes N] [--timeout-ms N] [--agent-host HOST...]", 1,
			func(fs *flag.FlagSet) call {
				var hosts, agentHosts list
				kind, gw, pkg, base := fs.String("kind", "", "http, mcp or local"), fs.String("gateway", "", "gateway id"),
					fs.String("package", "", "tool package name"), fs.String("base-url", "", "the target's base URL")
				fs.Var(&hosts, "allowed-host", "host a credential may be sent to (repeatable; default: the base URL's host)")
				fs.Var(&agentHosts, "agent-host", "a host name agents use for the API, which a sandbox maps here (repeatable)")
				acc, header, scheme := fs.String("access", "", "access mode"), fs.String("header", "", "credential header"),
					fs.String("scheme", "", "credential scheme, for example Bearer")
				class, mode := fs.String("class", "", "destination class"), fs.String("default-mode", "", "monitor (default) or enforce")
				maxBytes, timeout := fs.Int("max-response-bytes", 0, "response cap"), fs.Int("timeout-ms", 0, "dispatch timeout")
				return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
					k, err1 := enumFlag(connectionKinds, "kind", *kind)
					am, err2 := enumFlag(accessModes, "access", *acc)
					dc, err3 := enumFlag(destinationClasses, "class", *class)
					dm, err4 := enumFlag(routeModes, "default-mode", *mode)
					if err := errors.Join(err1, err2, err3, err4); err != nil {
						return nil, err
					}
					return c.connections.CreateConnection(ctx, &pb.CreateConnectionRequest{
						Name: a[0], Kind: k, GatewayId: *gw, Package: *pkg, BaseUrl: *base, AllowedHosts: hosts, AccessMode: am,
						CredentialHeader: *header, CredentialScheme: *scheme, DestinationClass: dc, DefaultMode: dm,
						MaxResponseBytes: int32(min(max(*maxBytes, 0), 8<<20)), TimeoutMs: int32(min(max(*timeout, 0), 60_000)),
						AgentHosts: agentHosts,
					})
				}
			}),
		"connection list": rpc("connection list [--gateway ID] [--include-retired]", 0, func(fs *flag.FlagSet) call {
			gw, retired := fs.String("gateway", "", "only this gateway's connections"), fs.Bool("include-retired", false, "also list retired ones")
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.connections.ListConnections(ctx, &pb.ListConnectionsRequest{
					PageSize: size(n), PageToken: *tok, GatewayId: *gw, IncludeRetired: *retired,
				})
			}
		}),
		"connection get": rpc("connection get ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.connections.GetConnection(ctx, &pb.GetConnectionRequest{Id: a[0]})
			}
		}),
		"connection update": rpc("connection update ID --revision N [--gateway ID] [--base-url URL] [--allowed-host HOST... | --clear-allowed-hosts] "+
			"[--access MODE] [--class CLASS] [--default-mode MODE] [--max-response-bytes N] [--timeout-ms N] [--agent-host HOST... | --clear-agent-hosts]", 1,
			func(fs *flag.FlagSet) call {
				var gw, base, acc, class, mode, maxBytes, timeout optional
				var hosts, agentHosts list
				rev := fs.Int("revision", 0, "the revision you read (from connection get)")
				fs.Var(&gw, "gateway", "new gateway")
				fs.Var(&base, "base-url", "new base URL")
				fs.Var(&hosts, "allowed-host", "new credential hosts (repeatable; replaces the list)")
				reset := fs.Bool("clear-allowed-hosts", false, "reset the credential hosts to the base URL's host")
				fs.Var(&agentHosts, "agent-host", "new agent hosts (repeatable; replaces the list; weakens enforcement)")
				clearAgent := fs.Bool("clear-agent-hosts", false, "remove every agent host")
				fs.Var(&acc, "access", "new access mode")
				fs.Var(&class, "class", "new destination class")
				fs.Var(&mode, "default-mode", "new default route mode")
				fs.Var(&maxBytes, "max-response-bytes", "new response cap")
				fs.Var(&timeout, "timeout-ms", "new dispatch timeout")
				return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
					req := &pb.UpdateConnectionRequest{
						Id: a[0], Revision: int32(min(max(*rev, 0), 1<<30)), GatewayId: gw.ptr(), BaseUrl: base.ptr(),
						AllowedHosts: hosts, UpdateAllowedHosts: len(hosts) > 0 || *reset,
						AgentHosts: agentHosts, UpdateAgentHosts: len(agentHosts) > 0 || *clearAgent,
					}
					var errs []error
					if acc.set {
						v, err := enumFlag(accessModes, "access", acc.v)
						req.AccessMode, errs = &v, append(errs, err)
					}
					if class.set {
						v, err := enumFlag(destinationClasses, "class", class.v)
						req.DestinationClass, errs = &v, append(errs, err)
					}
					if mode.set {
						v, err := enumFlag(routeModes, "default-mode", mode.v)
						req.DefaultMode, errs = &v, append(errs, err)
					}
					for _, o := range []struct {
						f   *optional
						dst **int32
					}{{&maxBytes, &req.MaxResponseBytes}, {&timeout, &req.TimeoutMs}} {
						if o.f.set {
							n, err := strconv.ParseInt(o.f.v, 10, 32)
							v := int32(n)
							*o.dst, errs = &v, append(errs, err)
						}
					}
					if err := errors.Join(errs...); err != nil {
						return nil, err
					}
					return c.connections.UpdateConnection(ctx, req)
				}
			}),
		"connection set-mode": rpc("connection set-mode ID ROUTE monitor|enforce", 3, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				m, ok := routeModes[a[2]]
				if !ok {
					return nil, errors.New("the mode is monitor or enforce")
				}
				return c.connections.SetRouteMode(ctx, &pb.SetRouteModeRequest{ConnectionId: a[0], Route: a[1], Mode: m})
			}
		}),
		"connection quarantine": rpc("connection quarantine ID --reason TEXT", 1, func(fs *flag.FlagSet) call {
			reason := fs.String("reason", "", "why (recorded in the ledger)")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.connections.QuarantineConnection(ctx, &pb.QuarantineConnectionRequest{Id: a[0], Reason: *reason})
			}
		}),
		"connection restore": rpc("connection restore ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.connections.RestoreConnection(ctx, &pb.RestoreConnectionRequest{Id: a[0]})
			}
		}),
		"connection retire": rpc("connection retire ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.connections.RetireConnection(ctx, &pb.RetireConnectionRequest{Id: a[0]})
			}
		}),
	}
}
