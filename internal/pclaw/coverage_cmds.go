// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// pclaw coverage (G0 M9 track A): read coverage records, their routes,
// closure evidence, exclusions and findings; explain a record in words;
// reassess a connection, exclude or dismiss (people only).

type coverageCall func(ctx context.Context, c pantherclawv1connect.CoverageServiceClient, args []string) (proto.Message, error)

// coverageRPC is rpc for CoverageService.
func coverageRPC(usage string, nargs int, setup func(fs *flag.FlagSet) coverageCall) command {
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
		res, err := fn(ctx, pantherclawv1connect.NewCoverageServiceClient(s.connect()), args[:nargs])
		if err != nil {
			return err
		}
		if e, ok := res.(*explained); ok {
			return e.write(a.stdout)
		}
		return a.print(res)
	}}
}

func optString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func coverageScopeOf(args []string) *pantherclawv1.CoverageScope {
	return &pantherclawv1.CoverageScope{AgentId: args[0], ConnectionId: args[1], Operation: args[2]}
}

var routeKinds = map[string]pantherclawv1.CoverageRouteKind{
	"direct_api": pantherclawv1.CoverageRouteKind_COVERAGE_ROUTE_KIND_DIRECT_API, "host": pantherclawv1.CoverageRouteKind_COVERAGE_ROUTE_KIND_HOST,
	"git_ssh": pantherclawv1.CoverageRouteKind_COVERAGE_ROUTE_KIND_GIT_SSH, "credential": pantherclawv1.CoverageRouteKind_COVERAGE_ROUTE_KIND_CREDENTIAL,
	"browser": pantherclawv1.CoverageRouteKind_COVERAGE_ROUTE_KIND_BROWSER, "delegated": pantherclawv1.CoverageRouteKind_COVERAGE_ROUTE_KIND_DELEGATED,
	"intermediary": pantherclawv1.CoverageRouteKind_COVERAGE_ROUTE_KIND_INTERMEDIARY, "target_side": pantherclawv1.CoverageRouteKind_COVERAGE_ROUTE_KIND_TARGET_SIDE,
}

func init() {
	for name, c := range map[string]command{
		"coverage list": coverageRPC("coverage list [--agent ID] [--connection ID]", 0, func(fs *flag.FlagSet) coverageCall {
			agent, conn := fs.String("agent", "", "only this agent"), fs.String("connection", "", "only this connection")
			n, tok := paging(fs)
			return func(ctx context.Context, c pantherclawv1connect.CoverageServiceClient, _ []string) (proto.Message, error) {
				return c.ListCoverage(ctx, &pantherclawv1.ListCoverageRequest{
					AgentId: optString(*agent), ConnectionId: optString(*conn), PageSize: size(n), PageToken: *tok,
				})
			}
		}),
		"coverage show": coverageRPC("coverage show AGENT CONNECTION OPERATION", 3, func(*flag.FlagSet) coverageCall {
			return func(ctx context.Context, c pantherclawv1connect.CoverageServiceClient, args []string) (proto.Message, error) {
				return c.GetCoverage(ctx, &pantherclawv1.GetCoverageRequest{Scope: coverageScopeOf(args)})
			}
		}),
		"coverage explain": coverageRPC("coverage explain AGENT CONNECTION OPERATION", 3, func(*flag.FlagSet) coverageCall {
			return func(ctx context.Context, c pantherclawv1connect.CoverageServiceClient, args []string) (proto.Message, error) {
				r, err := c.GetCoverage(ctx, &pantherclawv1.GetCoverageRequest{Scope: coverageScopeOf(args)})
				if err != nil {
					return nil, err
				}
				f, err := c.GetFreshnessContract(ctx, &pantherclawv1.GetFreshnessContractRequest{})
				if err != nil {
					return nil, err
				}
				return &explained{GetCoverageResponse: r, freshness: f}, nil
			}
		}),
		"coverage routes": coverageRPC("coverage routes [--agent ID] [--connection ID]", 0, func(fs *flag.FlagSet) coverageCall {
			agent, conn := fs.String("agent", "", "only this agent's routes and those of every agent"), fs.String("connection", "", "only this connection")
			n, tok := paging(fs)
			return func(ctx context.Context, c pantherclawv1connect.CoverageServiceClient, _ []string) (proto.Message, error) {
				return c.ListRoutes(ctx, &pantherclawv1.ListRoutesRequest{
					AgentId: optString(*agent), ConnectionId: optString(*conn), PageSize: size(n), PageToken: *tok,
				})
			}
		}),
		"coverage closure": coverageRPC("coverage closure ID", 1, func(*flag.FlagSet) coverageCall {
			return func(ctx context.Context, c pantherclawv1connect.CoverageServiceClient, args []string) (proto.Message, error) {
				return c.GetClosure(ctx, &pantherclawv1.GetClosureRequest{Id: args[0]})
			}
		}),
		"coverage freshness": coverageRPC("coverage freshness", 0, func(*flag.FlagSet) coverageCall {
			return func(ctx context.Context, c pantherclawv1connect.CoverageServiceClient, _ []string) (proto.Message, error) {
				return c.GetFreshnessContract(ctx, &pantherclawv1.GetFreshnessContractRequest{})
			}
		}),
		"coverage access": coverageRPC("coverage access CONNECTION [--agent ID]", 1, func(fs *flag.FlagSet) coverageCall {
			agent := fs.String("agent", "", "the agent whose access to describe")
			return func(ctx context.Context, c pantherclawv1connect.CoverageServiceClient, args []string) (proto.Message, error) {
				return c.GetAccessDetail(ctx, &pantherclawv1.GetAccessDetailRequest{ConnectionId: args[0], AgentId: optString(*agent)})
			}
		}),
		"coverage reassess": coverageRPC("coverage reassess CONNECTION [--agent ID]", 1, func(fs *flag.FlagSet) coverageCall {
			agent := fs.String("agent", "", "only this agent's scopes")
			return func(ctx context.Context, c pantherclawv1connect.CoverageServiceClient, args []string) (proto.Message, error) {
				return c.Reassess(ctx, &pantherclawv1.ReassessRequest{ConnectionId: args[0], AgentId: optString(*agent)})
			}
		}),
		"coverage exclude": coverageRPC("coverage exclude CONNECTION --reason TEXT --expires-in-days N [--agent ID] [--operation OP] [--route KIND]", 1,
			func(fs *flag.FlagSet) coverageCall {
				agent, op := fs.String("agent", "", "only this agent (default: every agent)"), fs.String("operation", "", "only this operation (default: every operation)")
				route := fs.String("route", "", "one route kind: direct_api, host, git_ssh, credential, browser, delegated, intermediary, target_side (default: the whole scope)")
				reason := fs.String("reason", "", "why, in writing (10 to 1,000 characters; required)")
				days := fs.Int("expires-in-days", 0, "days until it expires, 1 to 90 (required)")
				return func(ctx context.Context, c pantherclawv1connect.CoverageServiceClient, args []string) (proto.Message, error) {
					kind, ok := routeKinds[*route]
					switch {
					case *route != "" && !ok:
						return nil, fmt.Errorf("--route %q is not a route kind that can be excluded", *route)
					case len(strings.TrimSpace(*reason)) < 10 || *days < 1 || *days > 90:
						return nil, errors.New("--reason (10 to 1,000 characters) and --expires-in-days (1 to 90) are required")
					}
					return c.CreateExclusion(ctx, &pantherclawv1.CreateExclusionRequest{
						ConnectionId: args[0], AgentId: optString(*agent), Operation: optString(*op), RouteKind: kind,
						Reason: *reason, ExpiresInDays: int32(*days),
					})
				}
			}),
		"coverage unexclude": coverageRPC("coverage unexclude EXCLUSION", 1, func(*flag.FlagSet) coverageCall {
			return func(ctx context.Context, c pantherclawv1connect.CoverageServiceClient, args []string) (proto.Message, error) {
				return c.RevokeExclusion(ctx, &pantherclawv1.RevokeExclusionRequest{Id: args[0]})
			}
		}),
		"coverage exclusions": coverageRPC("coverage exclusions [--connection ID]", 0, func(fs *flag.FlagSet) coverageCall {
			conn := fs.String("connection", "", "only this connection")
			n, tok := paging(fs)
			return func(ctx context.Context, c pantherclawv1connect.CoverageServiceClient, _ []string) (proto.Message, error) {
				return c.ListExclusions(ctx, &pantherclawv1.ListExclusionsRequest{ConnectionId: optString(*conn), PageSize: size(n), PageToken: *tok})
			}
		}),
		"coverage findings": coverageRPC("coverage findings [--state open|resolved|dismissed] [--connection ID]", 0, func(fs *flag.FlagSet) coverageCall {
			state, conn := fs.String("state", "", "open, resolved or dismissed (default: all)"), fs.String("connection", "", "only this connection")
			n, tok := paging(fs)
			return func(ctx context.Context, c pantherclawv1connect.CoverageServiceClient, _ []string) (proto.Message, error) {
				return c.ListFindings(ctx, &pantherclawv1.ListFindingsRequest{
					State: optString(strings.ToUpper(*state)), ConnectionId: optString(*conn), PageSize: size(n), PageToken: *tok,
				})
			}
		}),
		"coverage acknowledge": coverageRPC("coverage acknowledge FINDING --reason TEXT", 1, func(fs *flag.FlagSet) coverageCall {
			reason := fs.String("reason", "", "why, in writing (10 to 1,000 characters; required)")
			return func(ctx context.Context, c pantherclawv1connect.CoverageServiceClient, args []string) (proto.Message, error) {
				return c.AcknowledgeFinding(ctx, &pantherclawv1.AcknowledgeFindingRequest{Id: args[0], Reason: *reason})
			}
		}),
	} {
		commands[name] = c
	}
}

// explained is a coverage record rendered in words for `pclaw coverage
// explain`.
type explained struct {
	*pantherclawv1.GetCoverageResponse
	freshness *pantherclawv1.GetFreshnessContractResponse
}

// reasonText says what each reason code means.
var reasonText = map[string]string{
	"not_assessed":            "no coverage snapshot was computed for this scope yet",
	"connection_retired":      "the connection is retired",
	"no_observed_traffic":     "no traffic through PantherClaw was observed; a connection setting alone proves nothing (F460)",
	"monitor_mode":            "a route is in monitor mode: actions are observed, not prevented",
	"cooperative_channel":     "a cooperative channel (SDK or hook) the agent could skip; capped at PARTIAL unless the target verifies action tokens (HR-024)",
	"opaque_mcp_server":       "an MCP server whose own egress is not mediated; capped at PARTIAL (HR-086)",
	"connection_not_active":   "the connection is quarantined",
	"no_closure_evidence":     "no sandbox closure evidence: equivalent routes are not proven closed",
	"closure_failed":          "the newest sandbox closure failed",
	"closure_expired":         "the closure evidence expired",
	"closure_binding_changed": "the connection's revision, gateway or package changed since the closure",
	"excluded":                "a person excluded this scope from the claim",
}

func explainReason(r string) string {
	if t, ok := reasonText[r]; ok {
		return t
	}
	if kind, ok := strings.CutPrefix(r, "invalidated:"); ok {
		return "a change since the evidence invalidated it (" + kind + ")"
	}
	if kind, ok := strings.CutPrefix(r, "route_not_closed:"); ok {
		return "the " + kind + " route is not proven closed"
	}
	return r
}

func short(s string) string { return strings.ToLower(strings.TrimPrefix(s, "COVERAGE_")) }

func (e *explained) write(w io.Writer) error {
	r := e.GetRecord()
	var b strings.Builder
	state := strings.TrimPrefix(r.GetState().String(), "COVERAGE_STATE_")
	fmt.Fprintf(&b, "%s  %s / %s / %s\n", state, r.GetScope().GetAgentId(), r.GetScope().GetConnectionId(), r.GetScope().GetOperation())
	if r.GetComputedState() != r.GetState() {
		fmt.Fprintf(&b, "  computed %s; reads %s now\n", strings.TrimPrefix(r.GetComputedState().String(), "COVERAGE_STATE_"), state)
	}
	if t := r.GetExpireTime(); t != nil && r.GetState() == pantherclawv1.CoverageState_COVERAGE_STATE_ENFORCED {
		fmt.Fprintf(&b, "  enforced until %s (closure %s)\n", t.AsTime().UTC().Format(time.RFC3339), r.GetClosureId())
	}
	if len(r.GetReasons()) > 0 {
		b.WriteString("Why:\n")
		for _, reason := range r.GetReasons() {
			fmt.Fprintf(&b, "  - %s\n", explainReason(reason))
		}
	}
	if len(r.GetRoutes()) > 0 {
		b.WriteString("Routes:\n")
		for _, rt := range r.GetRoutes() {
			name := strings.TrimPrefix(rt.GetKind().String(), "COVERAGE_ROUTE_KIND_")
			if rt.GetChannel() != "" {
				name += " " + rt.GetChannel()
			}
			if rt.GetLocator() != "" {
				name += " " + rt.GetLocator()
			}
			fmt.Fprintf(&b, "  %-40s %s\n", strings.ToLower(name), short(strings.TrimPrefix(rt.GetStatus().String(), "COVERAGE_ROUTE_STATUS_")))
		}
	}
	if lv := r.GetLastValid(); lv != nil {
		fmt.Fprintf(&b, "Last valid record: snapshot %s (%s)\n", lv.GetSnapshotId(), explainReason(lv.GetLapseReason()))
	}
	for _, x := range r.GetExclusions() {
		fmt.Fprintf(&b, "Excluded by %s until %s: %s\n", x.GetCreatedBy(), x.GetExpireTime().AsTime().UTC().Format(time.RFC3339), x.GetReason())
	}
	if f := e.freshness; f != nil {
		fmt.Fprintf(&b, "Freshness: ENFORCED holds for %s from its evidence; any of %s drops it to %s at once.\n",
			f.GetEnforcedTtl().AsDuration(), strings.Join(f.GetInvalidationKinds(), ", "),
			strings.TrimPrefix(f.GetStaleState().String(), "COVERAGE_STATE_"))
	}
	_, err := io.WriteString(w, b.String())
	return err
}
