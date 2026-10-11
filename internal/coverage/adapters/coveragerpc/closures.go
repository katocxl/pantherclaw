// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package coveragerpc

import (
	"context"
	"encoding/hex"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/coverage/app"
	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

var kinds = map[domain.RouteKind]pantherclawv1.CoverageRouteKind{
	domain.KindChannel:      pantherclawv1.CoverageRouteKind_COVERAGE_ROUTE_KIND_CHANNEL,
	domain.KindDirectAPI:    pantherclawv1.CoverageRouteKind_COVERAGE_ROUTE_KIND_DIRECT_API,
	domain.KindHost:         pantherclawv1.CoverageRouteKind_COVERAGE_ROUTE_KIND_HOST,
	domain.KindGitSSH:       pantherclawv1.CoverageRouteKind_COVERAGE_ROUTE_KIND_GIT_SSH,
	domain.KindCredential:   pantherclawv1.CoverageRouteKind_COVERAGE_ROUTE_KIND_CREDENTIAL,
	domain.KindBrowser:      pantherclawv1.CoverageRouteKind_COVERAGE_ROUTE_KIND_BROWSER,
	domain.KindDelegated:    pantherclawv1.CoverageRouteKind_COVERAGE_ROUTE_KIND_DELEGATED,
	domain.KindIntermediary: pantherclawv1.CoverageRouteKind_COVERAGE_ROUTE_KIND_INTERMEDIARY,
	domain.KindTargetSide:   pantherclawv1.CoverageRouteKind_COVERAGE_ROUTE_KIND_TARGET_SIDE,
}

func ts(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

func idOf(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil {
		return ids.UUID{}, errInvalidID
	}
	return id, nil
}

func optID(s *string) (*ids.UUID, error) {
	if s == nil {
		return nil, nil
	}
	id, err := idOf(*s)
	return &id, err
}

func closureProto(c app.Closure, probes bool) *pantherclawv1.CoverageClosure {
	out := &pantherclawv1.CoverageClosure{
		Id: c.ID.String(), AgentId: c.AgentID.String(), ConnectionId: c.ConnectionID.String(),
		SandboxSessionId: c.SandboxSessionID.String(), Passed: c.Result == "PASSED", SigningKeyJkt: c.SigningKeyJkt,
		ResultsDigest: "sha256:" + hex.EncodeToString(c.ResultsSha256), EngineVersion: c.EngineVersion,
		ApiVersion: c.ApiVersion, Runtime: c.Runtime, ImageDigests: c.ImageDigests, GatewayId: c.GatewayID.String(),
		ConnectionRevision: c.ConnectionRevision, PackageVersionId: c.PackageVersionID.String(),
		ObserveTime: ts(c.ObservedAt), ExpireTime: ts(c.ExpiresAt), RecordTime: ts(c.RecordedAt),
	}
	for _, k := range c.Verdict.Closed {
		out.ClosedKinds = append(out.ClosedKinds, kinds[k])
	}
	if probes {
		for _, p := range c.Probes {
			out.Probes = append(out.Probes, &pantherclawv1.CoverageProbeResult{
				Name: p.Name, Role: p.Role, Expect: p.Expect, Observed: p.Observed, Passed: p.Passed(), Detail: p.Detail,
			})
		}
	}
	return out
}

// GetClosure implements CoverageServiceHandler.
func (h *Handler) GetClosure(ctx context.Context, req *pantherclawv1.GetClosureRequest) (*pantherclawv1.GetClosureResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	c, err := h.svc.GetClosure(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetClosureResponse{Closure: closureProto(c, true)}, nil
}

func filterOf(agent, connection *string) (app.Filter, error) {
	a, err := optID(agent)
	if err != nil {
		return app.Filter{}, err
	}
	c, err := optID(connection)
	return app.Filter{Agent: a, Connection: c}, err
}

// ListClosures implements CoverageServiceHandler.
func (h *Handler) ListClosures(ctx context.Context, req *pantherclawv1.ListClosuresRequest) (*pantherclawv1.ListClosuresResponse, error) {
	f, err := filterOf(req.AgentId, req.ConnectionId)
	if err != nil {
		return nil, err
	}
	rows, next, err := h.svc.ListClosures(ctx, f, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListClosuresResponse{NextPageToken: next}
	for _, c := range rows {
		out.Closures = append(out.Closures, closureProto(c, false))
	}
	return out, nil
}

func tsp(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return ts(*t)
}
