// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package policiesrpc serves PolicyService over Connect (HR-040..044; G0
// M4 part 2). Bundles are immutable versions, compiled before they are
// stored and again before they are published; publishing is human only.
package policiesrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/policy/app"
)

// Policies serves PolicyService.
type Policies struct {
	pantherclawv1connect.UnimplementedPolicyServiceHandler
	svc *app.Versions
}

// New returns the PolicyService handler.
func New(svc *app.Versions) *Policies { return &Policies{svc: svc} }

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

func parseID(s string) (ids.UUID, error) {
	u, err := ids.ParseUUID(s)
	if err != nil || u.Version() != 7 {
		return ids.UUID{}, errInvalidID
	}
	return u, nil
}

func ts(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

// VersionProto renders a version; withBundle includes the bundle.
func VersionProto(v app.VersionInfo, withBundle bool) *pantherclawv1.PolicyVersion {
	out := &pantherclawv1.PolicyVersion{
		Id: v.ID.String(), BundleId: v.BundleID, Version: int32(v.Version), State: v.State, //nolint:gosec // small
		CreatedBy: v.CreatedBy, CreateTime: ts(v.CreatedAt),
	}
	if v.PublishedAt != nil {
		out.PublishTime = ts(*v.PublishedAt)
	}
	if withBundle {
		out.Bundle = v.Bundle
	}
	return out
}

// CreatePolicyVersion implements PolicyServiceHandler.
func (s *Policies) CreatePolicyVersion(ctx context.Context, req *pantherclawv1.CreatePolicyVersionRequest) (*pantherclawv1.CreatePolicyVersionResponse, error) {
	expected, err := expectedVersion(req.ExpectedCurrentVersion)
	if err != nil {
		return nil, err
	}
	v, err := s.svc.CreateExpecting(ctx, req.GetBundle(), expected)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreatePolicyVersionResponse{Version: VersionProto(v, false)}, nil
}

// PublishPolicyVersion implements PolicyServiceHandler.
func (s *Policies) PublishPolicyVersion(ctx context.Context, req *pantherclawv1.PublishPolicyVersionRequest) (*pantherclawv1.PublishPolicyVersionResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	expected, err := expectedVersion(req.ExpectedCurrentVersion)
	if err != nil {
		return nil, err
	}
	v, err := s.svc.PublishExpecting(ctx, id, expected)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.PublishPolicyVersionResponse{Version: VersionProto(v, false)}, nil
}

// GetPublishedPolicy implements PolicyServiceHandler.
func (s *Policies) GetPublishedPolicy(ctx context.Context, _ *pantherclawv1.GetPublishedPolicyRequest) (*pantherclawv1.GetPublishedPolicyResponse, error) {
	v, err := s.svc.Published(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetPublishedPolicyResponse{}
	if v != nil {
		out.Version = VersionProto(*v, true)
	}
	return out, nil
}

// GetPolicyVersion implements PolicyServiceHandler.
func (s *Policies) GetPolicyVersion(ctx context.Context, req *pantherclawv1.GetPolicyVersionRequest) (*pantherclawv1.GetPolicyVersionResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	v, err := s.svc.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetPolicyVersionResponse{Version: VersionProto(v, true)}, nil
}

// ListPolicyVersions implements PolicyServiceHandler.
func (s *Policies) ListPolicyVersions(ctx context.Context, req *pantherclawv1.ListPolicyVersionsRequest) (*pantherclawv1.ListPolicyVersionsResponse, error) {
	limit := int(req.GetPageSize())
	if limit == 0 {
		limit = 50
	}
	vs, err := s.svc.List(ctx, limit)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListPolicyVersionsResponse{}
	for _, v := range vs {
		out.Versions = append(out.Versions, VersionProto(v, false))
	}
	return out, nil
}

// expectedVersion is a request's expected_current_version: nil when unset,
// the zero id when set empty (none is published).
func expectedVersion(v *string) (*ids.UUID, error) {
	if v == nil {
		return nil, nil
	}
	if *v == "" {
		return &ids.UUID{}, nil
	}
	id, err := parseID(*v)
	if err != nil {
		return nil, err
	}
	return &id, nil
}
