// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package githubrpc serves GitHubService (G0 M8): the GitHub identity
// links independence compares (HR-207).
package githubrpc

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/github/app"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

// Handler serves GitHubService.
type Handler struct {
	pantherclawv1connect.UnimplementedGitHubServiceHandler
	s *app.Service
}

// New returns the handler.
func New(s *app.Service) *Handler { return &Handler{s: s} }

func identityOf(i app.Identity) *pb.GitHubIdentity {
	return &pb.GitHubIdentity{
		Id: i.ID.String(), UserId: i.UserID.String(), GithubLogin: i.GithubLogin, GithubUserId: i.GithubUserID, LinkedBy: i.LinkedBy,
		LinkTime: timestamppb.New(i.LinkedAt),
	}
}

func parseID(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil {
		return ids.UUID{}, errInvalidID
	}
	return id, nil
}

// LinkIdentity implements GitHubServiceHandler.
func (h *Handler) LinkIdentity(ctx context.Context, req *pb.LinkIdentityRequest) (*pb.LinkIdentityResponse, error) {
	user, err := parseID(req.GetUserId())
	if err != nil {
		return nil, err
	}
	i, err := h.s.Link(ctx, user, req.GetGithubLogin(), req.GetGithubUserId())
	if err != nil {
		return nil, err
	}
	return &pb.LinkIdentityResponse{Identity: identityOf(i)}, nil
}

// UnlinkIdentity implements GitHubServiceHandler.
func (h *Handler) UnlinkIdentity(ctx context.Context, req *pb.UnlinkIdentityRequest) (*pb.UnlinkIdentityResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	return &pb.UnlinkIdentityResponse{}, h.s.Unlink(ctx, id)
}

// ListIdentities implements GitHubServiceHandler.
func (h *Handler) ListIdentities(ctx context.Context, req *pb.ListIdentitiesRequest) (*pb.ListIdentitiesResponse, error) {
	var user *ids.UUID
	if req.GetUserId() != "" {
		id, err := parseID(req.GetUserId())
		if err != nil {
			return nil, err
		}
		user = &id
	}
	rows, next, err := h.s.List(ctx, user, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pb.ListIdentitiesResponse{NextPageToken: next}
	for _, i := range rows {
		out.Identities = append(out.Identities, identityOf(i))
	}
	return out, nil
}
