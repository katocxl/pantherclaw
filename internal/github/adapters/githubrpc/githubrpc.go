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
	s     *app.Service
	scans *app.Scans
}

// New returns the handler.
func New(s *app.Service, scans *app.Scans) *Handler { return &Handler{s: s, scans: scans} }

func identityOf(i app.Identity) *pb.GitHubIdentity {
	out := &pb.GitHubIdentity{
		Id: i.ID.String(), UserId: i.UserID.String(), GithubLogin: i.GithubLogin, GithubUserId: i.GithubUserID, LinkedBy: i.LinkedBy,
		LinkTime: timestamppb.New(i.LinkedAt),
	}
	if i.VerifiedAt != nil {
		out.VerifyTime = timestamppb.New(*i.VerifiedAt)
	}
	return out
}

func parseID(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil {
		return ids.UUID{}, errInvalidID
	}
	return id, nil
}

// ProveIdentity implements GitHubServiceHandler.
func (h *Handler) ProveIdentity(ctx context.Context, req *pb.ProveIdentityRequest) (*pb.ProveIdentityResponse, error) {
	i, err := h.s.Prove(ctx, req.GetGithubUserToken(), req.GetUnlink())
	if err != nil {
		return nil, err
	}
	return &pb.ProveIdentityResponse{Identity: identityOf(i)}, nil
}

// GetSignIn implements GitHubServiceHandler.
func (h *Handler) GetSignIn(ctx context.Context, _ *pb.GetSignInRequest) (*pb.GetSignInResponse, error) {
	c, err := h.s.SignInConfig(ctx)
	if err != nil {
		return nil, err
	}
	return &pb.GetSignInResponse{ClientId: c.ClientID, WebUrl: c.WebURL}, nil
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

func exemptionOf(e app.Exemption) *pb.GitHubExemption {
	return &pb.GitHubExemption{
		GithubUserId: e.GithubUserID, GithubLogin: e.GithubLogin, Reason: e.Reason, CreatedBy: e.CreatedBy,
		CreateTime: timestamppb.New(e.CreatedAt),
	}
}

// ExemptAccount implements GitHubServiceHandler.
func (h *Handler) ExemptAccount(ctx context.Context, req *pb.ExemptAccountRequest) (*pb.ExemptAccountResponse, error) {
	e, err := h.s.Exempt(ctx, req.GetGithubUserId(), req.GetGithubLogin(), req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pb.ExemptAccountResponse{Exemption: exemptionOf(e)}, nil
}

// RemoveExemption implements GitHubServiceHandler.
func (h *Handler) RemoveExemption(ctx context.Context, req *pb.RemoveExemptionRequest) (*pb.RemoveExemptionResponse, error) {
	return &pb.RemoveExemptionResponse{}, h.s.RemoveExemption(ctx, req.GetGithubUserId())
}

// ListExemptions implements GitHubServiceHandler.
func (h *Handler) ListExemptions(ctx context.Context, _ *pb.ListExemptionsRequest) (*pb.ListExemptionsResponse, error) {
	rows, err := h.s.Exemptions(ctx)
	if err != nil {
		return nil, err
	}
	out := &pb.ListExemptionsResponse{}
	for _, e := range rows {
		out.Exemptions = append(out.Exemptions, exemptionOf(e))
	}
	return out, nil
}

func scanOf(s app.Scan) *pb.OrgScan {
	out := &pb.OrgScan{
		Id: s.ID.String(), ConnectionId: s.ConnectionID.String(), State: s.State, Counts: s.Counts, Scanned: s.Scanned,
		NotScanned: s.NotScanned, StartedBy: s.StartedBy, CreateTime: timestamppb.New(s.CreatedAt),
	}
	if s.FinishedAt != nil {
		out.FinishTime = timestamppb.New(*s.FinishedAt)
	}
	return out
}

// StartOrgScan implements GitHubServiceHandler.
func (h *Handler) StartOrgScan(ctx context.Context, req *pb.StartOrgScanRequest) (*pb.StartOrgScanResponse, error) {
	conn, err := parseID(req.GetConnectionId())
	if err != nil {
		return nil, err
	}
	s, err := h.scans.Start(ctx, conn)
	if err != nil {
		return nil, err
	}
	return &pb.StartOrgScanResponse{Scan: scanOf(s)}, nil
}

// GetOrgScan implements GitHubServiceHandler.
func (h *Handler) GetOrgScan(ctx context.Context, req *pb.GetOrgScanRequest) (*pb.GetOrgScanResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	s, err := h.scans.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pb.GetOrgScanResponse{Scan: scanOf(s)}, nil
}
