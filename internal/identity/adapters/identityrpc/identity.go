// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package identityrpc serves IdentityService for people and services:
// enrollment tokens, instance admission and trusted-issuer entries (G0 M3).
// Handlers only translate; the use cases authorize where the agent lives.
package identityrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/app"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
)

// Identity serves IdentityService.
type Identity struct {
	pantherclawv1connect.UnimplementedIdentityServiceHandler
	svc      *app.Service
	clusters app.Clusters
}

// NewIdentity returns the IdentityService handler. clusters says which
// configured Kubernetes clusters each org may use.
func NewIdentity(svc *app.Service, clusters app.Clusters) *Identity {
	return &Identity{svc: svc, clusters: clusters}
}

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

func parseID(s string) (ids.UUID, error) {
	u, err := ids.ParseUUID(s)
	if err != nil || u.Version() != 7 {
		return ids.UUID{}, errInvalidID
	}
	return u, nil
}

func tsp(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

var instanceState = map[string]pantherclawv1.InstanceState{
	"PENDING_ADMISSION": pantherclawv1.InstanceState_INSTANCE_STATE_PENDING_ADMISSION,
	"ADMITTED":          pantherclawv1.InstanceState_INSTANCE_STATE_ADMITTED,
	"REJECTED":          pantherclawv1.InstanceState_INSTANCE_STATE_REJECTED,
	"REVOKED":           pantherclawv1.InstanceState_INSTANCE_STATE_REVOKED,
	"EXPIRED":           pantherclawv1.InstanceState_INSTANCE_STATE_EXPIRED,
}

var enrollmentPath = map[string]pantherclawv1.EnrollmentPath{
	"enrollment_token": pantherclawv1.EnrollmentPath_ENROLLMENT_PATH_ENROLLMENT_TOKEN,
	"attestation":      pantherclawv1.EnrollmentPath_ENROLLMENT_PATH_ATTESTATION,
	"discovery":        pantherclawv1.EnrollmentPath_ENROLLMENT_PATH_DISCOVERY,
}

func instanceProto(in app.Instance) *pantherclawv1.Instance {
	method := "fingerprint"
	if in.Level >= 2 {
		method = "attestation"
	}
	return &pantherclawv1.Instance{
		Id: in.ID.String(), AgentId: in.AgentID.String(), Identifier: in.Identifier.String(), Thumbprint: in.Thumbprint,
		State: instanceState[in.State], EnrolledVia: enrollmentPath[in.EnrolledVia],
		Verification: &pantherclawv1.Verification{
			Level: int32(in.Level), Method: method, AttestedUntil: tsp(in.AttestedUntil), //nolint:gosec // G115: 1 to 3
			LastVerifyTime: tsp(in.LastSeenAt), Binding: in.Binding, ReleaseState: in.ReleaseState,
			ReleaseDigest: in.ReleaseDigest, NeedsReview: in.NeedsReview,
		},
		LastNetwork: in.LastNetwork, LastSeenTime: tsp(in.LastSeenAt), DecidedBy: in.DecidedBy, DecideTime: tsp(in.DecidedAt),
		RevokeReason: in.RevokeReason, CreateTime: timestamppb.New(in.CreatedAt), ExpireTime: tsp(in.ExpiresAt),
	}
}

// CreateEnrollmentToken implements IdentityServiceHandler.
func (s *Identity) CreateEnrollmentToken(ctx context.Context, req *pantherclawv1.CreateEnrollmentTokenRequest) (*pantherclawv1.CreateEnrollmentTokenResponse, error) {
	agent, err := parseID(req.GetAgentId())
	if err != nil {
		return nil, err
	}
	et, err := s.svc.CreateEnrollmentToken(ctx, agent, time.Duration(req.GetTtlMinutes())*time.Minute)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateEnrollmentTokenResponse{
		Id: et.ID.String(), Token: et.Secret.Reveal(), ExpireTime: timestamppb.New(et.ExpiresAt),
	}, nil
}

// ListInstances implements IdentityServiceHandler.
func (s *Identity) ListInstances(ctx context.Context, req *pantherclawv1.ListInstancesRequest) (*pantherclawv1.ListInstancesResponse, error) {
	agent, err := parseID(req.GetAgentId())
	if err != nil {
		return nil, err
	}
	pr, err := page.Parse(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	var states []string
	for _, st := range req.GetStates() {
		for k, v := range instanceState {
			if v == st {
				states = append(states, k)
			}
		}
	}
	items, next, err := s.svc.ListInstances(ctx, agent, pr, states)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListInstancesResponse{NextPageToken: next}
	for _, in := range items {
		out.Instances = append(out.Instances, instanceProto(in))
	}
	return out, nil
}

// GetInstance implements IdentityServiceHandler.
func (s *Identity) GetInstance(ctx context.Context, req *pantherclawv1.GetInstanceRequest) (*pantherclawv1.GetInstanceResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	in, err := s.svc.GetInstance(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetInstanceResponse{Instance: instanceProto(in)}, nil
}

// AdmitInstance implements IdentityServiceHandler.
func (s *Identity) AdmitInstance(ctx context.Context, req *pantherclawv1.AdmitInstanceRequest) (*pantherclawv1.AdmitInstanceResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	in, err := s.svc.Admit(ctx, id, req.GetFingerprint())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.AdmitInstanceResponse{Instance: instanceProto(in)}, nil
}

// RejectInstance implements IdentityServiceHandler.
func (s *Identity) RejectInstance(ctx context.Context, req *pantherclawv1.RejectInstanceRequest) (*pantherclawv1.RejectInstanceResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	in, err := s.svc.Reject(ctx, id, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RejectInstanceResponse{Instance: instanceProto(in)}, nil
}

// RevokeInstance implements IdentityServiceHandler.
func (s *Identity) RevokeInstance(ctx context.Context, req *pantherclawv1.RevokeInstanceRequest) (*pantherclawv1.RevokeInstanceResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	in, err := s.svc.Revoke(ctx, id, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RevokeInstanceResponse{Instance: instanceProto(in)}, nil
}
