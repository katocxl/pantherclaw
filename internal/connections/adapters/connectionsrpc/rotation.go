// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package connectionsrpc

import (
	"context"
	"encoding/hex"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	credapp "github.com/katocxl/pantherclaw/internal/credentials/app"
	creddomain "github.com/katocxl/pantherclaw/internal/credentials/domain"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// Rotations serves CredentialRotationService (G0 M22 D5, F831, HR-553),
// one to one over the rotation use cases: permissions, the protected change
// and audit stay theirs, and no response carries a key.
//
// An RPC has no browser session, so it has no step-up: ActivateRotation and
// RollBackRotation pass none and the use case refuses with STEP_UP_REQUIRED
// (T-240). A person uses the server page.
type Rotations struct {
	pantherclawv1connect.UnimplementedCredentialRotationServiceHandler
	creds *credapp.Service
}

// NewRotations returns the CredentialRotationService handler.
func NewRotations(creds *credapp.Service) *Rotations { return &Rotations{creds: creds} }

var _ pantherclawv1connect.CredentialRotationServiceHandler = (*Rotations)(nil)

func text(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func optStamp(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

// rotationOf maps a rotation. The row's task ids stay out: they lease a key
// to a gateway.
func rotationOf(r credapp.Rotation) *pb.CredentialRotation {
	out := &pb.CredentialRotation{
		Id: r.ID.String(), ConnectionId: r.ConnectionID.String(), State: r.State, OldCredentialId: r.OldCredentialID.String(),
		PreviewDigest: r.PreviewDigest, RequestedBy: r.RequestedBy, TestPassTime: optStamp(r.TestPassedAt), ActivatedBy: text(r.ActivatedBy),
		ActivateTime: optStamp(r.ActivatedAt), RollbackUntil: optStamp(r.RollbackUntil), ConfirmTime: optStamp(r.ConfirmedAt),
		AwaitingSince: optStamp(r.AwaitingSince), EndReason: text(r.EndReason), CreateTime: timestamppb.New(r.CreatedAt),
		UpdateTime: timestamppb.New(r.UpdatedAt), FinishTime: optStamp(r.FinishedAt),
	}
	if r.CandidateCredentialID != nil {
		out.CandidateCredentialId = r.CandidateCredentialID.String()
	}
	return out
}

// RequestRotation implements CredentialRotationServiceHandler.
func (h *Rotations) RequestRotation(ctx context.Context, req *pb.RequestRotationRequest) (*pb.RequestRotationResponse, error) {
	id, err := parseID(req.GetConnectionId())
	if err != nil {
		return nil, err
	}
	digest, err := hex.DecodeString(req.GetPreviewDigest())
	if err != nil {
		return nil, credapp.ErrRotationPreview
	}
	r, err := h.creds.RequestRotation(ctx, id, digest)
	if err != nil {
		return nil, err
	}
	return &pb.RequestRotationResponse{Rotation: rotationOf(r)}, nil
}

// SealRotationCandidate implements CredentialRotationServiceHandler.
func (h *Rotations) SealRotationCandidate(ctx context.Context, req *pb.SealRotationCandidateRequest) (*pb.SealRotationCandidateResponse, error) {
	id, err := parseID(req.GetRotationId())
	if err != nil {
		return nil, err
	}
	c := req.GetCredential()
	conn, err := parseID(c.GetConnectionId())
	if err != nil {
		return nil, err
	}
	key, err := parseID(c.GetBrokerKeyId())
	if err != nil {
		return nil, err
	}
	in := credapp.PutInput{
		Connection: conn, BrokerKey: key, Version: c.GetVersion(), Sealed: c.GetSealed(), AllowedHosts: c.GetAllowedHosts(),
		Header: c.GetHeader(), Scheme: c.GetScheme(), Kind: c.GetKind(),
	}
	if gh := c.GetGithub(); gh != nil {
		in.GitHub = &creddomain.Installation{AppClientID: gh.GetAppClientId(), ID: gh.GetInstallationId(), Account: gh.GetAccountLogin()}
	}
	m, err := h.creds.SealCandidate(ctx, id, in)
	if err != nil {
		return nil, err
	}
	return &pb.SealRotationCandidateResponse{Credential: credentialOf(m)}, nil
}

// TestRotation implements CredentialRotationServiceHandler.
func (h *Rotations) TestRotation(ctx context.Context, req *pb.TestRotationRequest) (*pb.TestRotationResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	r, err := h.creds.TestRotation(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pb.TestRotationResponse{Rotation: rotationOf(r)}, nil
}

// ActivateRotation implements CredentialRotationServiceHandler. No step-up
// exists here, so the use case refuses.
func (h *Rotations) ActivateRotation(ctx context.Context, req *pb.ActivateRotationRequest) (*pb.ActivateRotationResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	r, err := h.creds.ActivateRotation(ctx, id, credapp.StepUp{})
	if err != nil {
		return nil, err
	}
	return &pb.ActivateRotationResponse{Rotation: rotationOf(r)}, nil
}

// RollBackRotation implements CredentialRotationServiceHandler. No step-up
// exists here, so the use case refuses.
func (h *Rotations) RollBackRotation(ctx context.Context, req *pb.RollBackRotationRequest) (*pb.RollBackRotationResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	r, err := h.creds.RollBackRotation(ctx, id, req.GetReason(), credapp.StepUp{})
	if err != nil {
		return nil, err
	}
	return &pb.RollBackRotationResponse{Rotation: rotationOf(r)}, nil
}

// ConfirmRotation implements CredentialRotationServiceHandler.
func (h *Rotations) ConfirmRotation(ctx context.Context, req *pb.ConfirmRotationRequest) (*pb.ConfirmRotationResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	r, err := h.creds.ConfirmRotation(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pb.ConfirmRotationResponse{Rotation: rotationOf(r)}, nil
}

// CancelRotation implements CredentialRotationServiceHandler.
func (h *Rotations) CancelRotation(ctx context.Context, req *pb.CancelRotationRequest) (*pb.CancelRotationResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	r, err := h.creds.CancelRotation(ctx, id, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pb.CancelRotationResponse{Rotation: rotationOf(r)}, nil
}

// GetRotation implements CredentialRotationServiceHandler.
func (h *Rotations) GetRotation(ctx context.Context, req *pb.GetRotationRequest) (*pb.GetRotationResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	r, err := h.creds.GetRotation(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pb.GetRotationResponse{Rotation: rotationOf(r)}, nil
}

// ListRotations implements CredentialRotationServiceHandler.
func (h *Rotations) ListRotations(ctx context.Context, req *pb.ListRotationsRequest) (*pb.ListRotationsResponse, error) {
	id, err := parseID(req.GetConnectionId())
	if err != nil {
		return nil, err
	}
	rows, err := h.creds.ListRotations(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &pb.ListRotationsResponse{}
	for _, r := range rows {
		out.Rotations = append(out.Rotations, rotationOf(r))
	}
	return out, nil
}
