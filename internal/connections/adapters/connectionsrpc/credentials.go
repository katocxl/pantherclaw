// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package connectionsrpc

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	credapp "github.com/katocxl/pantherclaw/internal/credentials/app"
	creddomain "github.com/katocxl/pantherclaw/internal/credentials/domain"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

var credentialStates = map[string]pb.SealedCredentialState{
	"ACTIVE": pb.SealedCredentialState_SEALED_CREDENTIAL_STATE_ACTIVE, "SUPERSEDED": pb.SealedCredentialState_SEALED_CREDENTIAL_STATE_SUPERSEDED,
	"REVOKED": pb.SealedCredentialState_SEALED_CREDENTIAL_STATE_REVOKED, "CANDIDATE": pb.SealedCredentialState_SEALED_CREDENTIAL_STATE_CANDIDATE,
}

func credentialOf(m credapp.Metadata) *pb.ConnectionCredential {
	return &pb.ConnectionCredential{
		Id: m.ID.String(), ConnectionId: m.ConnectionID.String(), Version: m.Version, BrokerKeyId: m.BrokerKeyID.String(),
		BrokerKeyFingerprint: m.BrokerKeyFingerprint, AllowedHosts: m.AllowedHosts, Header: m.Header, Scheme: deref(m.Scheme),
		State: credentialStates[m.State], CreatedBy: m.CreatedBy, CreateTime: timestamppb.New(m.CreatedAt), Kind: m.Kind,
	}
}

// GetSealingKey implements ConnectionServiceHandler.
func (h *Handler) GetSealingKey(ctx context.Context, req *pb.GetSealingKeyRequest) (*pb.GetSealingKeyResponse, error) {
	id, err := parseID(req.GetConnectionId())
	if err != nil {
		return nil, err
	}
	k, err := h.creds.GetSealingKey(ctx, id)
	if err != nil {
		return nil, err
	}
	b := k.Binding
	return &pb.GetSealingKeyResponse{
		OrgId: b.Org, ConnectionId: b.Connection, Version: b.Version, BrokerKeyId: b.BrokerKey, PublicKey: k.PublicKey,
		Fingerprint: k.Fingerprint, GatewayId: k.Gateway.String(), AllowedHosts: b.AllowedHosts, Header: b.Header, Scheme: b.Scheme,
	}, nil
}

// PutCredential implements ConnectionServiceHandler.
func (h *Handler) PutCredential(ctx context.Context, req *pb.PutCredentialRequest) (*pb.PutCredentialResponse, error) {
	id, err := parseID(req.GetConnectionId())
	if err != nil {
		return nil, err
	}
	key, err := parseID(req.GetBrokerKeyId())
	if err != nil {
		return nil, err
	}
	in := credapp.PutInput{
		Connection: id, BrokerKey: key, Version: req.GetVersion(), Sealed: req.GetSealed(), AllowedHosts: req.GetAllowedHosts(),
		Header: req.GetHeader(), Scheme: req.GetScheme(), Kind: req.GetKind(),
	}
	if gh := req.GetGithub(); gh != nil {
		in.GitHub = &creddomain.Installation{AppClientID: gh.GetAppClientId(), ID: gh.GetInstallationId(), Account: gh.GetAccountLogin()}
	}
	m, err := h.creds.PutCredential(ctx, in)
	if err != nil {
		return nil, err
	}
	return &pb.PutCredentialResponse{Credential: credentialOf(m)}, nil
}

// ListCredentials implements ConnectionServiceHandler.
func (h *Handler) ListCredentials(ctx context.Context, req *pb.ListCredentialsRequest) (*pb.ListCredentialsResponse, error) {
	id, err := parseID(req.GetConnectionId())
	if err != nil {
		return nil, err
	}
	rows, err := h.creds.ListCredentials(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &pb.ListCredentialsResponse{}
	for _, m := range rows {
		out.Credentials = append(out.Credentials, credentialOf(m))
	}
	return out, nil
}

// RevokeCredential implements ConnectionServiceHandler.
func (h *Handler) RevokeCredential(ctx context.Context, req *pb.RevokeCredentialRequest) (*pb.RevokeCredentialResponse, error) {
	id, err := parseID(req.GetConnectionId())
	if err != nil {
		return nil, err
	}
	if err := h.creds.RevokeCredential(ctx, id, req.GetVersion()); err != nil {
		return nil, err
	}
	return &pb.RevokeCredentialResponse{}, nil
}

// activeCredential is the active credential of a connection, or nil; a
// caller without connection.read already failed the connection read.
func (h *Handler) activeCredential(ctx context.Context, c *pb.Connection) (*pb.ConnectionCredential, error) {
	id, err := parseID(c.GetId())
	if err != nil {
		return nil, err
	}
	rows, err := h.creds.ListCredentials(ctx, id)
	if err != nil {
		return nil, err
	}
	for _, m := range rows {
		if m.State == "ACTIVE" {
			return credentialOf(m), nil
		}
	}
	return nil, nil
}
