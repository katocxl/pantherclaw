// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package sandboxrpc serves SandboxService over Connect (G0 M9 track B).
// Handlers only translate: authentication, the coarse permission check and
// protovalidate have run before a handler is called, and the use cases
// check the caller's permission over each agent. RPCs not yet built answer
// Unimplemented.
package sandboxrpc

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/sandboxes/app"
)

// Handler serves SandboxService.
type Handler struct {
	pantherclawv1connect.UnimplementedSandboxServiceHandler
	svc *app.Service
}

// New returns the SandboxService handler.
func New(svc *app.Service) *Handler { return &Handler{svc: svc} }

// StartSession implements SandboxServiceHandler.
func (h *Handler) StartSession(ctx context.Context, r *pantherclawv1.SandboxServiceStartSessionRequest) (*pantherclawv1.SandboxServiceStartSessionResponse, error) {
	in := app.StartInput{
		AgentImage: r.GetImages().GetAgent(), EdgeImage: r.GetImages().GetEdge(), ProbeImage: r.GetImages().GetProbe(),
		ConfigDigest: r.GetConfigDigest(), ProbeKey: ed25519.PublicKey(r.GetProbePublicKey()), HostKey: ed25519.PublicKey(r.GetHostPublicKey()),
		EngineVersion: r.GetEngine().GetVersion(), EngineAPI: r.GetEngine().GetApiVersion(), Runtime: r.GetEngine().GetRuntime(),
		TTL: r.GetTtl().AsDuration(),
	}
	var err error
	if in.Agent, err = ids.ParseUUID(r.GetAgentId()); err != nil {
		return nil, app.ErrNotFound
	}
	for _, c := range r.GetConnectionIds() {
		id, err := ids.ParseUUID(c)
		if err != nil {
			return nil, app.ErrConnections
		}
		in.Connections = append(in.Connections, id)
	}
	s, err := h.svc.StartSession(ctx, in)
	if err != nil {
		return nil, err
	}
	return started(s), nil
}

// started is an opened session's answer. It reveals the enrollment
// token, shown this once, so that pclaw can enroll the sandbox instance:
// the token's String is redacted, for logs.
func started(s app.Started) *pantherclawv1.SandboxServiceStartSessionResponse {
	return &pantherclawv1.SandboxServiceStartSessionResponse{
		Session: session(s.Session, s.Connections), EnrollmentToken: s.EnrollmentToken.Reveal(), Nonces: nonces(s.Nonces),
		AgentHosts: s.AgentHosts,
	}
}

// GetSession implements SandboxServiceHandler.
func (h *Handler) GetSession(ctx context.Context, r *pantherclawv1.SandboxServiceGetSessionRequest) (*pantherclawv1.SandboxServiceGetSessionResponse, error) {
	id, err := ids.ParseUUID(r.GetSessionId())
	if err != nil {
		return nil, app.ErrNotFound
	}
	s, conns, err := h.svc.GetSession(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.SandboxServiceGetSessionResponse{Session: session(s, conns)}, nil
}

// ListSessions implements SandboxServiceHandler.
func (h *Handler) ListSessions(ctx context.Context, r *pantherclawv1.SandboxServiceListSessionsRequest) (*pantherclawv1.SandboxServiceListSessionsResponse, error) {
	size := r.GetPageSize()
	if size <= 0 || size > 200 {
		size = 50
	}
	var agent, after *ids.UUID
	if r.GetAgentId() != "" {
		u, err := ids.ParseUUID(r.GetAgentId())
		if err != nil {
			return nil, app.ErrNotFound
		}
		agent = &u
	}
	if r.GetPageToken() != "" {
		b, err := base64.RawURLEncoding.DecodeString(r.GetPageToken())
		if err != nil {
			return nil, app.ErrNotFound
		}
		u, err := ids.ParseUUID(string(b))
		if err != nil {
			return nil, app.ErrNotFound
		}
		after = &u
	}
	rows, err := h.svc.ListSessions(ctx, agent, after, size+1)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.SandboxServiceListSessionsResponse{}
	if len(rows) > int(size) {
		rows = rows[:size]
		out.NextPageToken = base64.RawURLEncoding.EncodeToString([]byte(rows[len(rows)-1].ID.String()))
	}
	for _, s := range rows {
		out.Sessions = append(out.Sessions, session(s, nil))
	}
	return out, nil
}

var states = map[string]pantherclawv1.SandboxSessionState{
	"OPEN":    pantherclawv1.SandboxSessionState_SANDBOX_SESSION_STATE_OPEN,
	"ENDED":   pantherclawv1.SandboxSessionState_SANDBOX_SESSION_STATE_ENDED,
	"EXPIRED": pantherclawv1.SandboxSessionState_SANDBOX_SESSION_STATE_EXPIRED,
}

func session(s dbq.PcSandboxSession, conns []ids.UUID) *pantherclawv1.SandboxSession {
	out := &pantherclawv1.SandboxSession{
		Id: s.ID.String(), AgentId: s.AgentID.String(), Launcher: s.Launcher,
		Images:       &pantherclawv1.SandboxImages{Agent: s.AgentImage, Edge: s.EdgeImage, Probe: s.ProbeImage},
		ConfigDigest: s.ConfigDigest, ProbeKeyThumbprint: s.ProbeJkt, HostKeyThumbprint: s.HostJkt,
		Engine:   &pantherclawv1.SandboxEngine{Version: s.EngineVersion, ApiVersion: s.ApiVersion, Runtime: s.Runtime},
		State:    states[s.State],
		OpenTime: timestamppb.New(s.OpenedAt), ExpireTime: timestamppb.New(s.ExpiresAt),
	}
	if s.InstanceID != nil {
		out.InstanceId = s.InstanceID.String()
	}
	if s.RunID != nil {
		out.RunId = s.RunID.String()
	}
	if s.EndedAt != nil {
		out.EndTime = timestamppb.New(*s.EndedAt)
	}
	for _, c := range conns {
		out.ConnectionIds = append(out.ConnectionIds, c.String())
	}
	return out
}

func nonces(n app.Nonces) *pantherclawv1.ProbeNonces {
	return &pantherclawv1.ProbeNonces{Sandbox: n.Sandbox, Control: n.Control, Canary: n.Canary, ExpireTime: timestamppb.New(n.ExpiresAt)}
}
