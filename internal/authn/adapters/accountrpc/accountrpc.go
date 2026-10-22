// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package accountrpc serves AccountService over Connect: people's own
// sessions and security keys, and their administration (G0 M5 part 1).
package accountrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

// Handler implements AccountServiceHandler.
type Handler struct {
	a   *authnapp.Account
	del AccountDeleter
}

// New returns the handler.
func New(a *authnapp.Account) *Handler { return &Handler{a: a} }

var _ pantherclawv1connect.AccountServiceHandler = (*Handler)(nil)

func parse(s string) (ids.UUID, error) {
	u, err := ids.ParseUUID(s)
	if err != nil {
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

func tsp(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return ts(*t)
}

func sessions(in []authnapp.SessionView) []*pantherclawv1.Session {
	out := make([]*pantherclawv1.Session, len(in))
	for i, s := range in {
		kind := pantherclawv1.SessionKind_SESSION_KIND_BROWSER
		if s.Kind == authnapp.SessionCLI {
			kind = pantherclawv1.SessionKind_SESSION_KIND_CLI
		}
		out[i] = &pantherclawv1.Session{
			Id: s.ID.String(), Kind: kind, Device: s.Device, ClientAddress: s.Address, Active: s.Active,
			EndReason: s.EndReason, CreateTime: ts(s.CreatedAt), LastSeenTime: tsp(s.LastSeen), ExpireTime: ts(s.ExpiresAt),
		}
	}
	return out
}

var keyStates = map[string]pantherclawv1.KeyState{
	"ACTIVE": pantherclawv1.KeyState_KEY_STATE_ACTIVE, "SUSPENDED": pantherclawv1.KeyState_KEY_STATE_SUSPENDED,
	"REMOVED": pantherclawv1.KeyState_KEY_STATE_REMOVED,
}

func keys(in []authnapp.CredentialInfo) []*pantherclawv1.SecurityKey {
	out := make([]*pantherclawv1.SecurityKey, len(in))
	for i, k := range in {
		out[i] = &pantherclawv1.SecurityKey{
			Id: k.ID.String(), Name: k.Name, Algorithm: k.Algorithm, Synced: k.Synced, State: keyStates[k.State],
			StateReason: k.StateReason, CreateTime: ts(k.CreatedAt), LastUseTime: tsp(k.LastUsedAt), Transports: k.Transports,
		}
	}
	return out
}

// ListMySessions implements AccountServiceHandler.
func (h *Handler) ListMySessions(ctx context.Context, _ *pantherclawv1.ListMySessionsRequest) (*pantherclawv1.ListMySessionsResponse, error) {
	s, err := h.a.ListMySessions(ctx)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ListMySessionsResponse{Sessions: sessions(s)}, nil
}

// RevokeMySession implements AccountServiceHandler.
func (h *Handler) RevokeMySession(ctx context.Context, req *pantherclawv1.RevokeMySessionRequest) (*pantherclawv1.RevokeMySessionResponse, error) {
	id, err := parse(req.GetId())
	if err != nil {
		return nil, err
	}
	if err := h.a.RevokeMySession(ctx, id); err != nil {
		return nil, err
	}
	return &pantherclawv1.RevokeMySessionResponse{}, nil
}

// ListMyKeys implements AccountServiceHandler.
func (h *Handler) ListMyKeys(ctx context.Context, _ *pantherclawv1.ListMyKeysRequest) (*pantherclawv1.ListMyKeysResponse, error) {
	k, err := h.a.ListMyKeys(ctx)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ListMyKeysResponse{Keys: keys(k)}, nil
}

// ListUserSessions implements AccountServiceHandler.
func (h *Handler) ListUserSessions(ctx context.Context, req *pantherclawv1.ListUserSessionsRequest) (*pantherclawv1.ListUserSessionsResponse, error) {
	user, err := parse(req.GetUserId())
	if err != nil {
		return nil, err
	}
	s, err := h.a.ListUserSessions(ctx, user)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ListUserSessionsResponse{Sessions: sessions(s)}, nil
}

// ListUserKeys implements AccountServiceHandler.
func (h *Handler) ListUserKeys(ctx context.Context, req *pantherclawv1.ListUserKeysRequest) (*pantherclawv1.ListUserKeysResponse, error) {
	user, err := parse(req.GetUserId())
	if err != nil {
		return nil, err
	}
	k, err := h.a.ListUserKeys(ctx, user)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ListUserKeysResponse{Keys: keys(k)}, nil
}

// RevokeUserSessions implements AccountServiceHandler.
func (h *Handler) RevokeUserSessions(ctx context.Context, req *pantherclawv1.RevokeUserSessionsRequest) (*pantherclawv1.RevokeUserSessionsResponse, error) {
	user, err := parse(req.GetUserId())
	if err != nil {
		return nil, err
	}
	n, err := h.a.RevokeUserSessions(ctx, user)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RevokeUserSessionsResponse{Revoked: int32(min(n, 1<<30))}, nil //nolint:gosec // G115: bounded
}

// RemoveUserKey implements AccountServiceHandler.
func (h *Handler) RemoveUserKey(ctx context.Context, req *pantherclawv1.RemoveUserKeyRequest) (*pantherclawv1.RemoveUserKeyResponse, error) {
	user, err := parse(req.GetUserId())
	if err != nil {
		return nil, err
	}
	key, err := parse(req.GetKeyId())
	if err != nil {
		return nil, err
	}
	if err := h.a.RemoveUserKey(ctx, user, key); err != nil {
		return nil, err
	}
	return &pantherclawv1.RemoveUserKeyResponse{}, nil
}
