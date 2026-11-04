// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package ownedrpc serves OwnedAccountService over Connect (G0 M30 D933).
package ownedrpc

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/ownedaccounts/app"
	"github.com/katocxl/pantherclaw/internal/ownedaccounts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Handler serves OwnedAccountService.
type Handler struct {
	pantherclawv1connect.UnimplementedOwnedAccountServiceHandler
	s *app.Service
}

// New returns the handler.
func New(s *app.Service) *Handler { return &Handler{s: s} }

// ListOwnedAccounts implements OwnedAccountServiceHandler.
func (h *Handler) ListOwnedAccounts(ctx context.Context, _ *pantherclawv1.ListOwnedAccountsRequest) (*pantherclawv1.ListOwnedAccountsResponse, error) {
	rows, err := h.s.List(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListOwnedAccountsResponse{}
	for _, r := range rows {
		out.Accounts = append(out.Accounts, &pantherclawv1.OwnedAccount{
			Id: r.ID.String(), Kind: r.Kind, Value: r.Value, AddedBy: r.AddedBy, AddTime: timestamppb.New(r.AddedAt),
		})
	}
	return out, nil
}

// AddOwnedAccount implements OwnedAccountServiceHandler.
func (h *Handler) AddOwnedAccount(ctx context.Context, req *pantherclawv1.AddOwnedAccountRequest) (*pantherclawv1.AddOwnedAccountResponse, error) {
	held, err := h.s.Add(ctx, domain.Kind(req.GetKind()), req.GetValue(), req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.AddOwnedAccountResponse{ProtectedChangeId: held.Change.String()}, nil
}

// RemoveOwnedAccount implements OwnedAccountServiceHandler.
func (h *Handler) RemoveOwnedAccount(ctx context.Context, req *pantherclawv1.RemoveOwnedAccountRequest) (*pantherclawv1.RemoveOwnedAccountResponse, error) {
	id, err := ids.ParseUUID(req.GetId())
	if err != nil {
		return nil, app.ErrMissing
	}
	if err := h.s.Remove(ctx, id, req.GetReason()); err != nil {
		return nil, err
	}
	return &pantherclawv1.RemoveOwnedAccountResponse{}, nil
}
