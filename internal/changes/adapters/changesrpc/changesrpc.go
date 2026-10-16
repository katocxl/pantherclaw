// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package changesrpc serves ChangeService over Connect (G0 M11 part 2 D6).
// Handlers only translate; the use cases check the caller. Confirming is
// web only (the /changes pages).
package changesrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/changes"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Handler serves ChangeService.
type Handler struct {
	pantherclawv1connect.UnimplementedChangeServiceHandler
	svc *changes.Service
}

// New returns the ChangeService handler.
func New(svc *changes.Service) *Handler { return &Handler{svc: svc} }

var errID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "an id is not a UUID")

func parse(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil {
		return ids.UUID{}, errID
	}
	return id, nil
}

var states = map[string]pantherclawv1.ChangeRequestState{
	changes.StatePending:  pantherclawv1.ChangeRequestState_CHANGE_REQUEST_STATE_PENDING,
	changes.StateApproved: pantherclawv1.ChangeRequestState_CHANGE_REQUEST_STATE_APPROVED,
	changes.StateDeclined: pantherclawv1.ChangeRequestState_CHANGE_REQUEST_STATE_DECLINED,
	changes.StateExpired:  pantherclawv1.ChangeRequestState_CHANGE_REQUEST_STATE_EXPIRED,
	changes.StateVoided:   pantherclawv1.ChangeRequestState_CHANGE_REQUEST_STATE_VOIDED,
}

func ts(t *time.Time) *timestamppb.Timestamp {
	if t == nil || t.IsZero() {
		return nil
	}
	return timestamppb.New(*t)
}

// RequestPB converts a request.
func RequestPB(r changes.Request) *pantherclawv1.ChangeRequest {
	out := &pantherclawv1.ChangeRequest{
		Id: r.ID.String(), Domain: r.Domain, Kind: r.Kind, SubjectId: r.Subject.String(), ContentDigest: r.ContentDigest[:],
		Binding: r.Binding[:], Summary: string(r.Summary), Required: int32(r.Required), State: states[r.State], //nolint:gosec // 1..2
		RequestedBy: r.RequestedBy, CreatedAt: ts(&r.CreatedAt), ExpiresAt: ts(&r.ExpiresAt), DecidedAt: ts(r.DecidedAt),
		DecidedReason: r.DecidedReason,
	}
	for _, c := range r.Confirmations {
		out.Confirmations = append(out.Confirmations, &pantherclawv1.ChangeConfirmation{
			UserId: c.User.String(), CredentialId: c.Credential.String(), ConfirmedAt: ts(&c.At),
		})
	}
	return out
}

// GetChangeRequest implements ChangeServiceHandler.
func (h *Handler) GetChangeRequest(ctx context.Context, r *pantherclawv1.GetChangeRequestRequest) (*pantherclawv1.GetChangeRequestResponse, error) {
	id, err := parse(r.GetId())
	if err != nil {
		return nil, err
	}
	out, err := h.svc.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetChangeRequestResponse{Request: RequestPB(out)}, nil
}

// ListChangeRequests implements ChangeServiceHandler.
func (h *Handler) ListChangeRequests(ctx context.Context, r *pantherclawv1.ListChangeRequestsRequest) (*pantherclawv1.ListChangeRequestsResponse, error) {
	f := changes.Filter{Domain: r.GetDomain(), Limit: int(r.GetPageSize())}
	if f.Limit == 0 {
		f.Limit = 50
	}
	if r.SubjectId != nil {
		id, err := parse(r.GetSubjectId())
		if err != nil {
			return nil, err
		}
		f.Subject = id
	}
	if t := r.GetPageToken(); t != "" {
		id, err := parse(t)
		if err != nil {
			return nil, err
		}
		f.Before = id
	}
	for _, s := range r.GetStates() {
		for name, v := range states {
			if v == s {
				f.States = append(f.States, name)
			}
		}
	}
	rs, next, err := h.svc.List(ctx, f)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListChangeRequestsResponse{}
	for _, x := range rs {
		out.Requests = append(out.Requests, RequestPB(x))
	}
	if !next.IsZero() {
		out.NextPageToken = next.String()
	}
	return out, nil
}

// DeclineChangeRequest implements ChangeServiceHandler.
func (h *Handler) DeclineChangeRequest(ctx context.Context, r *pantherclawv1.DeclineChangeRequestRequest) (*pantherclawv1.DeclineChangeRequestResponse, error) {
	id, err := parse(r.GetId())
	if err != nil {
		return nil, err
	}
	out, err := h.svc.Decline(ctx, id, r.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.DeclineChangeRequestResponse{Request: RequestPB(out)}, nil
}
