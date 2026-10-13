// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package releasesrpc serves ChangeWindowService (G0 M8, HR-207).
package releasesrpc

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	rapp "github.com/katocxl/pantherclaw/internal/releases/app"
	"github.com/katocxl/pantherclaw/internal/releases/domain"
)

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

// Handler serves ChangeWindowService.
type Handler struct {
	pantherclawv1connect.UnimplementedChangeWindowServiceHandler
	s *rapp.Service
}

// New returns a handler over s.
func New(s *rapp.Service) *Handler { return &Handler{s: s} }

// CreateChangeWindow implements ChangeWindowServiceHandler.
func (h *Handler) CreateChangeWindow(ctx context.Context, req *pb.CreateChangeWindowRequest) (*pb.CreateChangeWindowResponse, error) {
	w := domain.Window{Environment: req.GetEnvironment(), Repository: req.GetRepository(), TimeZone: req.GetTimeZone()}
	for _, e := range req.GetWeekly() {
		w.Weekly = append(w.Weekly, domain.Weekly{Day: e.GetDay(), Start: e.GetStart(), Minutes: int(e.GetMinutes())})
	}
	w.OneOff, w.Freezes = spans(req.GetOneOff()), spans(req.GetFreezes())
	r, err := h.s.Create(ctx, w)
	if err != nil {
		return nil, err
	}
	return &pb.CreateChangeWindowResponse{Window: windowOf(r)}, nil
}

// ListChangeWindows implements ChangeWindowServiceHandler.
func (h *Handler) ListChangeWindows(ctx context.Context, req *pb.ListChangeWindowsRequest) (*pb.ListChangeWindowsResponse, error) {
	rs, err := h.s.List(ctx, req.GetEnvironment(), req.GetIncludeRetired())
	if err != nil {
		return nil, err
	}
	out := &pb.ListChangeWindowsResponse{}
	for _, r := range rs {
		out.Windows = append(out.Windows, windowOf(r))
	}
	return out, nil
}

// RetireChangeWindow implements ChangeWindowServiceHandler.
func (h *Handler) RetireChangeWindow(ctx context.Context, req *pb.RetireChangeWindowRequest) (*pb.RetireChangeWindowResponse, error) {
	id, err := ids.ParseUUID(req.GetId())
	if err != nil {
		return nil, errInvalidID
	}
	r, err := h.s.Retire(ctx, id, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pb.RetireChangeWindowResponse{Window: windowOf(r)}, nil
}

// GetActiveWindows implements ChangeWindowServiceHandler.
func (h *Handler) GetActiveWindows(ctx context.Context, req *pb.GetActiveWindowsRequest) (*pb.GetActiveWindowsResponse, error) {
	d, err := h.s.Active(ctx, req.GetEnvironment(), req.GetRepository())
	if err != nil {
		return nil, err
	}
	out := &pb.GetActiveWindowsResponse{State: string(d.State), DecideTime: timestamppb.New(d.At)}
	for _, r := range d.Windows {
		out.Windows = append(out.Windows, windowOf(r))
	}
	return out, nil
}

func spans(in []*pb.TimeSpan) []domain.Span {
	var out []domain.Span
	for _, s := range in {
		out = append(out, domain.Span{Start: s.GetStartTime().AsTime(), End: s.GetEndTime().AsTime()})
	}
	return out
}

func windowOf(r rapp.Record) *pb.ChangeWindow {
	out := &pb.ChangeWindow{
		Id: r.ID.String(), Environment: r.Environment, Repository: r.Repository, TimeZone: r.TimeZone, Revision: int32(r.Revision), //nolint:gosec // G115: a revision counter
		State: r.State, CreatedBy: r.CreatedBy, CreateTime: timestamppb.New(r.CreatedAt), RetiredBy: r.RetiredBy,
	}
	if r.RetiredAt != nil {
		out.RetireTime = timestamppb.New(*r.RetiredAt)
	}
	for _, e := range r.Weekly {
		out.Weekly = append(out.Weekly, &pb.WeeklyEntry{Day: e.Day, Start: e.Start, Minutes: int32(e.Minutes)}) //nolint:gosec // G115: at most 1440
	}
	for _, s := range r.OneOff {
		out.OneOff = append(out.OneOff, &pb.TimeSpan{StartTime: timestamppb.New(s.Start), EndTime: timestamppb.New(s.End)})
	}
	for _, s := range r.Freezes {
		out.Freezes = append(out.Freezes, &pb.TimeSpan{StartTime: timestamppb.New(s.Start), EndTime: timestamppb.New(s.End)})
	}
	return out
}
