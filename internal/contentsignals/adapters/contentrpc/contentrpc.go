// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package contentrpc serves ContentSignalService over Connect (G0 M27 D507).
package contentrpc

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/contentsignals/app"
	"github.com/katocxl/pantherclaw/internal/contentsignals/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// Handler serves ContentSignalService.
type Handler struct {
	pantherclawv1connect.UnimplementedContentSignalServiceHandler
	s *app.Service
}

// New returns the handler.
func New(s *app.Service) *Handler { return &Handler{s: s} }

var modeOf = map[domain.Mode]pantherclawv1.ContentSignalMode{
	domain.ModeOff:      pantherclawv1.ContentSignalMode_CONTENT_SIGNAL_MODE_OFF,
	domain.ModeWatching: pantherclawv1.ContentSignalMode_CONTENT_SIGNAL_MODE_WATCHING,
	domain.ModeActive:   pantherclawv1.ContentSignalMode_CONTENT_SIGNAL_MODE_ACTIVE,
}

// ModeProto is a mode on the wire.
func ModeProto(m domain.Mode) pantherclawv1.ContentSignalMode { return modeOf[m] }

func modeFrom(m pantherclawv1.ContentSignalMode) domain.Mode {
	for d, p := range modeOf {
		if p == m {
			return d
		}
	}
	return ""
}

func settings(s app.Settings) *pantherclawv1.ContentSignalSettings {
	out := &pantherclawv1.ContentSignalSettings{Mode: modeOf[s.Mode()], NotInspected: domain.NotInspectedFaces, NotInspectedNote: domain.NotScanned}
	if s.Row.UpdatedBy != nil {
		out.UpdatedBy = *s.Row.UpdatedBy
		out.UpdateTime = timestamppb.New(s.Row.UpdatedAt)
	}
	for _, w := range s.WouldHold {
		out.WouldHold = append(out.WouldHold, &pantherclawv1.ContentWouldHold{
			Reason: w.Reason, Count: w.Count, FirstTime: timestamppb.New(w.FirstAt), LastTime: timestamppb.New(w.LastAt),
		})
	}
	return out
}

// GetSettings implements ContentSignalServiceHandler.
func (h *Handler) GetSettings(ctx context.Context, _ *pantherclawv1.GetSettingsRequest) (*pantherclawv1.GetSettingsResponse, error) {
	s, err := h.s.Get(ctx)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetSettingsResponse{Settings: settings(s)}, nil
}

// SetMode implements ContentSignalServiceHandler.
func (h *Handler) SetMode(ctx context.Context, req *pantherclawv1.SetModeRequest) (*pantherclawv1.SetModeResponse, error) {
	r, err := h.s.SetMode(ctx, modeFrom(req.GetMode()), req.GetReason())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.SetModeResponse{Settings: settings(r.Settings)}
	if r.Held != nil {
		out.Change = &pantherclawv1.ProtectedChangeFiled{ProtectedChangeId: r.Held.Change.String(), ChangeRequestId: r.Held.Request.String()}
	}
	return out, nil
}
