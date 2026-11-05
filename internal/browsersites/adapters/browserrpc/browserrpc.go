// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package browserrpc serves BrowserService over Connect (G0 M33 D976).
package browserrpc

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/browsersites/app"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Handler serves BrowserService.
type Handler struct {
	pantherclawv1connect.UnimplementedBrowserServiceHandler
	s *app.Service
}

// New returns the handler.
func New(s *app.Service) *Handler { return &Handler{s: s} }

// ListBrowserSites implements BrowserServiceHandler.
func (h *Handler) ListBrowserSites(ctx context.Context, _ *pantherclawv1.ListBrowserSitesRequest) (*pantherclawv1.ListBrowserSitesResponse, error) {
	rows, err := h.s.List(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListBrowserSitesResponse{}
	for _, r := range rows {
		out.Sites = append(out.Sites, &pantherclawv1.BrowserSite{
			Id: r.ID.String(), Host: r.Host, IncludeSubdomains: r.IncludeSubdomains, Compare: r.Compare,
			ClickSelectors: r.ClickSelectors, Note: r.Note, CreatedBy: r.CreatedBy, CreateTime: timestamppb.New(r.CreatedAt),
		})
	}
	return out, nil
}

// AddBrowserSite implements BrowserServiceHandler.
func (h *Handler) AddBrowserSite(ctx context.Context, req *pantherclawv1.AddBrowserSiteRequest) (*pantherclawv1.AddBrowserSiteResponse, error) {
	held, err := h.s.Add(ctx, app.Site{
		Host: req.GetHost(), IncludeSubdomains: req.GetIncludeSubdomains(), Compare: req.GetCompare(),
		ClickSelectors: req.GetClickSelectors(), Note: req.GetNote(),
	}, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.AddBrowserSiteResponse{ProtectedChangeId: held.Change.String()}, nil
}

// RemoveBrowserSite implements BrowserServiceHandler.
func (h *Handler) RemoveBrowserSite(ctx context.Context, req *pantherclawv1.RemoveBrowserSiteRequest) (*pantherclawv1.RemoveBrowserSiteResponse, error) {
	id, err := ids.ParseUUID(req.GetId())
	if err != nil {
		return nil, app.ErrMissing
	}
	if err := h.s.Remove(ctx, id, req.GetReason()); err != nil {
		return nil, err
	}
	return &pantherclawv1.RemoveBrowserSiteResponse{}, nil
}
