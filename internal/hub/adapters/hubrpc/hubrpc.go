// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package hubrpc serves HubService over Connect (G0 M23 D103). Handlers only
// translate; the use cases check the caller.
package hubrpc

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/hub/app"
	"github.com/katocxl/pantherclaw/internal/hub/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

const defaultPageSize = 50

var errPageToken = pcerr.New(pcerr.InvalidArgument, "INVALID_PAGE_TOKEN", "the page token is not valid")

var (
	kinds = map[domain.Kind]pantherclawv1.HubItemKind{
		domain.KindPolicyTemplate: pantherclawv1.HubItemKind_HUB_ITEM_KIND_POLICY_TEMPLATE,
		domain.KindDetectionRule:  pantherclawv1.HubItemKind_HUB_ITEM_KIND_DETECTION_RULE,
		domain.KindRangeScenario:  pantherclawv1.HubItemKind_HUB_ITEM_KIND_RANGE_SCENARIO,
		domain.KindToolPackage:    pantherclawv1.HubItemKind_HUB_ITEM_KIND_TOOL_PACKAGE,
		domain.KindAutomation:     pantherclawv1.HubItemKind_HUB_ITEM_KIND_AUTOMATION,
	}
	statuses = map[app.Status]pantherclawv1.HubInstallStatus{
		app.StatusPending:   pantherclawv1.HubInstallStatus_HUB_INSTALL_STATUS_PENDING,
		app.StatusInstalled: pantherclawv1.HubInstallStatus_HUB_INSTALL_STATUS_INSTALLED,
		app.StatusFailed:    pantherclawv1.HubInstallStatus_HUB_INSTALL_STATUS_FAILED,
	}
)

// Handler serves HubService.
type Handler struct {
	pantherclawv1connect.UnimplementedHubServiceHandler
	svc *app.Service
}

// New returns the HubService handler.
func New(svc *app.Service) *Handler { return &Handler{svc: svc} }

func installPB(i app.Install) *pantherclawv1.HubInstall {
	return &pantherclawv1.HubInstall{
		Id: i.ID.String(), Name: i.Name, Version: i.Version, Kind: kinds[i.Kind], ItemSha256: i.ItemSHA256, IndexVersion: i.IndexVersion,
		ResultKind: i.ResultKind, ResultRef: i.ResultRef, InstalledBy: i.InstalledBy, InstalledAt: timestamppb.New(i.InstalledAt),
		Status: statuses[i.Status], FailureReason: i.FailureReason,
	}
}

// InstallHubItem implements HubServiceHandler.
func (h *Handler) InstallHubItem(ctx context.Context, r *pantherclawv1.InstallHubItemRequest) (*pantherclawv1.InstallHubItemResponse, error) {
	out, err := h.svc.Install(ctx, app.Input{IndexJWS: r.GetIndexJws(), Item: r.GetItem(), Params: r.GetParams()})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.InstallHubItemResponse{Install: installPB(out.Install), AlreadyInstalled: out.Already, Skipped: out.Skipped, Replaced: out.Replaced}, nil
}

// ListHubInstalls implements HubServiceHandler. The page token is the last id
// of the previous page.
func (h *Handler) ListHubInstalls(ctx context.Context, r *pantherclawv1.ListHubInstallsRequest) (*pantherclawv1.ListHubInstallsResponse, error) {
	limit := int(r.GetPageSize())
	if limit == 0 {
		limit = defaultPageSize
	}
	var before *ids.UUID
	if t := r.GetPageToken(); t != "" {
		id, err := ids.ParseUUID(t)
		if err != nil {
			return nil, errPageToken
		}
		before = &id
	}
	rows, err := h.svc.List(ctx, limit+1, before)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListHubInstallsResponse{}
	if len(rows) > limit {
		rows = rows[:limit]
		out.NextPageToken = rows[limit-1].ID.String()
	}
	for _, i := range rows {
		out.Installs = append(out.Installs, installPB(i))
	}
	return out, nil
}

// GetHubState implements HubServiceHandler.
func (h *Handler) GetHubState(ctx context.Context, _ *pantherclawv1.GetHubStateRequest) (*pantherclawv1.GetHubStateResponse, error) {
	st, err := h.svc.State(ctx)
	if err != nil || st == nil {
		return &pantherclawv1.GetHubStateResponse{}, err
	}
	return &pantherclawv1.GetHubStateResponse{
		Present: true, IndexVersion: st.Version, IndexDigest: st.Digest, UpdatedAt: timestamppb.New(st.UpdatedAt),
	}, nil
}
