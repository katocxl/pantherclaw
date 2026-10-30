// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package notificationsrpc

import (
	"context"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Chat identity links (G0 M20 D256, D265): a person links and confirms
// their own Slack identity for approval DMs.

var linkStates = map[string]pantherclawv1.ChatLinkState{
	napp.LinkProposed:  pantherclawv1.ChatLinkState_CHAT_LINK_STATE_PROPOSED,
	napp.LinkConfirmed: pantherclawv1.ChatLinkState_CHAT_LINK_STATE_CONFIRMED,
	napp.LinkStale:     pantherclawv1.ChatLinkState_CHAT_LINK_STATE_STALE,
	napp.LinkRevoked:   pantherclawv1.ChatLinkState_CHAT_LINK_STATE_REVOKED,
}

func chatLinkProto(l napp.ChatLink) *pantherclawv1.ChatLink {
	out := &pantherclawv1.ChatLink{
		Id: l.ID.String(), Provider: l.Provider, TeamId: l.TeamID, ExternalUserId: l.ExternalUser, Email: l.Email,
		State: linkStates[l.State], CreateTime: ts(l.Created),
	}
	if l.ConfirmedAt != nil {
		out.ConfirmTime = ts(*l.ConfirmedAt)
	}
	return out
}

var errLinkID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

func linkID(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil {
		return ids.UUID{}, errLinkID
	}
	return id, nil
}

// ProposeSlackLink implements NotificationService.
func (h *Handler) ProposeSlackLink(ctx context.Context, _ *pantherclawv1.ProposeSlackLinkRequest) (*pantherclawv1.ProposeSlackLinkResponse, error) {
	l, err := h.s.ProposeSlackLink(ctx)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ProposeSlackLinkResponse{Link: chatLinkProto(l)}, nil
}

// ConfirmChatLink implements NotificationService.
func (h *Handler) ConfirmChatLink(ctx context.Context, req *pantherclawv1.ConfirmChatLinkRequest) (*pantherclawv1.ConfirmChatLinkResponse, error) {
	id, err := linkID(req.GetId())
	if err != nil {
		return nil, err
	}
	l, err := h.s.ConfirmChatLink(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ConfirmChatLinkResponse{Link: chatLinkProto(l)}, nil
}

// RevokeChatLink implements NotificationService.
func (h *Handler) RevokeChatLink(ctx context.Context, req *pantherclawv1.RevokeChatLinkRequest) (*pantherclawv1.RevokeChatLinkResponse, error) {
	id, err := linkID(req.GetId())
	if err != nil {
		return nil, err
	}
	l, err := h.s.RevokeChatLink(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RevokeChatLinkResponse{Link: chatLinkProto(l)}, nil
}

// ListChatLinks implements NotificationService.
func (h *Handler) ListChatLinks(ctx context.Context, _ *pantherclawv1.ListChatLinksRequest) (*pantherclawv1.ListChatLinksResponse, error) {
	ls, err := h.s.ChatLinks(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListChatLinksResponse{}
	for _, l := range ls {
		out.Links = append(out.Links, chatLinkProto(l))
	}
	return out, nil
}

// teamsAppIn is a teams_app configuration from the API (G0 M20 D256).
func teamsAppIn(c *pantherclawv1.TeamsAppConfig) *domain.TeamsAppConfig {
	if c == nil {
		return nil
	}
	return &domain.TeamsAppConfig{
		TenantID: c.GetTenantId(), TeamID: c.GetTeamId(), ChannelID: c.GetChannelId(), AppID: c.GetAppId(),
		ClientSecret: c.GetClientSecret(), ServiceURL: c.GetServiceUrl(),
	}
}
