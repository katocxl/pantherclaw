// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"context"
	"errors"
	"net/http"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Teams approval channel activation (G0 M20 D256; HR-529): GET
// /notifications/channels/{id}/confirm-teams shows a teams_app channel and
// its state; POST on the same path activates a PENDING_ACTIVATION one
// right after a security-key step-up on this browser session. The bot's token is minted and the channel's
// members are read again before anything is stored; a shared channel is
// refused. Every POST carries the CSRF proof (HR-151).

// TeamsChannels is the teams_app activation (notifications app.Service).
type TeamsChannels interface {
	GetChannel(ctx context.Context, id ids.UUID) (napp.ChannelView, []napp.DeliveryView, error)
	ActivateTeamsApp(ctx context.Context, id ids.UUID, su stepup.StepUp) (napp.ChannelView, error)
}

// WithTeamsChannels adds the Teams channel activation; call it before
// Mount.
func (h *Handler) WithTeamsChannels(t TeamsChannels) *Handler {
	h.teamsChannels = t
	return h
}

func (h *Handler) mountTeamsChannels(m *http.ServeMux) {
	if h.teamsChannels == nil {
		return
	}
	h.withSession(m, http.MethodGet, "/notifications/channels/{id}/confirm-teams", h.teamsChannelPage)
	h.withSession(m, http.MethodPost, "/notifications/channels/{id}/confirm-teams", h.confirmTeamsChannel)
}

// teamsChannelView is the data of teams_channel.html.
type teamsChannelView struct {
	page
	napp.ChannelView
	Teams      napp.TeamsAppView
	CanManage  bool
	Pending    bool
	ActionPath string
}

func (h *Handler) teamsChannelPage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		h.toLogin(w, r)
		return
	}
	const title = "Teams approval channel"
	id, err := ids.ParseUUID(r.PathValue("id"))
	var c napp.ChannelView
	if err == nil {
		c, _, err = h.teamsChannels.GetChannel(callerContext(r, s), id)
	} else {
		err = napp.ErrChannelNotFound
	}
	if err == nil && c.TeamsApp == nil {
		err = napp.ErrChannelNotFound
	}
	switch code := pcerr.CodeOf(err); {
	case err == nil:
	case code == pcerr.NotFound || code == pcerr.PermissionDenied || code == pcerr.InvalidArgument:
		h.render(w, http.StatusNotFound, "error.html", page{Title: title, Message: "This channel does not exist, or you cannot see it."})
		return
	default:
		h.fail(w, r, err)
		return
	}
	h.renderAny(w, http.StatusOK, "teams_channel.html", teamsChannelView{
		page: page{Title: title, Session: s}, ChannelView: c, Teams: *c.TeamsApp,
		CanManage:  s.Human() && s.Can(td.PermNotificationManage, td.OrgPath(s.Org)),
		Pending:    c.TeamsApp.State == napp.SlackPending,
		ActionPath: napp.TeamsConfirmPath(c.ID),
	})
}

var teamsErrors = []struct {
	err    error
	status int
	code   string
}{
	{stepup.ErrStepUp, http.StatusForbidden, "step_up_required"},
	{napp.ErrNotTeamsApp, http.StatusNotFound, "not_found"},
	{napp.ErrChannelNotFound, http.StatusNotFound, "not_found"},
	{napp.ErrTeamsState, http.StatusConflict, "wrong_state"},
	{napp.ErrSlackEdition, http.StatusForbidden, "edition_required"},
	{napp.ErrTeamsRefused, http.StatusConflict, "teams_bot_refused"},
	{napp.ErrTeamsChannel, http.StatusConflict, "teams_channel_refused"},
	{napp.ErrTeamsShared, http.StatusConflict, "teams_channel_shared"},
	{napp.ErrTeamsUnread, http.StatusConflict, "teams_channel_unread"},
	{napp.ErrTeamsUnavailable, http.StatusServiceUnavailable, "teams_unavailable"},
	{napp.ErrSlackOrgAdmin, http.StatusForbidden, "org_admin_required"},
}

func (h *Handler) confirmTeamsChannel(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	_, err := h.teamsChannels.ActivateTeamsApp(callerContext(r, s), id, stepUpOfSession(s)) //nolint:contextcheck // callerContext derives from r.Context()
	if err != nil {
		for _, e := range teamsErrors {
			if errors.Is(err, e.err) {
				h.jsonError(w, e.status, e.code)
				return
			}
		}
		if pcerr.CodeOf(err) == pcerr.PermissionDenied {
			h.jsonError(w, http.StatusForbidden, "forbidden")
			return
		}
		h.log.ErrorContext(r.Context(), "web.teams_channels", pclog.Err(err))
		h.jsonError(w, http.StatusInternalServerError, "internal")
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"state": napp.SlackActive})
}
