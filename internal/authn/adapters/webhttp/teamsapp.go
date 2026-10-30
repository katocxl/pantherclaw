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
)

// Teams approval channel activation (G0 M20 D256; HR-529): POST
// /notifications/channels/{id}/confirm-teams activates a
// PENDING_ACTIVATION teams_app channel right after a security-key step-up
// on this browser session. The bot's token is minted and the channel's
// members are read again before anything is stored; a shared channel is
// refused. Every POST carries the CSRF proof (HR-151).

// TeamsChannels is the teams_app activation (notifications app.Service).
type TeamsChannels interface {
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
	h.withSession(m, http.MethodPost, "/notifications/channels/{id}/confirm-teams", h.confirmTeamsChannel)
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
