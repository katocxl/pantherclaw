// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The Slack approval channel page (G0 M14 D22, D66; HR-315):
// GET /notifications/channels/{id}/confirm shows a slack_app channel, its
// Slack channel, data level and state; for a PENDING_ACTIVATION one and a
// person holding notification.manage it asks Slack (auth.test,
// conversations.info) and shows the workspace, bot and channel found. The
// person activates it with a POST on the same path right after a
// security-key step-up on this browser session; Slack is asked again before
// anything is stored. Nothing else activates a slack_app channel, and no
// bot token is ever typed into this page (a new one comes through
// UpdateChannel). GET changes nothing; every POST carries the CSRF proof
// (HR-151).

// SlackChannels is the slack_app use-case set (notifications app.Service).
type SlackChannels interface {
	GetChannel(ctx context.Context, id ids.UUID) (napp.ChannelView, []napp.DeliveryView, error)
	ActivateSlackApp(ctx context.Context, id ids.UUID, su stepup.StepUp) (napp.ChannelView, error)
	PreviewSlackApp(ctx context.Context, id ids.UUID) (napp.SlackPreview, error)
}

// WithSlackChannels adds the Slack approval channel page; call it before
// Mount.
func (h *Handler) WithSlackChannels(s SlackChannels) *Handler {
	h.slackChannels = s
	return h
}

func (h *Handler) mountSlackChannels(m *http.ServeMux) {
	if h.slackChannels == nil {
		return
	}
	h.withSession(m, http.MethodGet, "/notifications/channels/{id}/confirm", h.slackChannelPage)
	h.withSession(m, http.MethodPost, "/notifications/channels/{id}/confirm", h.confirmSlackChannel)
}

// slackChannelView is the data of slack_channel.html.
type slackChannelView struct {
	page
	napp.ChannelView
	Slack      napp.SlackAppView
	CanManage  bool
	Pending    bool
	Summary    bool
	ActionPath string
	// Found is what Slack reported; Problem, why it could not be checked.
	Found   *napp.SlackPreview
	Problem string
}

func (h *Handler) slackChannelPage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		h.toLogin(w, r)
		return
	}
	const title = "Slack approval channel"
	id, err := ids.ParseUUID(r.PathValue("id"))
	var c napp.ChannelView
	if err == nil {
		c, _, err = h.slackChannels.GetChannel(callerContext(r, s), id)
	} else {
		err = napp.ErrChannelNotFound
	}
	if err == nil && c.SlackApp == nil {
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
	v := slackChannelView{
		page: page{Title: title, Session: s}, ChannelView: c, Slack: *c.SlackApp,
		CanManage:  s.Human() && s.Can(td.PermNotificationManage, td.OrgPath(s.Org)),
		Pending:    c.SlackApp.State == napp.SlackPending,
		Summary:    c.SlackApp.DataLevel == domain.SlackSummary,
		ActionPath: napp.SlackConfirmPath(c.ID),
	}
	if v.Pending && v.CanManage {
		if p, err := h.slackChannels.PreviewSlackApp(callerContext(r, s), id); err == nil {
			v.Found = &p
		} else {
			v.Problem = slackProblem(err)
		}
	}
	h.renderAny(w, http.StatusOK, "slack_channel.html", v)
}

// slackConfirmRequest is the POST body: an empty object.
type slackConfirmRequest struct{}

// slackErrors maps the use cases' errors to the page's codes.
var slackErrors = []struct {
	err    error
	status int
	code   string
}{
	{stepup.ErrStepUp, http.StatusForbidden, "step_up_required"},
	{napp.ErrNotSlackApp, http.StatusNotFound, "not_found"},
	{napp.ErrChannelNotFound, http.StatusNotFound, "not_found"},
	{napp.ErrSlackState, http.StatusConflict, "wrong_state"},
	{napp.ErrSlackEdition, http.StatusForbidden, "edition_required"},
	{napp.ErrSlackTokenRefused, http.StatusConflict, "slack_token_refused"},
	{napp.ErrSlackChannelRefuse, http.StatusConflict, "slack_channel_refused"},
	{napp.ErrSlackShared, http.StatusConflict, "slack_channel_shared"},
	{napp.ErrSlackUnavailable, http.StatusServiceUnavailable, "slack_unavailable"},
}

func (h *Handler) confirmSlackChannel(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	b, err := io.ReadAll(r.Body)
	var req slackConfirmRequest
	if err != nil || (len(b) > 0 && json.Unmarshal(b, &req, json.RejectUnknownMembers(true)) != nil) {
		h.jsonError(w, http.StatusBadRequest, "bad_request")
		return
	}
	ctx, su := callerContext(r, s), stepup.StepUp{Credential: s.StepUpCredential, At: s.StepUpAt}
	c, err := h.slackChannels.ActivateSlackApp(ctx, id, su)
	if err != nil {
		for _, e := range slackErrors {
			if errors.Is(err, e.err) {
				h.jsonError(w, e.status, e.code)
				return
			}
		}
		if pcerr.CodeOf(err) == pcerr.PermissionDenied {
			h.jsonError(w, http.StatusForbidden, "forbidden")
			return
		}
		h.log.ErrorContext(r.Context(), "web.slack_channels", pclog.Err(err))
		h.jsonError(w, http.StatusInternalServerError, "internal")
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"state": c.SlackApp.State})
}

// slackProblem is the page's reason Slack could not confirm the channel.
func slackProblem(err error) string {
	for _, p := range []struct {
		err  error
		text string
	}{
		{napp.ErrSlackTokenRefused, "Slack refused the bot token. Give the channel a new token (UpdateChannel)."},
		{napp.ErrSlackChannelRefuse, "The Slack channel does not exist, is archived, or the bot is not in it."},
		{napp.ErrSlackShared, "The Slack channel is shared outside the workspace; approval cards go only to internal channels."},
		{napp.ErrSlackEdition, "Slack approval cards need the Team edition or above."},
		{napp.ErrSlackState, "The channel changed. Reload the page."},
	} {
		if errors.Is(err, p.err) {
			return p.text
		}
	}
	return "Slack could not be reached. Reload the page to try again."
}
