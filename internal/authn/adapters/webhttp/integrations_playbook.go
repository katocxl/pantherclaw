// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"net/http"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/signals"
)

// The identity playbook page (G0 M10 D38, HR-262):
// GET /integrations/playbook/{id}/confirm shows one playbook request and
// lets a person holding signals.manage confirm it with a security key in
// a BINDING ceremony over the request's binding (confirm-options starts
// it, confirm verifies it and records the confirmation), or decline it
// with a reason. Enabling or changing the playbook needs two different
// people with two different keys; disabling needs one. Nothing else
// confirms a request. GET never records anything; every POST carries the
// CSRF proof (HR-151).

// PlaybookRequests is the playbook use-case set (signals.Service).
type PlaybookRequests interface {
	PlaybookRequest(ctx context.Context, id ids.UUID) (signals.PlaybookRequest, error)
	BeginConfirm(ctx context.Context, id ids.UUID) (signals.PlaybookRequest, error)
	Confirm(ctx context.Context, id ids.UUID, a signals.Assertion) (signals.PlaybookRequest, error)
	DeclinePlaybookRequest(ctx context.Context, id ids.UUID, reason string) (signals.PlaybookRequest, error)
}

// WithPlaybook adds the identity playbook page; call it before Mount.
func (h *Handler) WithPlaybook(p PlaybookRequests, b Bindings) *Handler {
	h.playbook, h.playbookBindings = p, b
	return h
}

func (h *Handler) mountPlaybook(m *http.ServeMux) {
	if h.playbook == nil || h.playbookBindings == nil {
		return
	}
	p := signals.PlaybookPath + "/{id}"
	h.withSession(m, http.MethodGet, p+"/confirm", h.playbookPage)
	h.withSession(m, http.MethodPost, p+"/confirm-options", h.playbookConfirmOptions)
	h.withSession(m, http.MethodPost, p+"/confirm", h.playbookConfirm)
	h.withSession(m, http.MethodPost, p+"/decline", h.playbookDecline)
}

// playbookView is the data of integration_playbook.html.
type playbookView struct {
	page
	signals.PlaybookRequest
	EventNames []string
	MayConfirm bool
	MaxReason  int
}

func (h *Handler) playbookPage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		h.toLogin(w, r)
		return
	}
	const title = "Identity playbook"
	id, err := ids.ParseUUID(r.PathValue("id"))
	var req signals.PlaybookRequest
	if err == nil {
		req, err = h.playbook.PlaybookRequest(callerContext(r, s), id)
	} else {
		err = signals.ErrRequestNotFound
	}
	switch c := pcerr.CodeOf(err); {
	case err == nil:
	case c == pcerr.NotFound || c == pcerr.PermissionDenied:
		h.render(w, http.StatusNotFound, "error.html", page{Title: title, Message: "This playbook request does not exist, or you cannot see it."})
		return
	default:
		h.fail(w, r, err)
		return
	}
	view := playbookView{
		page: page{Title: title, Session: s}, PlaybookRequest: req, MayConfirm: signals.MayConfirm(callerOf(s), req),
		MaxReason: signals.MaxPlaybookReason,
	}
	for _, e := range req.Events {
		view.EventNames = append(view.EventNames, signals.ShortName(e))
	}
	h.renderAny(w, http.StatusOK, "integration_playbook.html", view)
}

// playbookErrors maps the playbook's errors to the page's codes.
var playbookErrors = []struct {
	err    error
	status int
	code   string
}{
	{signals.ErrRequestNotFound, http.StatusNotFound, "not_found"},
	{signals.ErrBrowserSession, http.StatusForbidden, "human_session"},
	{signals.ErrSamePerson, http.StatusConflict, "same_person"},
	{signals.ErrSameKey, http.StatusConflict, "same_key"},
	{signals.ErrRequestExpired, http.StatusConflict, "expired"},
	{signals.ErrRequestNotPending, http.StatusConflict, "not_pending"},
	{signals.ErrRequestVoided, http.StatusConflict, "voided"},
	{signals.ErrCeremony, http.StatusBadRequest, "ceremony_invalid"},
	{signals.ErrPlaybookReason, http.StatusBadRequest, "invalid_reason"},
	{signals.ErrPlaybookUnavailable, http.StatusServiceUnavailable, "unavailable"},
	{signals.ErrEdition, http.StatusConflict, "edition"},
	{authnapp.ErrNoCredentials, http.StatusConflict, "no_keys"},
	{authnapp.ErrCeremonyInvalid, http.StatusBadRequest, "ceremony_invalid"},
	{authnapp.ErrWebAuthnFailed, http.StatusBadRequest, "verification_failed"},
	{authnapp.ErrCredentialSuspended, http.StatusForbidden, "key_suspended"},
}

func (h *Handler) playbookError(w http.ResponseWriter, r *http.Request, err error) {
	for _, e := range playbookErrors {
		if errors.Is(err, e.err) {
			h.jsonError(w, e.status, e.code)
			return
		}
	}
	if pcerr.CodeOf(err) == pcerr.PermissionDenied {
		h.jsonError(w, http.StatusForbidden, "not_permitted")
		return
	}
	h.log.ErrorContext(r.Context(), "web.playbook", pclog.Err(err))
	h.jsonError(w, http.StatusInternalServerError, "internal")
}

// playbookConfirmOptions starts the BINDING ceremony over the request's
// binding, for a person who may confirm it now.
func (h *Handler) playbookConfirmOptions(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	if _, err := readPolicyChange(r); err != nil {
		h.jsonError(w, http.StatusBadRequest, "bad_request")
		return
	}
	ctx := callerContext(r, s)
	req, err := h.playbook.BeginConfirm(ctx, id)
	if err != nil {
		h.playbookError(w, r, err)
		return
	}
	cer, err := h.playbookBindings.BeginBinding(ctx, s, authnapp.BindingSubject{Playbook: id}, req.Binding)
	if err != nil {
		h.playbookError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"ceremony": cer.ID.String(), "options": jsontext.Value(cer.Options)})
}

// playbookConfirm verifies the assertion over the request's binding and
// records the confirmation (HR-262). The ceremony is consumed with the
// confirmation, or spent when it is refused or names another request.
func (h *Handler) playbookConfirm(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	body, err := readPolicyChange(r)
	ceremony, cerr := ids.ParseUUID(body.Ceremony)
	if err != nil || cerr != nil || len(body.Response) == 0 {
		h.jsonError(w, http.StatusBadRequest, "bad_request")
		return
	}
	ctx := callerContext(r, s)
	a, err := h.playbookBindings.VerifyBinding(ctx, s, ceremony, body.Response)
	if err != nil {
		h.playbookError(w, r, err)
		return
	}
	if a.Subject.Playbook != id {
		h.playbookBindings.SpendBinding(ctx, s, ceremony)
		h.jsonError(w, http.StatusBadRequest, "ceremony_invalid")
		return
	}
	out, err := h.playbook.Confirm(ctx, id, signals.Assertion{Ceremony: a.Ceremony, Credential: a.Credential})
	if err != nil {
		h.playbookBindings.SpendBinding(ctx, s, ceremony)
		h.playbookError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"state": out.State, "confirmations": len(out.Confirmations), "required": out.Required})
}

// playbookDecline declines a pending request with a reason.
func (h *Handler) playbookDecline(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	body, err := readPolicyChange(r)
	if err != nil {
		h.jsonError(w, http.StatusBadRequest, "bad_request")
		return
	}
	out, err := h.playbook.DeclinePlaybookRequest(callerContext(r, s), id, body.Reason)
	if err != nil {
		h.playbookError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"state": out.State})
}
