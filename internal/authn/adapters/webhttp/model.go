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
	modelapp "github.com/katocxl/pantherclaw/internal/model/app"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The model drafting settings page (G0 M21 D309; G16, HR-541, HR-545):
// GET shows whether drafting is on and whether a key is stored, never the
// key. A person holding org.update turns drafting on or sets the key with a
// POST right after a security-key step-up on this browser session. Nothing
// else does either: no API call, key or link. Turning it off and clearing
// the key need no step-up and stay on offer when the plan has lapsed, here
// and as API calls. Every POST carries the CSRF proof (HR-151), and a key in
// a request body is never logged.

// ModelDraftingPath is the settings page.
const ModelDraftingPath = "/settings/model-drafting"

// ModelDrafting is the settings use-case set (model/app.Service).
type ModelDrafting interface {
	Get(ctx context.Context) (modelapp.Settings, error)
	Enable(ctx context.Context, su stepup.StepUp) (modelapp.Settings, error)
	SetKey(ctx context.Context, key string, su stepup.StepUp) (modelapp.Settings, error)
	Disable(ctx context.Context) (modelapp.Settings, error)
	ClearKey(ctx context.Context) (modelapp.Settings, error)
}

// WithModelDrafting adds the settings page; call it before Mount.
func (h *Handler) WithModelDrafting(m ModelDrafting) *Handler {
	h.modelDrafting = m
	return h
}

func (h *Handler) mountModelDrafting(m *http.ServeMux) {
	if h.modelDrafting == nil {
		return
	}
	h.withSession(m, http.MethodGet, ModelDraftingPath, h.modelDraftingPage)
	h.withSession(m, http.MethodPost, ModelDraftingPath+"/enable", h.enableModelDrafting)
	h.withSession(m, http.MethodPost, ModelDraftingPath+"/key", h.setModelKey)
	h.withSession(m, http.MethodPost, ModelDraftingPath+"/disable", h.disableModelDrafting)
	h.withSession(m, http.MethodPost, ModelDraftingPath+"/key/clear", h.clearModelKey)
}

// modelDraftingView is the data of model_drafting.html.
type modelDraftingView struct {
	page
	modelapp.Settings
	CanChange bool
	// CanLeave offers turning it off and clearing the key, even when the
	// server or the plan no longer offers drafting.
	CanLeave bool
}

func (h *Handler) modelDraftingPage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		h.toLogin(w, r)
		return
	}
	const title = "Model drafting"
	set, err := h.modelDrafting.Get(callerContext(r, s))
	switch {
	case err == nil:
	case pcerr.CodeOf(err) == pcerr.PermissionDenied:
		h.render(w, http.StatusNotFound, "error.html", page{Title: title, Message: "You cannot see this page."})
		return
	default:
		h.fail(w, r, err)
		return
	}
	canLeave := s.Human() && s.Can(td.PermOrgUpdate, td.OrgPath(s.Org))
	h.renderAny(w, http.StatusOK, "model_drafting.html", modelDraftingView{
		page: page{Title: title, Session: s}, Settings: set,
		CanChange: set.Available && canLeave, CanLeave: canLeave,
	})
}

// modelErrors maps use-case errors to the page's error codes.
var modelErrors = []struct {
	err    error
	status int
	code   string
}{
	{stepup.ErrStepUp, http.StatusForbidden, "step_up_required"},
	{modelapp.ErrHuman, http.StatusForbidden, "forbidden"},
	{modelapp.ErrEdition, http.StatusForbidden, "edition_required"},
	{modelapp.ErrPlatformOff, http.StatusConflict, "unavailable"},
	{modelapp.ErrNoKey, http.StatusConflict, "no_key"},
	{modelapp.ErrInvalidKey, http.StatusBadRequest, "invalid_key"},
}

func (h *Handler) modelError(w http.ResponseWriter, r *http.Request, err error) {
	for _, e := range modelErrors {
		if errors.Is(err, e.err) {
			h.jsonError(w, e.status, e.code)
			return
		}
	}
	if pcerr.CodeOf(err) == pcerr.PermissionDenied {
		h.jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	h.log.ErrorContext(r.Context(), "web.model_drafting", pclog.Err(err))
	h.jsonError(w, http.StatusInternalServerError, "internal")
}

func (h *Handler) enableModelDrafting(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	if _, err := h.modelDrafting.Enable(callerContext(r, s), stepUpOfSession(s)); err != nil {
		h.modelError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"state": "ENABLED"})
}

func (h *Handler) disableModelDrafting(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	if _, err := h.modelDrafting.Disable(callerContext(r, s)); err != nil {
		h.modelError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"state": "DISABLED"})
}

func (h *Handler) clearModelKey(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	if _, err := h.modelDrafting.ClearKey(callerContext(r, s)); err != nil {
		h.modelError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"state": "KEY_CLEARED"})
}

// modelKeyRequest is the body of a key change. Its Key is never logged.
type modelKeyRequest struct {
	Key string `json:"key"`
}

func (h *Handler) setModelKey(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		h.jsonError(w, http.StatusBadRequest, "bad_request")
		return
	}
	var body modelKeyRequest
	if json.Unmarshal(b, &body, json.RejectUnknownMembers(true)) != nil {
		h.jsonError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if _, err := h.modelDrafting.SetKey(callerContext(r, s), body.Key, stepUpOfSession(s)); err != nil {
		h.modelError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"state": "KEY_SET"})
}
