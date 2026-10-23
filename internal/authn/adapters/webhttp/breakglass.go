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
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	"github.com/katocxl/pantherclaw/internal/support"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// BreakGlass serves the holder's canonical confirmation page and audits
// all authenticated page calls made during an activation (D33, D38).
type BreakGlass interface {
	MyBreakGlass(context.Context) (*support.Holder, *support.Activation, error)
	ActivateBreakGlass(context.Context, string, int, *stepup.StepUp) (support.Activation, error)
	BreakGlassCall(context.Context, tapp.Caller, string) (tapp.Caller, error)
}

// MountBreakGlass mounts the step-up protected activation page; GET is
// read-only and POST uses the same CSRF and body bounds as other pages.
func (h *Handler) MountBreakGlass(mux *http.ServeMux, bg BreakGlass) {
	if bg == nil {
		return
	}
	h.breakGlass = bg
	h.withSession(mux, http.MethodGet, "/break-glass/activate", h.breakGlassConfirm)
	h.withSession(mux, http.MethodPost, "/break-glass/activate", h.breakGlassActivate)
}

type breakGlassView struct {
	page
	Holder *support.Holder
	Active *support.Activation
}

func (h *Handler) breakGlassConfirm(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	holder, active, err := h.breakGlass.MyBreakGlass(callerContext(r, s))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.renderAny(w, http.StatusOK, "breakglass.html", breakGlassView{page: page{Title: "Activate break-glass access", Session: s}, Holder: holder, Active: active})
}

func (h *Handler) breakGlassActivate(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	var in struct {
		Reason  string `json:"reason"`
		Minutes int    `json:"minutes"`
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		h.jsonError(w, http.StatusBadRequest, "invalid")
		return
	}
	if err := json.Unmarshal(b, &in, json.RejectUnknownMembers(true)); err != nil {
		h.jsonError(w, http.StatusBadRequest, "invalid")
		return
	}
	a, err := h.breakGlass.ActivateBreakGlass(callerContext(r, s), in.Reason, in.Minutes, stepUpPtr(s))
	switch {
	case errors.Is(err, support.ErrNotHolder):
		h.jsonError(w, http.StatusForbidden, "not_holder")
	case errors.Is(err, support.ErrAlreadyActive):
		h.jsonError(w, http.StatusConflict, "active")
	case errors.Is(err, support.ErrActivation):
		h.jsonError(w, http.StatusBadRequest, "invalid")
	case errors.Is(err, support.ErrBreakGlassEdition):
		h.jsonError(w, http.StatusForbidden, "edition")
	case errors.Is(err, stepup.ErrStepUp):
		h.jsonError(w, http.StatusForbidden, "step_up_required")
	case err != nil:
		h.fail(w, r, err)
	default:
		h.writeJSON(w, http.StatusOK, map[string]string{"activation": a.ID.String(), "next": authnapp.ConsolePath})
	}
}
