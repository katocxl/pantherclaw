// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"context"
	"errors"
	"net/http"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/enforcementpoints"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The enforcement point confirm page (G0 M14 D29, D62):
//
//	GET  /enforcement-points/{id}/confirm   a point and the connections it proposes
//	POST /enforcement-points/{id}/activate  confirm them
//
// Confirming, which activates a PENDING point or applies a widening, needs
// a security-key step-up of this browser session within five minutes,
// made right before on the page; the API refuses it (STEP_UP_REQUIRED).
// GET never changes anything; the POST carries the CSRF proof (HR-151).

// EnforcementPoints is the use-case set of the page (enforcementpoints.Service).
type EnforcementPoints interface {
	Get(ctx context.Context, id ids.UUID) (enforcementpoints.Point, error)
	Activate(ctx context.Context, id ids.UUID, su *stepup.StepUp) (enforcementpoints.Point, error)
}

// MountEnforcementPoints adds the confirm page to mux. The server calls it
// after Mount.
func (h *Handler) MountEnforcementPoints(mux *http.ServeMux, ep EnforcementPoints) {
	if ep == nil {
		return
	}
	p := pointPages{h: h, ep: ep}
	h.withSession(mux, http.MethodGet, "/enforcement-points/{id}/confirm", p.page)
	h.withSession(mux, http.MethodPost, "/enforcement-points/{id}/activate", p.activate)
}

type pointPages struct {
	h  *Handler
	ep EnforcementPoints
}

// enforcementPointView is the data of enforcement_point.html.
type enforcementPointView struct {
	page
	enforcementpoints.Point
	CanManage bool
}

func (p pointPages) page(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	const title = "Enforcement point"
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		p.h.toLogin(w, r)
		return
	}
	notFound := func() {
		p.h.render(w, http.StatusNotFound, "error.html", page{Title: title, Message: "This does not exist, or you cannot see it."})
	}
	id, err := ids.ParseUUID(r.PathValue("id"))
	if err != nil {
		notFound()
		return
	}
	pt, err := p.ep.Get(callerContext(r, s), id)
	switch pcerr.CodeOf(err) { //nolint:exhaustive // these read as "not found"; the rest fail
	case "":
		p.h.renderAny(w, http.StatusOK, "enforcement_point.html", enforcementPointView{
			page: page{Title: title, Session: s}, Point: pt,
			CanManage: s.Human() && s.Can(td.PermEnforcementPointManage, td.OrgPath(s.Org)),
		})
	case pcerr.NotFound, pcerr.PermissionDenied, pcerr.InvalidArgument:
		notFound()
	default:
		p.h.fail(w, r, err)
	}
}

// pointErrors maps the use cases' errors to the page's codes.
var pointErrors = []struct {
	err    error
	status int
	code   string
}{
	{stepup.ErrStepUp, http.StatusForbidden, "step_up_required"},
	{enforcementpoints.ErrHuman, http.StatusForbidden, "forbidden"},
	{enforcementpoints.ErrNotFound, http.StatusNotFound, "not_found"},
	{enforcementpoints.ErrState, http.StatusConflict, "not_pending"},
	{enforcementpoints.ErrNothing, http.StatusConflict, "not_pending"},
	{enforcementpoints.ErrNotBindable, http.StatusConflict, "not_pending"},
}

func (p pointPages) activate(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := p.h.requestID(w, r)
	if !ok {
		return
	}
	pt, err := p.ep.Activate(callerContext(r, s), id, stepUpPtr(s))
	if err != nil {
		for _, e := range pointErrors {
			if errors.Is(err, e.err) {
				p.h.jsonError(w, e.status, e.code)
				return
			}
		}
		if pcerr.CodeOf(err) == pcerr.PermissionDenied {
			p.h.jsonError(w, http.StatusForbidden, "forbidden")
			return
		}
		p.h.log.ErrorContext(r.Context(), "web.enforcement_points", pclog.Err(err))
		p.h.jsonError(w, http.StatusInternalServerError, "internal")
		return
	}
	p.h.writeJSON(w, http.StatusOK, map[string]string{"state": pt.State})
}
