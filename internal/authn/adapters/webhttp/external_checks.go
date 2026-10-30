// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"context"
	"errors"
	"net/http"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/externalchecks"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The external policy check activation page (G0 M16 D81, HR-438):
//
//	GET  /policies/external-checks/{id}/confirm   a check and what activating it does
//	POST /policies/external-checks/{id}/activate  activate it
//
// Activating a PENDING check needs a security-key step-up of this browser
// session within five minutes, made right before on the page; the API
// refuses it (STEP_UP_REQUIRED). GET never changes anything; the POST
// carries the CSRF proof (HR-151).

// ExternalChecks is the use-case set of the page (externalchecks.Service).
type ExternalChecks interface {
	Get(ctx context.Context, id ids.UUID) (externalchecks.Check, error)
	Activate(ctx context.Context, id ids.UUID, su *stepup.StepUp) (externalchecks.Check, error)
}

// MountExternalChecks adds the activation page to mux. The server calls it
// after Mount.
func (h *Handler) MountExternalChecks(mux *http.ServeMux, ec ExternalChecks) {
	if ec == nil {
		return
	}
	p := externalCheckPages{h: h, ec: ec}
	h.withSession(mux, http.MethodGet, "/policies/external-checks/{id}/confirm", p.page)
	h.withSession(mux, http.MethodPost, "/policies/external-checks/{id}/activate", p.activate)
}

type externalCheckPages struct {
	h  *Handler
	ec ExternalChecks
}

// externalCheckView is the data of external_check.html.
type externalCheckView struct {
	page
	externalchecks.Check
	CanManage bool
}

func (p externalCheckPages) page(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	const title = "External policy check"
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
	c, err := p.ec.Get(callerContext(r, s), id)
	switch pcerr.CodeOf(err) { //nolint:exhaustive // these read as "not found"; the rest fail
	case "":
		p.h.renderAny(w, http.StatusOK, "external_check.html", externalCheckView{
			page: page{Title: title, Session: s}, Check: c,
			CanManage: s.Human() && s.Can(td.PermExternalCheckManage, td.OrgPath(s.Org)),
		})
	case pcerr.NotFound, pcerr.PermissionDenied, pcerr.InvalidArgument:
		notFound()
	default:
		p.h.fail(w, r, err)
	}
}

// externalCheckErrors maps the use cases' errors to the page's codes.
var externalCheckErrors = []struct {
	err    error
	status int
	code   string
}{
	{stepup.ErrStepUp, http.StatusForbidden, "step_up_required"},
	{externalchecks.ErrHuman, http.StatusForbidden, "forbidden"},
	{externalchecks.ErrEdition, http.StatusForbidden, "edition_required"},
	{externalchecks.ErrNotFound, http.StatusNotFound, "not_found"},
	{externalchecks.ErrState, http.StatusConflict, "not_pending"},
	{externalchecks.ErrTooMany, http.StatusConflict, "too_many_active"},
	{externalchecks.ErrEndpoint, http.StatusConflict, "endpoint_not_allowed"},
}

func (p externalCheckPages) activate(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := p.h.requestID(w, r)
	if !ok {
		return
	}
	c, err := p.ec.Activate(callerContext(r, s), id, stepUpPtr(s)) //nolint:contextcheck // callerContext derives from the request's context
	if err != nil {
		for _, e := range externalCheckErrors {
			if errors.Is(err, e.err) {
				p.h.jsonError(w, e.status, e.code)
				return
			}
		}
		if pcerr.CodeOf(err) == pcerr.PermissionDenied {
			p.h.jsonError(w, http.StatusForbidden, "forbidden")
			return
		}
		p.h.log.ErrorContext(r.Context(), "web.external_checks", pclog.Err(err))
		p.h.jsonError(w, http.StatusInternalServerError, "internal")
		return
	}
	p.h.writeJSON(w, http.StatusOK, map[string]string{"state": c.State})
}
