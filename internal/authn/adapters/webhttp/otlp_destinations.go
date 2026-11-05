// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"context"
	"errors"
	"net/http"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/otlpexport"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The OTLP destination activation page (G0 M36 D1061; HR-786):
//
//	GET  /integrations/otlp-destinations/{id}/confirm  a destination, its URL and header names
//	POST /integrations/otlp-destinations/{id}/confirm  activate it
//
// Activating needs a person holding otlp.manage and a security-key step-up
// of this browser session within five minutes, as a SIEM destination; the
// API refuses it (STEP_UP_REQUIRED). GET never changes anything; the POST
// carries the CSRF proof (HR-151).

// OTLPDestinations is the use-case set of the page (otlpexport.Service).
type OTLPDestinations interface {
	Get(ctx context.Context, id ids.UUID) (otlpexport.Destination, error)
	Activate(ctx context.Context, id ids.UUID, su *stepup.StepUp) (otlpexport.Destination, error)
}

// MountOTLPDestinations adds the activation page to mux. The server calls
// it after Mount.
func (h *Handler) MountOTLPDestinations(mux *http.ServeMux, d OTLPDestinations) {
	if d == nil {
		return
	}
	p := otlpPages{h: h, d: d}
	h.withSession(mux, http.MethodGet, otlpexport.ConfirmPath+"/{id}/confirm", p.page)
	h.withSession(mux, http.MethodPost, otlpexport.ConfirmPath+"/{id}/confirm", p.activate)
}

type otlpPages struct {
	h *Handler
	d OTLPDestinations
}

// otlpDestinationView is the data of otlp_destination.html.
type otlpDestinationView struct {
	page
	otlpexport.Destination
	CanActivate bool
}

func (p otlpPages) page(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	const title = "OpenTelemetry destination"
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		p.h.toLogin(w, r)
		return
	}
	id, err := ids.ParseUUID(r.PathValue("id"))
	var d otlpexport.Destination
	if err == nil {
		d, err = p.d.Get(callerContext(r, s), id)
	} else {
		err = otlpexport.ErrNotFound
	}
	switch c := pcerr.CodeOf(err); {
	case err == nil:
	case c == pcerr.NotFound || c == pcerr.PermissionDenied || c == pcerr.InvalidArgument:
		p.h.integrationNotFound(w, title)
		return
	default:
		p.h.fail(w, r, err)
		return
	}
	p.h.renderAny(w, http.StatusOK, "otlp_destination.html", otlpDestinationView{
		page: page{Title: title, Session: s}, Destination: d,
		CanActivate: d.State == otlpexport.StatePending && s.Human() && s.Can(otlpexport.PermManage, td.OrgPath(s.Org)),
	})
}

// otlpErrors maps the use cases' errors to the page's codes.
var otlpErrors = []struct {
	err    error
	status int
	code   string
}{
	{stepup.ErrStepUp, http.StatusForbidden, "step_up_required"},
	{otlpexport.ErrHuman, http.StatusForbidden, "forbidden"},
	{otlpexport.ErrNotFound, http.StatusNotFound, "not_found"},
	{otlpexport.ErrState, http.StatusConflict, "not_pending"},
	{otlpexport.ErrURL, http.StatusConflict, "url_refused"},
	{otlpexport.ErrMetadata, http.StatusConflict, "url_refused"},
}

func (p otlpPages) activate(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := p.h.requestID(w, r)
	if !ok {
		return
	}
	su := stepUpOfSession(s)
	d, err := p.d.Activate(callerContext(r, s), id, &su) //nolint:contextcheck // callerContext derives from the request's context
	if err != nil {
		for _, e := range otlpErrors {
			if errors.Is(err, e.err) {
				p.h.jsonError(w, e.status, e.code)
				return
			}
		}
		if pcerr.CodeOf(err) == pcerr.PermissionDenied {
			p.h.jsonError(w, http.StatusForbidden, "forbidden")
			return
		}
		p.h.log.ErrorContext(r.Context(), "web.otlp_destinations", pclog.Err(err))
		p.h.jsonError(w, http.StatusInternalServerError, "internal")
		return
	}
	p.h.writeJSON(w, http.StatusOK, map[string]string{"state": d.State})
}
