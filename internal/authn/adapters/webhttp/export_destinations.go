// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"context"
	"errors"
	"net/http"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/exports"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The export destination activation page (G0 M20 D252; HR-513):
// GET /integrations/export-destinations/{id}/confirm shows the target, whether
// it is internal and the data classes it will receive. A person holding
// siem.manage activates it with a POST on the same path right after a
// security-key step-up on this browser session. Nothing else activates it:
// no API call, key or link. GET never changes anything; every POST carries
// the CSRF proof (HR-151).

// ExportDestinationsPath is the page's path.
const ExportDestinationsPath = "/integrations/export-destinations"

// ExportDestinations is the activation use-case set (exports.Service).
type ExportDestinations interface {
	Get(ctx context.Context, id ids.UUID) (exports.Destination, error)
	Activate(ctx context.Context, id ids.UUID, su stepup.StepUp) (exports.Destination, error)
}

// WithExportDestinations adds the activation page; call it before Mount.
func (h *Handler) WithExportDestinations(e ExportDestinations) *Handler {
	h.exportDestinations = e
	return h
}

func (h *Handler) mountExportDestinations(m *http.ServeMux) {
	if h.exportDestinations == nil {
		return
	}
	h.withSession(m, http.MethodGet, ExportDestinationsPath+"/{id}/confirm", h.exportDestinationPage)
	h.withSession(m, http.MethodPost, ExportDestinationsPath+"/{id}/confirm", h.activateExportDestination)
}

// exportDestinationView is the data of integration_export_destination.html.
type exportDestinationView struct {
	page
	exports.Destination
	CanActivate bool
}

func (h *Handler) exportDestinationPage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		h.toLogin(w, r)
		return
	}
	const title = "Evidence export destination"
	id, err := ids.ParseUUID(r.PathValue("id"))
	var d exports.Destination
	if err == nil {
		d, err = h.exportDestinations.Get(callerContext(r, s), id)
	} else {
		err = exports.ErrNotFound
	}
	switch c := pcerr.CodeOf(err); {
	case err == nil:
	case c == pcerr.NotFound || c == pcerr.PermissionDenied || c == pcerr.InvalidArgument:
		h.integrationNotFound(w, title)
		return
	default:
		h.fail(w, r, err)
		return
	}
	h.renderAny(w, http.StatusOK, "integration_export_destination.html", exportDestinationView{
		page: page{Title: title, Session: s}, Destination: d,
		CanActivate: d.State == exports.StatePending && s.Human() && s.Can(exports.PermManage, td.OrgPath(s.Org)),
	})
}

// exportDestinationErrors maps the use cases' errors to the page's codes.
var exportDestinationErrors = []struct {
	err    error
	status int
	code   string
}{
	{stepup.ErrStepUp, http.StatusForbidden, "step_up_required"},
	{exports.ErrNotFound, http.StatusNotFound, "not_found"},
	{exports.ErrState, http.StatusConflict, "not_pending"},
	{exports.ErrURL, http.StatusConflict, "url_refused"},
	{exports.ErrMetadata, http.StatusConflict, "url_refused"},
	{exports.ErrHuman, http.StatusForbidden, "forbidden"},
}

func (h *Handler) activateExportDestination(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	d, err := h.exportDestinations.Activate(callerContext(r, s), id, stepUpOfSession(s)) //nolint:contextcheck // callerContext derives from the request's context
	if err == nil {
		h.writeJSON(w, http.StatusOK, map[string]string{"state": d.State})
		return
	}
	for _, e := range exportDestinationErrors {
		if errors.Is(err, e.err) {
			h.jsonError(w, e.status, e.code)
			return
		}
	}
	if pcerr.CodeOf(err) == pcerr.PermissionDenied {
		h.jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	h.log.ErrorContext(r.Context(), "web.export_destinations", pclog.Err(err))
	h.jsonError(w, http.StatusInternalServerError, "internal")
}
