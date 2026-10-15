// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"context"
	"errors"
	"net/http"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/siem"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	"github.com/katocxl/pantherclaw/internal/signals"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The integration activation pages (G0 M10 D35, D37; HR-259, HR-261):
// GET /integrations/destinations/{id}/confirm shows a SIEM export
// destination, its URL, whether it is internal and the data classes it
// will receive; GET /integrations/transmitters/{id}/confirm shows a Shared
// Signals transmitter, its issuer and key set. A person holding the manage
// permission activates either with a POST on the same path right after a
// security-key step-up on this browser session (the account page's
// step-up). Nothing else activates them: no API call, key or link. GET
// never changes anything; every POST carries the CSRF proof (HR-151).

// Integration paths.
const (
	DestinationsPath = "/integrations/destinations"
	TransmittersPath = "/integrations/transmitters"
)

// Integrations is the activation use-case set (siem.Service and
// signals.Service).
type Integrations interface {
	Destination(ctx context.Context, id ids.UUID) (siem.Destination, error)
	ActivateDestination(ctx context.Context, id ids.UUID, su stepup.StepUp) (siem.Destination, error)
	Transmitter(ctx context.Context, id ids.UUID) (signals.Transmitter, error)
	ActivateTransmitter(ctx context.Context, id ids.UUID, su stepup.StepUp) (signals.Transmitter, error)
}

// WithIntegrations adds the activation pages; call it before Mount.
func (h *Handler) WithIntegrations(i Integrations) *Handler {
	h.integrations = i
	return h
}

func (h *Handler) mountIntegrations(m *http.ServeMux) {
	if h.integrations == nil {
		return
	}
	h.withSession(m, http.MethodGet, DestinationsPath+"/{id}/confirm", h.destinationPage)
	h.withSession(m, http.MethodPost, DestinationsPath+"/{id}/confirm", h.activateDestination)
	h.withSession(m, http.MethodGet, TransmittersPath+"/{id}/confirm", h.transmitterPage)
	h.withSession(m, http.MethodPost, TransmittersPath+"/{id}/confirm", h.activateTransmitter)
}

// destinationView is the data of integration_destination.html.
type destinationView struct {
	page
	siem.Destination
	CanActivate bool
}

// transmitterView is the data of integration_transmitter.html.
type transmitterView struct {
	page
	signals.Transmitter
	CanActivate bool
}

func stepUpOfSession(s authnapp.BrowserSession) stepup.StepUp {
	return stepup.StepUp{Credential: s.StepUpCredential, At: s.StepUpAt}
}

func (h *Handler) integrationNotFound(w http.ResponseWriter, title string) {
	h.render(w, http.StatusNotFound, "error.html", page{
		Title: title, Message: "This integration does not exist, or you cannot see it.",
	})
}

func (h *Handler) destinationPage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		h.toLogin(w, r)
		return
	}
	const title = "Export destination"
	id, err := ids.ParseUUID(r.PathValue("id"))
	var d siem.Destination
	if err == nil {
		d, err = h.integrations.Destination(callerContext(r, s), id)
	} else {
		err = siem.ErrNotFound
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
	h.renderAny(w, http.StatusOK, "integration_destination.html", destinationView{
		page: page{Title: title, Session: s}, Destination: d,
		CanActivate: d.State == siem.StatePending && s.Human() && s.Can(siem.PermManage, td.OrgPath(s.Org)),
	})
}

func (h *Handler) transmitterPage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		h.toLogin(w, r)
		return
	}
	const title = "Shared Signals transmitter"
	id, err := ids.ParseUUID(r.PathValue("id"))
	var t signals.Transmitter
	if err == nil {
		t, err = h.integrations.Transmitter(callerContext(r, s), id)
	} else {
		err = signals.ErrNotFound
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
	h.renderAny(w, http.StatusOK, "integration_transmitter.html", transmitterView{
		page: page{Title: title, Session: s}, Transmitter: t,
		CanActivate: t.State == signals.StatePending && s.Human() && s.Can(signals.PermManage, td.OrgPath(s.Org)),
	})
}

// integrationErrors maps the use cases' errors to the pages' codes.
var integrationErrors = []struct {
	err    error
	status int
	code   string
}{
	{stepup.ErrStepUp, http.StatusForbidden, "step_up_required"},
	{siem.ErrNotFound, http.StatusNotFound, "not_found"},
	{signals.ErrNotFound, http.StatusNotFound, "not_found"},
	{siem.ErrState, http.StatusConflict, "not_pending"},
	{signals.ErrState, http.StatusConflict, "not_pending"},
	{siem.ErrURL, http.StatusConflict, "url_refused"},
	{siem.ErrMetadata, http.StatusConflict, "url_refused"},
	{siem.ErrHuman, http.StatusForbidden, "forbidden"},
	{signals.ErrHuman, http.StatusForbidden, "forbidden"},
}

func (h *Handler) integrationError(w http.ResponseWriter, r *http.Request, err error) {
	for _, e := range integrationErrors {
		if errors.Is(err, e.err) {
			h.jsonError(w, e.status, e.code)
			return
		}
	}
	if pcerr.CodeOf(err) == pcerr.PermissionDenied {
		h.jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	h.log.ErrorContext(r.Context(), "web.integrations", pclog.Err(err))
	h.jsonError(w, http.StatusInternalServerError, "internal")
}

func (h *Handler) activateDestination(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	d, err := h.integrations.ActivateDestination(callerContext(r, s), id, stepUpOfSession(s))
	if err != nil {
		h.integrationError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"state": d.State})
}

func (h *Handler) activateTransmitter(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	t, err := h.integrations.ActivateTransmitter(callerContext(r, s), id, stepUpOfSession(s))
	if err != nil {
		h.integrationError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"state": t.State})
}
