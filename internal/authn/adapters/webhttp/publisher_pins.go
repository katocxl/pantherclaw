// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"context"
	"errors"
	"net/http"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	bundlesapp "github.com/katocxl/pantherclaw/internal/bundles/app"
	bdomain "github.com/katocxl/pantherclaw/internal/bundles/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The publisher pin activation page (G0 M37 D1081; FQ37-1; HR-795):
//
//	GET  /integrations/publisher-pins/{id}/confirm  a pin: publisher, kid, fingerprint, allowed kinds
//	POST /integrations/publisher-pins/{id}/confirm  activate it
//
// Activating needs a person holding publisher.manage and a security-key
// step-up of this browser session within five minutes, as an OTLP
// destination; the API refuses it (STEP_UP_REQUIRED). GET never changes
// anything; the POST carries the CSRF proof (HR-151).

// PublisherPins is the use-case set of the page (bundles/app.Service).
type PublisherPins interface {
	GetPin(ctx context.Context, id ids.UUID) (bundlesapp.Pin, error)
	ActivatePin(ctx context.Context, id ids.UUID, su *stepup.StepUp) (bundlesapp.Pin, error)
}

// MountPublisherPins adds the activation page to mux. The server calls it
// after Mount.
func (h *Handler) MountPublisherPins(mux *http.ServeMux, p PublisherPins) {
	if p == nil {
		return
	}
	pp := pinPages{h: h, p: p}
	h.withSession(mux, http.MethodGet, bundlesapp.ConfirmPath+"/{id}/confirm", pp.page)
	h.withSession(mux, http.MethodPost, bundlesapp.ConfirmPath+"/{id}/confirm", pp.activate)
}

type pinPages struct {
	h *Handler
	p PublisherPins
}

// publisherPinView is the data of publisher_pin.html.
type publisherPinView struct {
	page
	bundlesapp.Pin
	CanActivate bool
}

func (pp pinPages) page(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	const title = "Publisher key"
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		pp.h.toLogin(w, r)
		return
	}
	id, err := ids.ParseUUID(r.PathValue("id"))
	var pin bundlesapp.Pin
	if err == nil {
		pin, err = pp.p.GetPin(callerContext(r, s), id)
	} else {
		err = bdomain.ErrPinNotFound
	}
	switch c := pcerr.CodeOf(err); {
	case err == nil:
	case c == pcerr.NotFound || c == pcerr.PermissionDenied || c == pcerr.InvalidArgument:
		pp.h.integrationNotFound(w, title)
		return
	default:
		pp.h.fail(w, r, err)
		return
	}
	pp.h.renderAny(w, http.StatusOK, "publisher_pin.html", publisherPinView{
		page: page{Title: title, Session: s}, Pin: pin,
		CanActivate: pin.State == bdomain.PinPending && s.Human() && s.Can(bdomain.PermPublisherManage, td.OrgPath(s.Org)),
	})
}

// pinErrors maps the use cases' errors to the page's codes.
var pinErrors = []struct {
	err    error
	status int
	code   string
}{
	{stepup.ErrStepUp, http.StatusForbidden, "step_up_required"},
	{bdomain.ErrHuman, http.StatusForbidden, "forbidden"},
	{bdomain.ErrPinNotFound, http.StatusNotFound, "not_found"},
	{bdomain.ErrPinState, http.StatusConflict, "not_pending"},
	{bdomain.ErrKeyWithdrawn, http.StatusConflict, "not_pending"},
}

func (pp pinPages) activate(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := pp.h.requestID(w, r)
	if !ok {
		return
	}
	su := stepUpOfSession(s)
	pin, err := pp.p.ActivatePin(callerContext(r, s), id, &su) //nolint:contextcheck // callerContext derives from the request's context
	if err != nil {
		for _, e := range pinErrors {
			if errors.Is(err, e.err) {
				pp.h.jsonError(w, e.status, e.code)
				return
			}
		}
		if pcerr.CodeOf(err) == pcerr.PermissionDenied {
			pp.h.jsonError(w, http.StatusForbidden, "forbidden")
			return
		}
		pp.h.log.ErrorContext(r.Context(), "web.publisher_pins", pclog.Err(err))
		pp.h.jsonError(w, http.StatusInternalServerError, "internal")
		return
	}
	pp.h.writeJSON(w, http.StatusOK, map[string]string{"state": pin.State})
}
