// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"context"
	"errors"
	"net/http"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/payments/anchors"
	"github.com/katocxl/pantherclaw/internal/payments/ap2"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The payment trust anchor activation page (G0 M39 D1121; HR-832):
//
//	GET  /integrations/payment-anchors/{id}/confirm  an anchor, its kind and key source
//	POST /integrations/payment-anchors/{id}/confirm  activate it
//
// Activating needs a person holding payments.manage and a security-key
// step-up of this browser session within five minutes; the API refuses it
// (STEP_UP_REQUIRED). The sandbox rules are checked again (D1120). GET
// never changes anything; the POST carries the CSRF proof (HR-151).

// PaymentAnchors is the use-case set of the page (anchors.Service).
type PaymentAnchors interface {
	Get(ctx context.Context, id ids.UUID) (anchors.TrustAnchor, error)
	Activate(ctx context.Context, id ids.UUID, su *stepup.StepUp) (anchors.TrustAnchor, error)
}

// MountPaymentAnchors adds the activation page to mux. The server calls it
// after Mount.
func (h *Handler) MountPaymentAnchors(mux *http.ServeMux, a PaymentAnchors) {
	if a == nil {
		return
	}
	p := paymentAnchorPages{h: h, a: a}
	h.withSession(mux, http.MethodGet, anchors.ConfirmPath+"/{id}/confirm", p.page)
	h.withSession(mux, http.MethodPost, anchors.ConfirmPath+"/{id}/confirm", p.activate)
}

type paymentAnchorPages struct {
	h *Handler
	a PaymentAnchors
}

// paymentAnchorView is the data of payment_anchor.html.
type paymentAnchorView struct {
	page
	anchors.TrustAnchor
	CanActivate bool
}

func (p paymentAnchorPages) page(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	const title = "Payment trust anchor"
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		p.h.toLogin(w, r)
		return
	}
	id, err := ids.ParseUUID(r.PathValue("id"))
	var a anchors.TrustAnchor
	if err == nil {
		a, err = p.a.Get(callerContext(r, s), id)
	} else {
		err = anchors.ErrNotFound
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
	p.h.renderAny(w, http.StatusOK, "payment_anchor.html", paymentAnchorView{
		page: page{Title: title, Session: s}, TrustAnchor: a,
		CanActivate: a.State == anchors.StatePending && s.Human() && s.Can(anchors.PermManage, td.OrgPath(s.Org)),
	})
}

// paymentAnchorErrors maps the use cases' errors to the page's codes.
var paymentAnchorErrors = []struct {
	err    error
	status int
	code   string
}{
	{stepup.ErrStepUp, http.StatusForbidden, "step_up_required"},
	{anchors.ErrHuman, http.StatusForbidden, "forbidden"},
	{anchors.ErrNotFound, http.StatusNotFound, "not_found"},
	{anchors.ErrState, http.StatusConflict, "not_pending"},
	{anchors.ErrEdition, http.StatusForbidden, "edition_required"},
	{ap2.ErrLiveRefused, http.StatusConflict, "url_refused"},
}

func (p paymentAnchorPages) activate(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := p.h.requestID(w, r)
	if !ok {
		return
	}
	su := stepUpOfSession(s)
	a, err := p.a.Activate(callerContext(r, s), id, &su) //nolint:contextcheck // callerContext derives from the request's context
	if err != nil {
		for _, e := range paymentAnchorErrors {
			if errors.Is(err, e.err) {
				p.h.jsonError(w, e.status, e.code)
				return
			}
		}
		if pcerr.CodeOf(err) == pcerr.PermissionDenied {
			p.h.jsonError(w, http.StatusForbidden, "forbidden")
			return
		}
		p.h.log.ErrorContext(r.Context(), "web.payment_anchors", pclog.Err(err))
		p.h.jsonError(w, http.StatusInternalServerError, "internal")
		return
	}
	p.h.writeJSON(w, http.StatusOK, map[string]string{"state": a.State})
}
