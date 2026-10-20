// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"context"
	"errors"
	"net/http"

	"github.com/katocxl/pantherclaw/internal/a2a/a2astore"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The a2a pin confirm page (G0 M14 D30, D85):
//
//	GET  /connections/{id}/a2a-pin                 the pin that serves and the one proposed
//	POST /connections/{id}/a2a-pin/{pin}/confirm   confirm the proposal
//
// Confirming makes the proposed card, interface, skills and peer scope the
// ones the gateway uses. It needs a security-key step-up of this browser
// session within five minutes, made right before on the page; the API
// refuses it (STEP_UP_REQUIRED). GET never changes anything; the POST
// carries the CSRF proof (HR-151).

// A2APins is the use-case set of the page (a2astore.Pins).
type A2APins interface {
	Get(ctx context.Context, conn ids.UUID) (a2astore.Proposal, error)
	Confirm(ctx context.Context, conn, pin ids.UUID, su *stepup.StepUp) (a2astore.Pin, error)
}

// MountA2APins adds the confirm page to mux. The server calls it after
// Mount.
func (h *Handler) MountA2APins(mux *http.ServeMux, pins A2APins) {
	if pins == nil {
		return
	}
	p := a2aPinPages{h: h, pins: pins}
	h.withSession(mux, http.MethodGet, "/connections/{id}/a2a-pin", p.page)
	h.withSession(mux, http.MethodPost, "/connections/{id}/a2a-pin/{pin}/confirm", p.confirm)
}

type a2aPinPages struct {
	h    *Handler
	pins A2APins
}

// a2aPinView is the data of a2a_pin.html.
type a2aPinView struct {
	page
	a2astore.Proposal
	CanManage bool
}

func (p a2aPinPages) page(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	const title = "Peer agent card"
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
	got, err := p.pins.Get(callerContext(r, s), id)
	switch {
	case err == nil:
		p.h.renderAny(w, http.StatusOK, "a2a_pin.html", a2aPinView{
			page: page{Title: title, Session: s}, Proposal: got,
			CanManage: s.Human() && s.Can(td.PermConnectionManage, td.OrgPath(s.Org)),
		})
	case errors.Is(err, a2astore.ErrNotFound), pcerr.CodeOf(err) == pcerr.PermissionDenied, pcerr.CodeOf(err) == pcerr.InvalidArgument:
		notFound()
	default:
		p.h.fail(w, r, err)
	}
}

// a2aPinErrors maps the use cases' errors to the page's codes.
var a2aPinErrors = []struct {
	err    error
	status int
	code   string
}{
	{stepup.ErrStepUp, http.StatusForbidden, "step_up_required"},
	{a2astore.ErrHuman, http.StatusForbidden, "forbidden"},
	{a2astore.ErrNotFound, http.StatusNotFound, "not_found"},
	{a2astore.ErrNoProposal, http.StatusConflict, "not_pending"},
	{a2astore.ErrCardChanged, http.StatusConflict, "card_changed"},
}

func (p a2aPinPages) confirm(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := p.h.requestID(w, r)
	if !ok {
		return
	}
	pin, err := ids.ParseUUID(r.PathValue("pin"))
	if err != nil {
		p.h.jsonError(w, http.StatusNotFound, "not_found")
		return
	}
	got, err := p.pins.Confirm(callerContext(r, s), id, pin, stepUpPtr(s)) //nolint:contextcheck // callerContext derives from the request's context
	if err != nil {
		for _, e := range a2aPinErrors {
			if errors.Is(err, e.err) {
				p.h.jsonError(w, e.status, e.code)
				return
			}
		}
		if pcerr.CodeOf(err) == pcerr.PermissionDenied {
			p.h.jsonError(w, http.StatusForbidden, "forbidden")
			return
		}
		if pcerr.CodeOf(err) == pcerr.FailedPrecondition {
			// The card could not be read again, or no longer pins.
			p.h.jsonError(w, http.StatusConflict, "card_changed")
			return
		}
		p.h.log.ErrorContext(r.Context(), "web.a2a_pins", pclog.Err(err))
		p.h.jsonError(w, http.StatusInternalServerError, "internal")
		return
	}
	p.h.writeJSON(w, http.StatusOK, map[string]string{"state": got.State, "card_digest": got.Digest()})
}
