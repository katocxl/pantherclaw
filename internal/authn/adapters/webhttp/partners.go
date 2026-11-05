// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/partners"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The MSSP partner pages (G0 M38 D1100, D1100a, D1101; HR-810..812):
//
//	GET  /partners/links/{id}/decide        customer: the link request's decide page
//	POST /partners/links/{id}/approve       customer: approve (step-up)
//	POST /partners/links/{id}/deny          customer: deny (step-up)
//	GET  /partners/customers/{org}/open     partner: the open page of a customer
//	POST /partners/customers/{org}/open     partner: open a partner session (step-up)
//	POST /partners/logout                   end the browser's partner session
//
// Deciding needs a customer person holding partner.approve, opening a
// partner person holding partner.operate, each with a security-key step-up
// of this browser session within five minutes, made right before on the
// page; the API refuses both (STEP_UP_REQUIRED). The decide page shows
// exactly what is approved. GET never changes anything; every POST carries
// the CSRF proof (HR-151). Opening a session replaces this browser's
// session cookie with the partner session's.

// PartnerPages is the use-case set of the pages (partners.Service).
type PartnerPages interface {
	Get(ctx context.Context, id ids.UUID) (partners.Link, error)
	Decide(ctx context.Context, id ids.UUID, approve bool, su *stepup.StepUp) (partners.Link, error)
	LiveLink(ctx context.Context, customer ids.UUID) (partners.Link, error)
	Open(ctx context.Context, op partners.Operator, customer ids.OrgID) (partners.Opened, error)
	Logout(ctx context.Context, cookie string) error
}

// MountPartners adds the partner pages to mux. The server calls it after
// Mount.
func (h *Handler) MountPartners(mux *http.ServeMux, pp PartnerPages) {
	if pp == nil {
		return
	}
	p := partnerPages{h: h, pp: pp}
	h.withSession(mux, http.MethodGet, partners.LinksPath+"/{id}/decide", p.decidePage)
	h.withSession(mux, http.MethodPost, partners.LinksPath+"/{id}/approve", p.approve)
	h.withSession(mux, http.MethodPost, partners.LinksPath+"/{id}/deny", p.deny)
	h.withSession(mux, http.MethodGet, partners.CustomersPath+"/{org}/open", p.openPage)
	h.withSession(mux, http.MethodPost, partners.CustomersPath+"/{org}/open", p.open)
	// Signing a partner session out needs no browser session: the cookie
	// holds the partner session, which the pages never accept.
	h.routes = append(h.routes, Route{Method: http.MethodPost, Path: partners.LogoutPath, CSRF: true})
	mux.HandleFunc(http.MethodPost+" "+partners.LogoutPath, h.limited(p.logout))
}

type partnerPages struct {
	h  *Handler
	pp PartnerPages
}

// partnerLinkView is the data of partner_link.html and partner_open.html.
type partnerLinkView struct {
	page
	Link      partners.Link
	Propose   bool
	CanDecide bool
	CanOpen   bool
	Customer  string
}

// partnerErrors maps the use cases' errors to the pages' codes.
var partnerErrors = []struct {
	err    error
	status int
	code   string
}{
	{stepup.ErrStepUp, http.StatusForbidden, "step_up_required"},
	{partners.ErrHuman, http.StatusForbidden, "forbidden"},
	{partners.ErrPartnerSide, http.StatusForbidden, "forbidden"},
	{partners.ErrSelfDecision, http.StatusForbidden, "self_approval"},
	{partners.ErrEdition, http.StatusForbidden, "edition"},
	{partners.ErrLinkNotFound, http.StatusNotFound, "not_found"},
	{partners.ErrNotRequested, http.StatusConflict, "not_pending"},
	{partners.ErrNoLink, http.StatusConflict, "no_grant"},
}

func (p partnerPages) jsonFail(w http.ResponseWriter, r *http.Request, err error) {
	for _, e := range partnerErrors {
		if errors.Is(err, e.err) {
			p.h.jsonError(w, e.status, e.code)
			return
		}
	}
	if pcerr.CodeOf(err) == pcerr.PermissionDenied {
		p.h.jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	p.h.log.ErrorContext(r.Context(), "web.partners", pclog.Err(err))
	p.h.jsonError(w, http.StatusInternalServerError, "internal")
}

func (p partnerPages) notFound(w http.ResponseWriter, title string) {
	p.h.render(w, http.StatusNotFound, "error.html", page{Title: title, Message: "This does not exist, or you cannot see it."})
}

// decidePage is a customer person's decide page for one link request.
func (p partnerPages) decidePage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	const title = "MSSP partner link"
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		p.h.toLogin(w, r)
		return
	}
	id, err := ids.ParseUUID(r.PathValue("id"))
	if err != nil {
		p.notFound(w, title)
		return
	}
	l, err := p.pp.Get(callerContext(r, s), id)
	switch c := pcerr.CodeOf(err); {
	case err == nil && l.CustomerOrg == s.Org.UUID():
		p.h.renderAny(w, http.StatusOK, "partner_link.html", partnerLinkView{
			page: page{Title: title, Session: s}, Link: l, Propose: l.Has(partners.ScopePropose),
			CanDecide: s.Human() && s.Can(td.PermPartnerApprove, td.OrgPath(s.Org)) && l.State == partners.StateRequested,
		})
	case err == nil, c == pcerr.NotFound, c == pcerr.PermissionDenied, c == pcerr.InvalidArgument:
		p.notFound(w, title)
	default:
		p.h.fail(w, r, err)
	}
}

func (p partnerPages) approve(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	p.decide(w, r, s, true)
}

func (p partnerPages) deny(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	p.decide(w, r, s, false)
}

func (p partnerPages) decide(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession, approve bool) {
	id, ok := p.h.requestID(w, r)
	if !ok {
		return
	}
	l, err := p.pp.Decide(callerContext(r, s), id, approve, stepUpPtr(s)) //nolint:contextcheck // callerContext derives from the request's context
	if err != nil {
		p.jsonFail(w, r, err)
		return
	}
	p.h.writeJSON(w, http.StatusOK, map[string]string{"state": l.State})
}

// openPage is a partner person's open page for one customer.
func (p partnerPages) openPage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	const title = "Open a partner session"
	customer, err := ids.ParseUUID(r.PathValue("org"))
	if err != nil {
		p.notFound(w, title)
		return
	}
	l, err := p.pp.LiveLink(callerContext(r, s), customer)
	switch c := pcerr.CodeOf(err); {
	case err == nil:
		p.h.renderAny(w, http.StatusOK, "partner_open.html", partnerLinkView{
			page: page{Title: title, Session: s}, Link: l, Propose: l.Has(partners.ScopePropose), Customer: customer.String(),
			CanOpen: s.Human() && s.Can(td.PermPartnerOperate, td.OrgPath(s.Org)),
		})
	case c == pcerr.NotFound, c == pcerr.PermissionDenied, c == pcerr.InvalidArgument, c == pcerr.FailedPrecondition:
		p.notFound(w, title)
	default:
		p.h.fail(w, r, err)
	}
}

func (p partnerPages) open(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	customer, err := ids.Parse[ids.Org](r.PathValue("org"))
	if err != nil {
		p.h.jsonError(w, http.StatusNotFound, "not_found")
		return
	}
	op := partners.Operator{Caller: s.Caller, StepUp: stepUpPtr(s), UserAgent: r.UserAgent(), IP: p.h.clientIP(r)}
	o, err := p.pp.Open(r.Context(), op, customer)
	if err != nil {
		p.jsonFail(w, r, err)
		return
	}
	// The partner session replaces this browser's session cookie; the
	// partner person's own session lives on and signs in again later.
	p.h.setCookie(w, sessionCookie, o.Secret, partners.SessionMaxAge, http.SameSiteStrictMode)
	p.h.log.InfoContext(r.Context(), "web.partner_session_opened", slog.String("org", customer.String()),
		slog.String("session", o.Session.String()))
	p.h.writeJSON(w, http.StatusOK, map[string]string{"next": authnapp.ConsolePath})
}

// logout ends the browser's partner session and clears the cookie.
func (p partnerPages) logout(w http.ResponseWriter, r *http.Request) {
	if !p.h.csrfOK(r) {
		p.h.jsonError(w, http.StatusForbidden, "csrf")
		return
	}
	if c, err := r.Cookie(p.h.cookieName(sessionCookie)); err == nil && partners.IsSessionCookie(c.Value) {
		if err := p.pp.Logout(r.Context(), c.Value); err != nil {
			p.h.log.ErrorContext(r.Context(), "web.partner_logout", pclog.Err(err))
			p.h.jsonError(w, http.StatusInternalServerError, "internal")
			return
		}
		p.h.setCookie(w, sessionCookie, "", -1, http.SameSiteStrictMode)
	}
	p.h.writeJSON(w, http.StatusOK, map[string]bool{"signed_out": true})
}
