// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net/http"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	"github.com/katocxl/pantherclaw/internal/support"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The support access pages (G0 M13 D32, D38; HR-385, HR-386):
//
//	GET  /support-access/request                     staff: the request form
//	POST /support-access/request                     staff: ask (step-up)
//	GET  /support-access/requests/{org}/{id}          staff: their request
//	POST /support-access/requests/{org}/{id}/open     staff: open a support session (step-up)
//	GET  /support-access/{id}                         org admin: the request's confirm page
//	POST /support-access/{id}/approve                 org admin: approve (step-up)
//	POST /support-access/{id}/deny                    org admin: deny (step-up)
//	POST /support-access/logout                       end the browser's support session
//
// Asking, opening, approving and denying need a security-key step-up of
// this browser session within five minutes, made right before on the page;
// the API refuses them (STEP_UP_REQUIRED). The page shows exactly what is
// approved. GET never changes anything; every POST carries the CSRF proof
// (HR-151). Opening a session replaces this browser's session cookie with
// the support session's.

// SupportAccess is the use-case set of the pages (support.Service).
type SupportAccess interface {
	IsStaff(ctx context.Context, c tapp.Caller) (bool, error)
	Request(ctx context.Context, st support.Staff, in support.RequestInput) (support.Request, error)
	StaffRequest(ctx context.Context, staff tapp.Caller, org, id ids.UUID) (support.Request, error)
	Open(ctx context.Context, st support.Staff, org ids.OrgID, request ids.UUID) (support.Opened, error)
	GetRequest(ctx context.Context, id ids.UUID) (support.Request, *support.Grant, error)
	Decide(ctx context.Context, id ids.UUID, approve bool, su *stepup.StepUp) (support.Request, *support.Grant, error)
	Logout(ctx context.Context, cookie string) error
}

// MountSupportAccess adds the support access pages to mux. The server
// calls it after Mount.
func (h *Handler) MountSupportAccess(mux *http.ServeMux, sa SupportAccess) {
	if sa == nil {
		return
	}
	h.support = sa
	p := supportPages{h: h, sa: sa}
	h.withSession(mux, http.MethodGet, "/support-access/request", p.requestForm)
	h.withSession(mux, http.MethodPost, "/support-access/request", p.request)
	h.withSession(mux, http.MethodGet, "/support-access/requests/{org}/{id}", p.staffRequest)
	h.withSession(mux, http.MethodPost, "/support-access/requests/{org}/{id}/open", p.open)
	h.withSession(mux, http.MethodGet, "/support-access/{id}", p.confirm)
	h.withSession(mux, http.MethodPost, "/support-access/{id}/approve", func(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
		p.decide(w, r, s, true)
	})
	h.withSession(mux, http.MethodPost, "/support-access/{id}/deny", func(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
		p.decide(w, r, s, false)
	})
	// Signing a support session out needs no browser session: the cookie
	// holds the support session, which the pages never accept.
	h.routes = append(h.routes, Route{Method: http.MethodPost, Path: "/support-access/logout", CSRF: true})
	mux.HandleFunc(http.MethodPost+" /support-access/logout", h.limited(p.logout))
}

type supportPages struct {
	h  *Handler
	sa SupportAccess
}

// supportView is the data of the support pages.
type supportView struct {
	page
	Request   support.Request
	Grant     *support.Grant
	Org       string
	CanDecide bool
	Staff     bool
}

// supportErrors maps the use cases' errors to the pages' codes.
var supportErrors = []struct {
	err    error
	status int
	code   string
}{
	{stepup.ErrStepUp, http.StatusForbidden, "step_up_required"},
	{support.ErrNotStaff, http.StatusForbidden, "forbidden"},
	{support.ErrHuman, http.StatusForbidden, "forbidden"},
	{support.ErrSelfApproval, http.StatusForbidden, "self_approval"},
	{support.ErrEdition, http.StatusForbidden, "edition"},
	{support.ErrNeedsHosted, http.StatusConflict, "unavailable"},
	{support.ErrOff, http.StatusConflict, "unavailable"},
	{support.ErrInvalid, http.StatusBadRequest, "invalid"},
	{support.ErrOrgNotFound, http.StatusNotFound, "not_found"},
	{support.ErrRequestNotFound, http.StatusNotFound, "not_found"},
	{support.ErrNotPending, http.StatusConflict, "not_pending"},
	{support.ErrNoGrant, http.StatusConflict, "no_grant"},
}

func (p supportPages) jsonFail(w http.ResponseWriter, r *http.Request, err error) {
	for _, e := range supportErrors {
		if errors.Is(err, e.err) {
			p.h.jsonError(w, e.status, e.code)
			return
		}
	}
	if pcerr.CodeOf(err) == pcerr.PermissionDenied {
		p.h.jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	p.h.log.ErrorContext(r.Context(), "web.support_access", pclog.Err(err))
	p.h.jsonError(w, http.StatusInternalServerError, "internal")
}

func (p supportPages) notFound(w http.ResponseWriter, title string) {
	p.h.render(w, http.StatusNotFound, "error.html", page{Title: title, Message: "This does not exist, or you cannot see it."})
}

func staffOf(r *http.Request, s authnapp.BrowserSession) support.Staff {
	return support.Staff{Caller: s.Caller, StepUp: stepUpPtr(s), UserAgent: r.UserAgent()}
}

// requestForm shows the staff's request form.
func (p supportPages) requestForm(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	const title = "Request support access"
	ok, err := p.sa.IsStaff(r.Context(), s.Caller)
	if err != nil {
		p.h.fail(w, r, err)
		return
	}
	if !ok {
		p.notFound(w, title)
		return
	}
	p.h.renderAny(w, http.StatusOK, "support_request.html", supportView{
		page: page{Title: title, Session: s}, Staff: true, Org: r.URL.Query().Get("target"),
	})
}

// supportRequestBody is the body of POST /support-access/request.
type supportRequestBody struct {
	Org   string `json:"org"`
	Task  string `json:"task"`
	Scope string `json:"scope,omitzero"`
	Hours int    `json:"hours"`
}

func (p supportPages) request(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		p.h.jsonError(w, http.StatusBadRequest, "invalid")
		return
	}
	var in supportRequestBody
	if err := json.Unmarshal(b, &in, json.RejectUnknownMembers(true)); err != nil {
		p.h.jsonError(w, http.StatusBadRequest, "invalid")
		return
	}
	org, err := ids.Parse[ids.Org](in.Org)
	if err != nil {
		p.h.jsonError(w, http.StatusBadRequest, "invalid")
		return
	}
	st := staffOf(r, s)
	st.IP = p.h.clientIP(r)
	req, err := p.sa.Request(r.Context(), st, support.RequestInput{Org: org, Task: in.Task, Scope: in.Scope, Hours: in.Hours})
	if err != nil {
		p.jsonFail(w, r, err)
		return
	}
	p.h.writeJSON(w, http.StatusOK, map[string]string{
		"request": req.ID.String(), "next": "/support-access/requests/" + org.String() + "/" + req.ID.String(),
	})
}

// staffRequest shows a staff member their own request.
func (p supportPages) staffRequest(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	const title = "Support access request"
	org, err1 := ids.ParseUUID(r.PathValue("org"))
	id, err2 := ids.ParseUUID(r.PathValue("id"))
	if err1 != nil || err2 != nil {
		p.notFound(w, title)
		return
	}
	req, err := p.sa.StaffRequest(r.Context(), s.Caller, org, id)
	switch {
	case errors.Is(err, support.ErrNotStaff), errors.Is(err, support.ErrRequestNotFound):
		p.notFound(w, title)
		return
	case err != nil:
		p.h.fail(w, r, err)
		return
	}
	p.h.renderAny(w, http.StatusOK, "support_request.html", supportView{
		page: page{Title: title, Session: s}, Request: req, Org: org.String(), Staff: true,
	})
}

func (p supportPages) open(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	org, err1 := ids.Parse[ids.Org](r.PathValue("org"))
	id, err2 := ids.ParseUUID(r.PathValue("id"))
	if err1 != nil || err2 != nil {
		p.h.jsonError(w, http.StatusNotFound, "not_found")
		return
	}
	st := staffOf(r, s)
	st.IP = p.h.clientIP(r)
	o, err := p.sa.Open(r.Context(), st, org, id)
	if err != nil {
		p.jsonFail(w, r, err)
		return
	}
	// The support session replaces this browser's session cookie; the
	// staff member's own session lives on and signs in again later.
	p.h.setCookie(w, sessionCookie, o.Secret, support.SessionMaxAge, http.SameSiteStrictMode)
	p.h.log.InfoContext(r.Context(), "web.support_session_opened", slog.String("org", org.String()),
		slog.String("session", o.Session.String()))
	p.h.writeJSON(w, http.StatusOK, map[string]string{"next": authnapp.ConsolePath})
}

// confirm is the org admin's confirm page for one request.
func (p supportPages) confirm(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	const title = "Support access request"
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		p.h.toLogin(w, r)
		return
	}
	id, err := ids.ParseUUID(r.PathValue("id"))
	if err != nil {
		p.notFound(w, title)
		return
	}
	req, grant, err := p.sa.GetRequest(callerContext(r, s), id)
	switch pcerr.CodeOf(err) { //nolint:exhaustive // these read as "not found"; the rest fail
	case "":
		p.h.renderAny(w, http.StatusOK, "support_access.html", supportView{
			page: page{Title: title, Session: s}, Request: req, Grant: grant, Org: s.Org.String(),
			CanDecide: s.Human() && s.Can(td.PermSupportManage, td.OrgPath(s.Org)) && req.State == support.StatePending,
		})
	case pcerr.NotFound, pcerr.PermissionDenied, pcerr.InvalidArgument:
		p.notFound(w, title)
	default:
		p.h.fail(w, r, err)
	}
}

func (p supportPages) decide(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession, approve bool) {
	id, ok := p.h.requestID(w, r)
	if !ok {
		return
	}
	req, _, err := p.sa.Decide(callerContext(r, s), id, approve, stepUpPtr(s)) //nolint:contextcheck // callerContext derives from the request's context
	if err != nil {
		p.jsonFail(w, r, err)
		return
	}
	p.h.writeJSON(w, http.StatusOK, map[string]string{"state": req.State})
}

// logout ends the browser's support session and clears the cookie.
func (p supportPages) logout(w http.ResponseWriter, r *http.Request) {
	if !p.h.csrfOK(r) {
		p.h.jsonError(w, http.StatusForbidden, "csrf")
		return
	}
	if c, err := r.Cookie(p.h.cookieName(sessionCookie)); err == nil && support.IsSessionCookie(c.Value) {
		if err := p.sa.Logout(r.Context(), c.Value); err != nil {
			p.h.log.ErrorContext(r.Context(), "web.support_logout", pclog.Err(err))
			p.h.jsonError(w, http.StatusInternalServerError, "internal")
			return
		}
		p.h.setCookie(w, sessionCookie, "", -1, http.SameSiteStrictMode)
	}
	p.h.writeJSON(w, http.StatusOK, map[string]bool{"signed_out": true})
}
