// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"time"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/protect"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The protected-change step-up pages (G0 M11 part 2 D42, D43, D53;
// HR-292, HR-293). GET /protected-changes/{id}/emergency shows a pending
// protected change by its change request; a person holding
// incident.respond applies it now with a POST on the same path right after
// a security-key step-up on this browser session (F590). GET
// /publishers/compromise shows the form that marks a person compromised; a
// person holding publisher.compromise submits it with a POST on the same
// path after a step-up. Neither has an API equivalent that works without
// the step-up. GET never changes anything; every POST carries the CSRF
// proof (HR-151).

// Protect paths.
const (
	ProtectedChangesPath = "/protected-changes"
	CompromisePath       = "/publishers/compromise"
)

// Protect is the step-up use-case set (protect.Service and
// protect.Publishers).
type Protect interface {
	ProtectedChange(ctx context.Context, request ids.UUID) (dbq.PcProtectedChange, error)
	ApplyEmergency(ctx context.Context, request ids.UUID, su stepup.StepUp) (dbq.PcProtectedChange, error)
	MarkCompromised(ctx context.Context, user ids.UUID, since time.Time, reason string, su stepup.StepUp) (dbq.PcCompromisedPublisher, error)
}

// WithProtect adds the protected-change pages; call it before Mount.
func (h *Handler) WithProtect(p Protect) *Handler {
	h.protect = p
	return h
}

func (h *Handler) mountProtect(m *http.ServeMux) {
	if h.protect == nil {
		return
	}
	h.withSession(m, http.MethodGet, ProtectedChangesPath+"/{id}/emergency", h.emergencyPage)
	h.withSession(m, http.MethodPost, ProtectedChangesPath+"/{id}/emergency", h.applyEmergency)
	h.withSession(m, http.MethodGet, CompromisePath, h.compromisePage)
	h.withSession(m, http.MethodPost, CompromisePath, h.markCompromised)
}

// emergencyView is the data of protected_change.html.
type emergencyView struct {
	page
	dbq.PcProtectedChange
	Request  string
	Summary  map[string]string
	CanApply bool
}

// compromiseView is the data of publisher_compromise.html.
type compromiseView struct {
	page
	CanMark bool
}

// protectErrors maps the use cases' errors to the pages' codes.
var protectErrors = []struct {
	err    error
	status int
	code   string
}{
	{stepup.ErrStepUp, http.StatusForbidden, "step_up_required"},
	{protect.ErrNotFound, http.StatusNotFound, "not_found"},
	{protect.ErrState, http.StatusConflict, "not_pending"},
	{protect.ErrCompromised, http.StatusForbidden, "compromised"},
	{protect.ErrHuman, http.StatusForbidden, "forbidden"},
	{protect.ErrUnavailable, http.StatusServiceUnavailable, "unavailable"},
	{protect.ErrEdition, http.StatusForbidden, "edition"},
	{protect.ErrAlreadyMarked, http.StatusConflict, "already_marked"},
	{protect.ErrCompromiseQ, http.StatusBadRequest, "invalid"},
}

func (h *Handler) protectError(w http.ResponseWriter, r *http.Request, err error) {
	for _, e := range protectErrors {
		if errors.Is(err, e.err) {
			h.jsonError(w, e.status, e.code)
			return
		}
	}
	switch pcerr.CodeOf(err) {
	case pcerr.PermissionDenied:
		h.jsonError(w, http.StatusForbidden, "forbidden")
		return
	case pcerr.NotFound:
		h.jsonError(w, http.StatusNotFound, "not_found")
		return
	case pcerr.FailedPrecondition, pcerr.Aborted:
		h.jsonError(w, http.StatusConflict, "refused")
		return
	}
	h.log.ErrorContext(r.Context(), "web.protect", pclog.Err(err))
	h.jsonError(w, http.StatusInternalServerError, "internal")
}

func (h *Handler) emergencyPage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		h.toLogin(w, r)
		return
	}
	const title = "Protected change"
	id, err := ids.ParseUUID(r.PathValue("id"))
	var c dbq.PcProtectedChange
	if err == nil {
		c, err = h.protect.ProtectedChange(callerContext(r, s), id)
	} else {
		err = protect.ErrNotFound
	}
	switch code := pcerr.CodeOf(err); {
	case err == nil:
	case code == pcerr.NotFound || code == pcerr.PermissionDenied || code == pcerr.InvalidArgument:
		h.render(w, http.StatusNotFound, "error.html", page{
			Title: title, Message: "This protected change does not exist, or you cannot see it.",
		})
		return
	default:
		h.fail(w, r, err)
		return
	}
	var summary map[string]string
	_ = json.Unmarshal(c.Summary, &summary)
	h.renderAny(w, http.StatusOK, "protected_change.html", emergencyView{
		page: page{Title: title, Session: s}, PcProtectedChange: c, Request: id.String(), Summary: summary,
		CanApply: c.State == protect.StatePending && c.ChangeRequestID != nil && *c.ChangeRequestID == id &&
			c.Surface != string(protect.SurfaceSettings) && s.Human() && s.Can(td.PermIncidentRespond, td.OrgPath(s.Org)),
	})
}

func (h *Handler) applyEmergency(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	c, err := h.protect.ApplyEmergency(callerContext(r, s), id, stepUpOfSession(s))
	if err != nil {
		h.protectError(w, r, err)
		return
	}
	out := map[string]string{"state": c.State}
	if c.ReviewRequestID != nil {
		out["review_request_id"] = c.ReviewRequestID.String()
	}
	h.writeJSON(w, http.StatusOK, out)
}

func (h *Handler) compromisePage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		h.toLogin(w, r)
		return
	}
	h.renderAny(w, http.StatusOK, "publisher_compromise.html", compromiseView{
		page:    page{Title: "Mark a publisher compromised", Session: s},
		CanMark: s.Human() && s.Can(td.PermPublisherCompromise, td.OrgPath(s.Org)),
	})
}

// compromiseBody is the compromise form.
type compromiseBody struct {
	User   string `json:"user_id"`
	Since  string `json:"since"`
	Reason string `json:"reason"`
}

func (h *Handler) markCompromised(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		h.jsonError(w, http.StatusBadRequest, "invalid")
		return
	}
	var body compromiseBody
	if err := json.Unmarshal(b, &body, json.RejectUnknownMembers(true)); err != nil {
		h.jsonError(w, http.StatusBadRequest, "invalid")
		return
	}
	user, err := ids.ParseUUID(body.User)
	if err != nil {
		h.jsonError(w, http.StatusBadRequest, "invalid")
		return
	}
	since, err := time.Parse(time.RFC3339, body.Since)
	if err != nil {
		h.jsonError(w, http.StatusBadRequest, "invalid")
		return
	}
	c, err := h.protect.MarkCompromised(callerContext(r, s), user, since, body.Reason, stepUpOfSession(s))
	if err != nil {
		h.protectError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"id": c.ID.String(), "state": c.State})
}
