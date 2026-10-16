// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/jsontext"
	"errors"
	"net/http"
	"strings"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/changes"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// The change request pages (G0 M11 part 2 D6, D53; HR-272, HR-151): GET
// /changes lists the change requests waiting for the viewer's
// confirmation; GET /changes/{id} shows one, its summary as untrusted text,
// and lets an eligible person confirm it with a security key in the
// BINDING ceremony over the request's binding (confirm-options starts it,
// confirm verifies it and records the confirmation) or decline it with a
// reason. Nothing else confirms a change: no RPC, command, API key or
// message. GET never records anything; every POST carries the CSRF proof
// (HR-151).

// Changes is the change-request use-case set (internal/changes).
type Changes interface {
	Pending(ctx context.Context) ([]changes.Request, error)
	Get(ctx context.Context, id ids.UUID) (changes.Request, error)
	BeginConfirm(ctx context.Context, id ids.UUID) (changes.Request, error)
	Confirm(ctx context.Context, id ids.UUID, a changes.Assertion) (changes.Request, error)
	Decline(ctx context.Context, id ids.UUID, reason string) (changes.Request, error)
}

// WithChanges adds the change request pages; call it before Mount.
func (h *Handler) WithChanges(c Changes, b Bindings) *Handler {
	h.changes, h.changeBindings = c, b
	return h
}

func (h *Handler) mountChanges(m *http.ServeMux) {
	if h.changes == nil || h.changeBindings == nil {
		return
	}
	p := changes.Path
	h.withSession(m, http.MethodGet, p, h.changesPage)
	h.withSession(m, http.MethodGet, p+"/{id}", h.changePage)
	h.withSession(m, http.MethodPost, p+"/{id}/confirm-options", h.changeConfirmOptions)
	h.withSession(m, http.MethodPost, p+"/{id}/confirm", h.changeConfirm)
	h.withSession(m, http.MethodPost, p+"/{id}/decline", h.changeDecline)
}

// ChangeSummaryLabel is the fixed label above a change request's summary.
const ChangeSummaryLabel = "What this change does, as PantherClaw summarized it. Names, purposes and texts come from the people who wrote them."

type changesView struct {
	page
	Requests []changes.Request
}

type changeView struct {
	page
	changes.Request
	Digest       string
	Summary      []apdomain.Untrusted
	MixedScript  bool
	SummaryLabel string
	MayConfirm   bool
	MaxReason    int
}

func (h *Handler) changesPage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		h.toLogin(w, r)
		return
	}
	rs, err := h.changes.Pending(callerContext(r, s))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.renderAny(w, http.StatusOK, "changes.html", changesView{page: page{Title: "Changes", Session: s}, Requests: rs})
}

func (h *Handler) changePage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		h.toLogin(w, r)
		return
	}
	id, err := ids.ParseUUID(r.PathValue("id"))
	var c changes.Request
	if err == nil {
		c, err = h.changes.Get(callerContext(r, s), id)
	} else {
		err = changes.ErrNotFound
	}
	switch {
	case pcerr.CodeOf(err) == pcerr.NotFound || pcerr.CodeOf(err) == pcerr.PermissionDenied:
		h.render(w, http.StatusNotFound, "error.html", page{
			Title: "Change", Message: "This change request does not exist, or you cannot see it.",
		})
		return
	case err != nil:
		h.fail(w, r, err)
		return
	}
	var pretty bytes.Buffer
	if v := jsontext.Value(bytes.Clone(c.Summary)); v.Indent(jsontext.WithIndent("  ")) == nil {
		pretty.Write(v)
	} else {
		pretty.Write(c.Summary)
	}
	view := changeView{
		page: page{Title: "Change", Session: s}, Request: c, SummaryLabel: ChangeSummaryLabel,
		Digest:     base64.RawURLEncoding.EncodeToString(c.ContentDigest[:]),
		MayConfirm: changes.MayConfirm(callerOf(s), c), MaxReason: changes.MaxDeclineReason,
	}
	for line := range strings.Lines(pretty.String()) {
		u := apdomain.Clean("summary", line, maxSummaryLine)
		view.Summary = append(view.Summary, u)
		view.MixedScript = view.MixedScript || u.MixedScript
	}
	h.renderAny(w, http.StatusOK, "change.html", view)
}

var changeErrors = []struct {
	err    error
	status int
	code   string
}{
	{changes.ErrNotFound, http.StatusNotFound, "not_found"},
	{changes.ErrBrowserSession, http.StatusForbidden, "human_session"},
	{changes.ErrSamePerson, http.StatusConflict, "same_person"},
	{changes.ErrSameKey, http.StatusConflict, "same_key"},
	{changes.ErrNotEligible, http.StatusForbidden, "not_eligible"},
	{changes.ErrCompromised, http.StatusForbidden, "compromised"},
	{changes.ErrExpired, http.StatusConflict, "expired"},
	{changes.ErrNotPending, http.StatusConflict, "not_pending"},
	{changes.ErrVoided, http.StatusConflict, "voided"},
	{changes.ErrAssertion, http.StatusBadRequest, "ceremony_invalid"},
	{changes.ErrDeclineReason, http.StatusBadRequest, "invalid_reason"},
	{changes.ErrUnknownKind, http.StatusServiceUnavailable, "unavailable"},
	{authnapp.ErrNoCredentials, http.StatusConflict, "no_keys"},
	{authnapp.ErrCeremonyInvalid, http.StatusBadRequest, "ceremony_invalid"},
	{authnapp.ErrWebAuthnFailed, http.StatusBadRequest, "verification_failed"},
	{authnapp.ErrCredentialSuspended, http.StatusForbidden, "key_suspended"},
}

func (h *Handler) changeError(w http.ResponseWriter, r *http.Request, err error) {
	for _, e := range changeErrors {
		if errors.Is(err, e.err) {
			h.jsonError(w, e.status, e.code)
			return
		}
	}
	if pcerr.CodeOf(err) == pcerr.PermissionDenied {
		h.jsonError(w, http.StatusForbidden, "not_permitted")
		return
	}
	if pcerr.CodeOf(err) == pcerr.FailedPrecondition {
		h.jsonError(w, http.StatusConflict, "not_applied")
		return
	}
	h.log.ErrorContext(r.Context(), "web.changes", pclog.Err(err))
	h.jsonError(w, http.StatusInternalServerError, "internal")
}

// changeConfirmOptions starts the BINDING ceremony of a confirmation: its
// challenge is exactly the request's binding, for a person who may confirm
// it now.
func (h *Handler) changeConfirmOptions(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	if _, err := readPolicyChange(r); err != nil {
		h.jsonError(w, http.StatusBadRequest, "bad_request")
		return
	}
	ctx := callerContext(r, s)
	c, err := h.changes.BeginConfirm(ctx, id)
	if err != nil {
		h.changeError(w, r, err)
		return
	}
	cer, err := h.changeBindings.BeginBinding(ctx, s, authnapp.BindingSubject{Change: id}, c.Binding)
	if err != nil {
		h.changeError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"ceremony": cer.ID.String(), "options": jsontext.Value(cer.Options)})
}

// changeConfirm verifies the assertion over the request's binding (HR-153,
// HR-154) and records the confirmation (HR-272). The ceremony is consumed
// with the confirmation, or spent when it is refused or names another
// request.
func (h *Handler) changeConfirm(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	body, err := readPolicyChange(r)
	ceremony, cerr := ids.ParseUUID(body.Ceremony)
	if err != nil || cerr != nil || len(body.Response) == 0 {
		h.jsonError(w, http.StatusBadRequest, "bad_request")
		return
	}
	ctx := callerContext(r, s)
	a, err := h.changeBindings.VerifyBinding(ctx, s, ceremony, body.Response)
	if err != nil {
		h.changeError(w, r, err)
		return
	}
	if a.Subject.Change != id {
		h.changeBindings.SpendBinding(ctx, s, ceremony)
		h.jsonError(w, http.StatusBadRequest, "ceremony_invalid")
		return
	}
	out, err := h.changes.Confirm(ctx, id, changes.Assertion{Ceremony: a.Ceremony, Credential: a.Credential})
	if err != nil {
		h.changeBindings.SpendBinding(ctx, s, ceremony)
		h.changeError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"state": out.State, "confirmations": len(out.Confirmations), "required": out.Required})
}

// changeDecline declines a pending request with a reason.
func (h *Handler) changeDecline(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	body, err := readPolicyChange(r)
	if err != nil {
		h.jsonError(w, http.StatusBadRequest, "bad_request")
		return
	}
	out, err := h.changes.Decline(callerContext(r, s), id, body.Reason)
	if err != nil {
		h.changeError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"state": out.State})
}
