// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"strings"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// The policy changes pages (G0 M11.1 design decision 11, HR-231, HR-151):
// GET /policy-changes lists the change requests waiting for the viewer's
// confirmation; GET /policy-changes/{id} shows one, its summary as
// untrusted text, and lets a person holding policy.publish confirm it with
// a security key in M5 part 2's BINDING ceremony over the request's
// binding (confirm-options starts it, confirm verifies it and records the
// confirmation) or decline it with a reason. Nothing else confirms a
// change: no link, command, API key or message. GET never records
// anything; every POST carries the CSRF proof (HR-151).

// PolicyChanges is the change-request use-case set (policy/app.Changes).
type PolicyChanges interface {
	Pending(ctx context.Context) ([]policyapp.ChangeRequest, error)
	Get(ctx context.Context, id ids.UUID) (policyapp.ChangeRequest, error)
	BeginConfirm(ctx context.Context, id ids.UUID) (policyapp.ChangeRequest, error)
	Confirm(ctx context.Context, id ids.UUID, a policyapp.Assertion) (policyapp.ChangeRequest, error)
	Decline(ctx context.Context, id ids.UUID, reason string) (policyapp.ChangeRequest, error)
}

// WithPolicyChanges adds the policy changes pages; call it before Mount.
func (h *Handler) WithPolicyChanges(c PolicyChanges, b Bindings) *Handler {
	h.policyChanges, h.policyBindings = c, b
	return h
}

func (h *Handler) mountPolicyChanges(m *http.ServeMux) {
	if h.policyChanges == nil || h.policyBindings == nil {
		return
	}
	p := policyapp.ChangesPath
	h.withSession(m, http.MethodGet, p, h.policyChangesPage)
	h.withSession(m, http.MethodGet, p+"/{id}", h.policyChangePage)
	h.withSession(m, http.MethodPost, p+"/{id}/confirm-options", h.policyConfirmOptions)
	h.withSession(m, http.MethodPost, p+"/{id}/confirm", h.policyConfirm)
	h.withSession(m, http.MethodPost, p+"/{id}/decline", h.policyDecline)
}

// maxSummaryLine caps one shown line of a summary, in runes.
const maxSummaryLine = 4096

// SummaryLabel is the fixed label above a change request's summary.
const SummaryLabel = "What this change does, as PantherClaw classified it. Rule text and ids come from the authors of the policy."

// policyChangesView is the data of policy_changes.html.
type policyChangesView struct {
	page
	Requests []policyapp.ChangeRequest
}

// policyChangeView is the data of policy_change.html.
type policyChangeView struct {
	page
	policyapp.ChangeRequest
	// Summary is the request's summary, indented, one cleaned line each:
	// bidi, control and format characters removed (HR-034); the signed
	// binding is over the stored summary, unchanged.
	Summary []apdomain.Untrusted
	// MixedScript is set when a line mixes writing systems (look-alikes).
	MixedScript  bool
	SummaryLabel string
	MayConfirm   bool
	MaxReason    int
}

func (h *Handler) policyChangesPage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		h.toLogin(w, r)
		return
	}
	rs, err := h.policyChanges.Pending(callerContext(r, s))
	switch {
	case pcerr.CodeOf(err) == pcerr.PermissionDenied:
		h.render(w, http.StatusForbidden, "error.html", page{
			Title: "Policy changes", Message: "You cannot see this organization's policy changes. Ask an administrator for a role that can.",
		})
		return
	case err != nil:
		h.fail(w, r, err)
		return
	}
	h.renderAny(w, http.StatusOK, "policy_changes.html", policyChangesView{
		page: page{Title: "Policy changes", Session: s}, Requests: rs,
	})
}

func (h *Handler) policyChangePage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		h.toLogin(w, r)
		return
	}
	id, err := ids.ParseUUID(r.PathValue("id"))
	var c policyapp.ChangeRequest
	if err == nil {
		c, err = h.policyChanges.Get(callerContext(r, s), id)
	} else {
		err = policyapp.ErrChangeNotFound
	}
	switch {
	case pcerr.CodeOf(err) == pcerr.NotFound || pcerr.CodeOf(err) == pcerr.PermissionDenied:
		h.render(w, http.StatusNotFound, "error.html", page{
			Title: "Policy change", Message: "This policy change does not exist, or you cannot see it.",
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
	view := policyChangeView{
		page: page{Title: "Policy change", Session: s}, ChangeRequest: c, SummaryLabel: SummaryLabel,
		MayConfirm: policyapp.MayConfirm(callerOf(s), c), MaxReason: policyapp.MaxDeclineReason,
	}
	for line := range strings.Lines(pretty.String()) {
		u := apdomain.Clean("summary", line, maxSummaryLine)
		view.Summary = append(view.Summary, u)
		view.MixedScript = view.MixedScript || u.MixedScript
	}
	h.renderAny(w, http.StatusOK, "policy_change.html", view)
}

func callerOf(s authnapp.BrowserSession) tenancy.Caller { return s.Caller }

// policyChangeErrors maps the change requests' errors to the page's codes.
var policyChangeErrors = []struct {
	err    error
	status int
	code   string
}{
	{policyapp.ErrChangeNotFound, http.StatusNotFound, "not_found"},
	{policyapp.ErrBrowserSession, http.StatusForbidden, "human_session"},
	{policyapp.ErrSamePerson, http.StatusConflict, "same_person"},
	{policyapp.ErrSameKey, http.StatusConflict, "same_key"},
	{policyapp.ErrChangeExpired, http.StatusConflict, "expired"},
	{policyapp.ErrChangeNotPending, http.StatusConflict, "not_pending"},
	{policyapp.ErrChangeVoided, http.StatusConflict, "voided"},
	{policyapp.ErrChangeAssertion, http.StatusBadRequest, "ceremony_invalid"},
	{policyapp.ErrDeclineReason, http.StatusBadRequest, "invalid_reason"},
	{policyapp.ErrGateUnavailable, http.StatusServiceUnavailable, "unavailable"},
	{authnapp.ErrNoCredentials, http.StatusConflict, "no_keys"},
	{authnapp.ErrCeremonyInvalid, http.StatusBadRequest, "ceremony_invalid"},
	{authnapp.ErrWebAuthnFailed, http.StatusBadRequest, "verification_failed"},
	{authnapp.ErrCredentialSuspended, http.StatusForbidden, "key_suspended"},
}

func (h *Handler) policyChangeError(w http.ResponseWriter, r *http.Request, err error) {
	for _, e := range policyChangeErrors {
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
	h.log.ErrorContext(r.Context(), "web.policy_changes", pclog.Err(err))
	h.jsonError(w, http.StatusInternalServerError, "internal")
}

// policyChangeBody is the body of the confirm and decline actions.
type policyChangeBody struct {
	Ceremony string         `json:"ceremony,omitzero"`
	Response jsontext.Value `json:"response,omitzero"`
	Reason   string         `json:"reason,omitzero"`
}

func readPolicyChange(r *http.Request) (policyChangeBody, error) {
	var body policyChangeBody
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return body, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return body, nil
	}
	return body, json.Unmarshal(b, &body, json.RejectUnknownMembers(true))
}

// policyConfirmOptions starts the BINDING ceremony of a confirmation: its
// challenge is exactly the request's binding, for a person who may
// confirm it now.
func (h *Handler) policyConfirmOptions(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	if _, err := readPolicyChange(r); err != nil {
		h.jsonError(w, http.StatusBadRequest, "bad_request")
		return
	}
	ctx := callerContext(r, s)
	c, err := h.policyChanges.BeginConfirm(ctx, id)
	if err != nil {
		h.policyChangeError(w, r, err)
		return
	}
	cer, err := h.policyBindings.BeginBinding(ctx, s, authnapp.BindingSubject{PolicyChange: id}, c.Binding)
	if err != nil {
		h.policyChangeError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"ceremony": cer.ID.String(), "options": jsontext.Value(cer.Options)})
}

// policyConfirm verifies the assertion over the request's binding
// (HR-153, HR-154) and records the confirmation (HR-231). The ceremony is
// consumed with the confirmation, or spent when it is refused or names
// another request.
func (h *Handler) policyConfirm(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
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
	a, err := h.policyBindings.VerifyBinding(ctx, s, ceremony, body.Response)
	if err != nil {
		h.policyChangeError(w, r, err)
		return
	}
	if a.Subject.PolicyChange != id {
		h.policyBindings.SpendBinding(ctx, s, ceremony)
		h.jsonError(w, http.StatusBadRequest, "ceremony_invalid")
		return
	}
	out, err := h.policyChanges.Confirm(ctx, id, policyapp.Assertion{Ceremony: a.Ceremony, Credential: a.Credential})
	if err != nil {
		h.policyBindings.SpendBinding(ctx, s, ceremony)
		h.policyChangeError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"state": out.State, "confirmations": len(out.Confirmations), "required": out.Required})
}

// policyDecline declines a pending request with a reason.
func (h *Handler) policyDecline(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	body, err := readPolicyChange(r)
	if err != nil {
		h.jsonError(w, http.StatusBadRequest, "bad_request")
		return
	}
	out, err := h.policyChanges.Decline(callerContext(r, s), id, body.Reason)
	if err != nil {
		h.policyChangeError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"state": out.State})
}
