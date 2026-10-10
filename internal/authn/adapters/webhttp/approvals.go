// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	apapp "github.com/katocxl/pantherclaw/internal/approvals/app"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Approvals is the approval use-case set (approvals/app.Service). The
// approval page is the only place a person approves or steps up (G0 M5
// part 2, decision 1); GET never records anything (HR-151).
type Approvals interface {
	Inbox(ctx context.Context) (apapp.Inbox, error)
	View(ctx context.Context, id ids.UUID) (apapp.View, error)
	BeginApproval(ctx context.Context, org ids.OrgID, r apapp.Responder, id ids.UUID) ([32]byte, error)
	Approve(ctx context.Context, org ids.OrgID, r apapp.Responder, id ids.UUID, a apapp.Assertion) (apapp.Request, error)
	Decline(ctx context.Context, id ids.UUID, reason, alternative, note string) (apapp.Request, error)
	RequestEvidence(ctx context.Context, id ids.UUID, question, note string, deadline time.Time) (apapp.Request, error)
	ProposeNarrower(ctx context.Context, id ids.UUID, params []byte, note string, validateOnly bool) (apapp.Proposal, error)
	BeginBatch(ctx context.Context, org ids.OrgID, r apapp.Responder, requests []ids.UUID) (ids.UUID, [32]byte, error)
	ApproveBatch(ctx context.Context, org ids.OrgID, r apapp.Responder, batch ids.UUID, a apapp.Assertion) ([]apapp.Request, error)
}

// Bindings is the BINDING ceremony (authn/app.WebAuthn): a security-key
// assertion whose challenge is the request's binding (HR-033).
type Bindings interface {
	BeginBinding(ctx context.Context, s authnapp.BrowserSession, subject authnapp.BindingSubject, challenge [32]byte) (authnapp.Ceremony, error)
	VerifyBinding(ctx context.Context, s authnapp.BrowserSession, ceremony ids.UUID, response []byte) (authnapp.BindingAssertion, error)
	SpendBinding(ctx context.Context, s authnapp.BrowserSession, ceremony ids.UUID)
}

// WithApprovals adds the approval page; call it before Mount.
func (h *Handler) WithApprovals(a Approvals, b Bindings) *Handler {
	h.approvals, h.bindings = a, b
	return h
}

func (h *Handler) mountApprovals(m *http.ServeMux) {
	if h.approvals == nil || h.bindings == nil {
		return
	}
	p := authnapp.ApprovalsPath
	h.withSession(m, http.MethodGet, p, h.approvalsPage)
	h.withSession(m, http.MethodPost, p+"/batch-options", h.batchOptions)
	h.withSession(m, http.MethodPost, p+"/batch", h.approveBatch)
	h.withSession(m, http.MethodGet, p+"/{id}", h.approvalPage)
	h.withSession(m, http.MethodPost, p+"/{id}/approve-options", h.approveOptions)
	h.withSession(m, http.MethodPost, p+"/{id}/approve", h.approve)
	h.withSession(m, http.MethodPost, p+"/{id}/decline", h.decline)
	h.withSession(m, http.MethodPost, p+"/{id}/evidence-request", h.requestEvidence)
	h.withSession(m, http.MethodPost, p+"/{id}/narrower", h.proposeNarrower)
}

// inboxPage is the data of approvals.html.
type inboxPage struct {
	page
	Inbox apapp.Inbox
	Scan  int
}

// approvalView is the data of approval.html: the stored display (HR-034)
// with each fact's age at the database clock.
type approvalView struct {
	page
	apapp.View
	Facts []factRow
	// The fixed codes of the page's actions (HR-172).
	Reasons, Alternatives, Questions []string
}

type factRow struct {
	apdomain.FactLine
	Age string
}

// approvalsPage lists the requests waiting for the person (F626).
func (h *Handler) approvalsPage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		h.toLogin(w, r) // a link for another org: sign in there
		return
	}
	in, err := h.approvals.Inbox(callerContext(r, s))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.renderAny(w, http.StatusOK, "approvals.html", inboxPage{page: page{Title: "Approvals", Session: s}, Inbox: in, Scan: apapp.InboxScan})
}

// approvalPage shows one request; anyone who may not see it gets "not
// found" (T-037).
func (h *Handler) approvalPage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		h.toLogin(w, r)
		return
	}
	id, err := ids.ParseUUID(r.PathValue("id"))
	var v apapp.View
	if err == nil {
		v, err = h.approvals.View(callerContext(r, s), id)
	} else {
		err = apapp.ErrNotFound
	}
	switch {
	case errors.Is(err, apapp.ErrNotFound):
		h.render(w, http.StatusNotFound, "error.html", page{
			Title: "Approval", Message: "This approval request does not exist, or you cannot see it.",
		})
		return
	case err != nil:
		h.fail(w, r, err)
		return
	}
	p := approvalView{
		page: page{Title: "Approval", Session: s}, View: v,
		Reasons: apdomain.DeclineReasons, Alternatives: apdomain.Alternatives, Questions: apdomain.Questions,
	}
	for _, f := range v.Display.Facts {
		p.Facts = append(p.Facts, factRow{FactLine: f, Age: age(f.ObservedAt, v.Now)})
	}
	h.renderAny(w, http.StatusOK, "approval.html", p)
}

// age is how long before now a fact was observed, in words.
func age(observed string, now time.Time) string {
	t, err := time.Parse(time.RFC3339Nano, observed)
	if err != nil {
		return "unknown"
	}
	d := now.Sub(t).Truncate(time.Second)
	switch {
	case d < 0:
		return "just now"
	case d < time.Minute:
		return strconv.Itoa(int(d/time.Second)) + "s"
	case d < time.Hour:
		return strconv.Itoa(int(d/time.Minute)) + "m"
	case d < 48*time.Hour:
		return strconv.Itoa(int(d/time.Hour)) + "h " + strconv.Itoa(int(d%time.Hour/time.Minute)) + "m"
	}
	return strconv.Itoa(int(d/(24*time.Hour))) + "d"
}

// renderAny renders a page whose data is not the plain page.
func (h *Handler) renderAny(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pages.ExecuteTemplate(w, name, data); err != nil {
		h.log.Error("web.render", slog.String("template", name), pclog.Err(err))
	}
}
