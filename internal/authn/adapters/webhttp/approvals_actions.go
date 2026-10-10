// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"slices"
	"time"

	apapp "github.com/katocxl/pantherclaw/internal/approvals/app"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// The approval page's actions (G0 M5 part 2 slice 209). Approving is a
// BINDING ceremony; declining, asking for evidence and proposing a
// narrower action need only the signed-in person (decision 1, HR-172).
// Every action is a POST with the CSRF proof (HR-151).

// maxEvidenceMinutes bounds an evidence deadline (the request's own
// deadline bounds it further).
const maxEvidenceMinutes = 7 * 24 * 60

// approvalRequest is the body of the actions; each route reads its fields.
type approvalRequest struct {
	Ceremony     string         `json:"ceremony,omitzero"`
	Response     jsontext.Value `json:"response,omitzero"`
	Reason       string         `json:"reason,omitzero"`
	Alternative  string         `json:"alternative,omitzero"`
	Question     string         `json:"question,omitzero"`
	Note         string         `json:"note,omitzero"`
	Minutes      int            `json:"minutes,omitzero"`
	Params       jsontext.Value `json:"params,omitzero"`
	ValidateOnly bool           `json:"validate_only,omitzero"`
	IDs          []string       `json:"ids,omitzero"`
	Batch        string         `json:"batch,omitzero"`
}

// readApprovalRequest decodes a strict JSON body (unknown members,
// duplicate names and invalid UTF-8 are refused).
func readApprovalRequest(r *http.Request) (approvalRequest, error) {
	var a approvalRequest
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return a, err
	}
	err = json.Unmarshal(b, &a, json.RejectUnknownMembers(true))
	return a, err
}

// approvalErrors maps use-case errors to the page's error codes.
var approvalErrors = []struct {
	err    error
	status int
	code   string
}{
	{apapp.ErrNotFound, http.StatusNotFound, "not_found"},
	{apapp.ErrHumanSession, http.StatusForbidden, "human_session"},
	{apapp.ErrNotEligible, http.StatusForbidden, "not_eligible"},
	{apapp.ErrNotWaiting, http.StatusConflict, "not_waiting"},
	{apapp.ErrInvalidCode, http.StatusBadRequest, "invalid"},
	{apapp.ErrEvidenceDeadline, http.StatusBadRequest, "evidence_deadline"},
	{apapp.ErrTooMuchEvidence, http.StatusConflict, "evidence_limit"},
	{apapp.ErrNoProposals, http.StatusConflict, "proposal_unavailable"},
	{apdomain.ErrNotNarrower, http.StatusBadRequest, "not_narrower"},
	{apapp.ErrCeremony, http.StatusBadRequest, "ceremony_invalid"},
	{authnapp.ErrNoCredentials, http.StatusConflict, "no_keys"},
	{authnapp.ErrCeremonyInvalid, http.StatusBadRequest, "ceremony_invalid"},
	{authnapp.ErrWebAuthnFailed, http.StatusBadRequest, "verification_failed"},
	{authnapp.ErrCredentialSuspended, http.StatusForbidden, "key_suspended"},
	{apapp.ErrEditionRequired, http.StatusForbidden, "edition_required"},
	{apapp.ErrBatchInvalid, http.StatusBadRequest, "batch_invalid"},
}

func (h *Handler) approvalError(w http.ResponseWriter, r *http.Request, err error) {
	for _, e := range approvalErrors {
		if errors.Is(err, e.err) {
			h.jsonError(w, e.status, e.code)
			return
		}
	}
	h.log.ErrorContext(r.Context(), "web.approvals", pclog.Err(err))
	h.jsonError(w, http.StatusInternalServerError, "internal")
}

// requestID reads the request id of the path; a malformed one is "not
// found".
func (h *Handler) requestID(w http.ResponseWriter, r *http.Request) (ids.UUID, bool) {
	id, err := ids.ParseUUID(r.PathValue("id"))
	if err != nil {
		h.jsonError(w, http.StatusNotFound, "not_found")
		return id, false
	}
	return id, true
}

// responder is the person of a browser session (decision 1).
func responder(s authnapp.BrowserSession) apapp.Responder {
	return apapp.Responder{User: s.User(), Browser: s.ID}
}

// hidden answers "not found" instead of a refusal to someone who may not
// see the request (T-037).
func (h *Handler) hidden(ctx context.Context, id ids.UUID, err error) error {
	if !errors.Is(err, apapp.ErrNotEligible) && !errors.Is(err, apapp.ErrNotWaiting) {
		return err
	}
	if _, verr := h.approvals.View(ctx, id); verr != nil {
		return verr
	}
	return err
}

// approveOptions starts the BINDING ceremony (HR-033, design decision 12):
// its challenge is exactly the request's binding, for a person who may
// approve now.
func (h *Handler) approveOptions(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	ctx := callerContext(r, s)
	binding, err := h.approvals.BeginApproval(ctx, s.Org, responder(s), id)
	if err != nil {
		h.approvalError(w, r, h.hidden(ctx, id, err))
		return
	}
	c, err := h.bindings.BeginBinding(ctx, s, authnapp.BindingSubject{Request: id}, binding)
	if err != nil {
		h.approvalError(w, r, err)
		return
	}
	h.writeCeremony(w, c)
}

// approve verifies the assertion over the binding (HR-033, HR-153, HR-154)
// and records the approval or step-up (decision 1). The ceremony is
// consumed with the response, or spent when the use case refuses it.
func (h *Handler) approve(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	req, err := readApprovalRequest(r)
	ceremony, perr := ids.ParseUUID(req.Ceremony)
	if err != nil || perr != nil || len(req.Response) == 0 {
		h.jsonError(w, http.StatusBadRequest, "bad_request")
		return
	}
	a, err := h.bindings.VerifyBinding(r.Context(), s, ceremony, req.Response)
	if err != nil {
		h.approvalError(w, r, err)
		return
	}
	if a.Subject.Request != id {
		h.bindings.SpendBinding(r.Context(), s, ceremony)
		h.jsonError(w, http.StatusBadRequest, "ceremony_invalid")
		return
	}
	out, err := h.approvals.Approve(r.Context(), s.Org, responder(s), id, apapp.Assertion{
		Ceremony: a.Ceremony, Credential: a.Credential, AuthenticatorData: a.AuthenticatorData,
		ClientDataJSON: a.ClientDataJSON, Signature: a.Signature,
	})
	if err != nil {
		h.bindings.SpendBinding(r.Context(), s, ceremony)
		h.approvalError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"state": out.State})
}

// respond answers an action that returns the request.
func (h *Handler) respond(w http.ResponseWriter, r *http.Request, out apapp.Request, err error) {
	if err != nil {
		h.approvalError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"state": out.State})
}

func (h *Handler) decline(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	req, err := readApprovalRequest(r)
	if err != nil {
		h.jsonError(w, http.StatusBadRequest, "bad_request")
		return
	}
	out, err := h.approvals.Decline(callerContext(r, s), id, req.Reason, req.Alternative, req.Note)
	h.respond(w, r, out, err)
}

func (h *Handler) requestEvidence(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	req, err := readApprovalRequest(r)
	if err != nil || req.Minutes < 1 || req.Minutes > maxEvidenceMinutes {
		h.jsonError(w, http.StatusBadRequest, "bad_request")
		return
	}
	deadline := time.Now().Add(time.Duration(req.Minutes) * time.Minute)
	out, err := h.approvals.RequestEvidence(callerContext(r, s), id, req.Question, req.Note, deadline)
	h.respond(w, r, out, err)
}

// narrowerJSON is a narrower proposal's answer: the canonical parameters
// and the decision the agent would get for them.
type narrowerJSON struct {
	State    string         `json:"state"`
	Decision string         `json:"decision"`
	Params   jsontext.Value `json:"params"`
	Reasons  []string       `json:"reasons"`
}

func (h *Handler) proposeNarrower(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	req, err := readApprovalRequest(r)
	if err != nil || len(req.Params) == 0 {
		h.jsonError(w, http.StatusBadRequest, "bad_request")
		return
	}
	p, err := h.approvals.ProposeNarrower(callerContext(r, s), id, req.Params, req.Note, req.ValidateOnly)
	if err != nil {
		h.approvalError(w, r, err)
		return
	}
	out := narrowerJSON{State: p.Request.State, Decision: p.Simulation.Decision, Params: p.Simulation.Params, Reasons: []string{}}
	for _, x := range p.Simulation.Reasons {
		out.Reasons = append(out.Reasons, x.Code)
	}
	h.writeJSON(w, http.StatusOK, out)
}

// batchOptions starts the BINDING ceremony of a batch approval (HR-175,
// Team edition): its challenge is the hash of exactly the batch's bindings.
func (h *Handler) batchOptions(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	req, err := readApprovalRequest(r)
	if err != nil || len(req.IDs) == 0 {
		h.jsonError(w, http.StatusBadRequest, "bad_request")
		return
	}
	var list []ids.UUID
	for _, x := range req.IDs {
		id, err := ids.ParseUUID(x)
		if err != nil {
			h.jsonError(w, http.StatusBadRequest, "bad_request")
			return
		}
		list = append(list, id)
	}
	ctx := callerContext(r, s)
	batch, hash, err := h.approvals.BeginBatch(ctx, s.Org, responder(s), list)
	if err != nil {
		h.batchError(w, r, err)
		return
	}
	c, err := h.bindings.BeginBinding(ctx, s, authnapp.BindingSubject{Batch: batch}, hash)
	if err != nil {
		h.approvalError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, batchCeremony{Batch: batch.String(), Ceremony: c.ID.String(), Options: jsontext.Value(c.Options)})
}

// batchCeremony is what the page passes to navigator.credentials for a
// batch.
type batchCeremony struct {
	Batch    string         `json:"batch"`
	Ceremony string         `json:"ceremony"`
	Options  jsontext.Value `json:"options"`
}

// batchError answers a refused batch, with the code of a request that must
// be reviewed alone.
func (h *Handler) batchError(w http.ResponseWriter, r *http.Request, err error) {
	var pe *pcerr.Error
	if errors.As(err, &pe) && slices.Contains([]string{
		apdomain.BatchNotAHold, apdomain.BatchNotReversible, apdomain.BatchNotSingleApprover, apdomain.BatchNoValue, apdomain.BatchOverCeiling,
	}, pe.Reason()) {
		h.writeJSON(w, http.StatusConflict, map[string]string{"error": "not_batchable", "reason": pe.Reason()})
		return
	}
	h.approvalError(w, r, err)
}

// approveBatch verifies the batch's assertion and records an approval of
// each request (HR-175); the ceremony is spent when the use case refuses.
func (h *Handler) approveBatch(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	req, err := readApprovalRequest(r)
	batch, berr := ids.ParseUUID(req.Batch)
	ceremony, cerr := ids.ParseUUID(req.Ceremony)
	if err != nil || berr != nil || cerr != nil || len(req.Response) == 0 {
		h.jsonError(w, http.StatusBadRequest, "bad_request")
		return
	}
	a, err := h.bindings.VerifyBinding(r.Context(), s, ceremony, req.Response)
	if err != nil {
		h.approvalError(w, r, err)
		return
	}
	if a.Subject.Batch != batch {
		h.bindings.SpendBinding(r.Context(), s, ceremony)
		h.jsonError(w, http.StatusBadRequest, "ceremony_invalid")
		return
	}
	rows, err := h.approvals.ApproveBatch(r.Context(), s.Org, responder(s), batch, apapp.Assertion{
		Ceremony: a.Ceremony, Credential: a.Credential, AuthenticatorData: a.AuthenticatorData,
		ClientDataJSON: a.ClientDataJSON, Signature: a.Signature,
	})
	if err != nil {
		h.bindings.SpendBinding(r.Context(), s, ceremony)
		h.batchError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]int{"approved": len(rows)})
}
