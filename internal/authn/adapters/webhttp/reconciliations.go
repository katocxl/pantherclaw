// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"time"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
	txdomain "github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// The reconciliation page (G0 M7 slice A11, design decision 3, HR-192):
// GET /reconciliations/{id} shows an unknown outcome with the verifier's
// evidence; a person who may release it writes a basis and signs the
// release binding with a security key in M5 part 2's BINDING ceremony
// (release-options starts it, release verifies it and records the
// release). Nothing else releases an unknown outcome: no link, command,
// API key or message. GET never records anything; every POST carries the
// CSRF proof (HR-151).

// Reconciliations is the release use-case set (transactions/app.Releases).
type Reconciliations interface {
	View(ctx context.Context, id ids.UUID) (txapp.ReleaseView, error)
	BeginRelease(ctx context.Context, req txapp.ReleaseRequest) (txapp.ReleaseOffer, error)
	Release(ctx context.Context, req txapp.ReleaseRequest, expiresAt time.Time, a txapp.Assertion) (txapp.Reconciliation, error)
}

// WithReconciliations adds the reconciliation page; call it before Mount.
func (h *Handler) WithReconciliations(r Reconciliations, b Bindings) *Handler {
	h.reconciliations, h.releaseBindings = r, b
	return h
}

func (h *Handler) mountReconciliations(m *http.ServeMux) {
	if h.reconciliations == nil || h.releaseBindings == nil {
		return
	}
	p := authnapp.ReconciliationsPath
	h.withSession(m, http.MethodGet, p+"/{id}", h.reconciliationPage)
	h.withSession(m, http.MethodPost, p+"/{id}/release-options", h.releaseOptions)
	h.withSession(m, http.MethodPost, p+"/{id}/release", h.release)
}

// BasisLabel is the fixed label above a person's basis on the page.
const BasisLabel = "Written by the person who resolved it. PantherClaw has not checked this text."

// reconciliationView is the data of reconciliation.html.
type reconciliationView struct {
	page
	txapp.ReleaseView
	Observations []observationRow
	Effects      []effectRow
	Dispatched   string
	// Basis is the resolution's basis, cleaned for display (untrusted).
	Basis       apdomain.Untrusted
	BasisLabel  string
	RefusalText string
	MaxBasis    int
}

// observationRow is one observation shown as evidence: target data and
// what PantherClaw recorded about the read.
type observationRow struct {
	ID       string
	Observed string
	After    string
	Source   string
	Status   string
	Found    string
	Complete string
	Fields   []fieldRow
}

type fieldRow struct{ Name, Value string }

// effectRow is one effect receipt, with its reason in words.
type effectRow struct {
	Seq           int
	State, Basis  string
	Reason, Words string
	Created       string
}

// reasonWords says what an effect receipt's reason means.
var reasonWords = map[string]string{
	txdomain.ReasonNotInListing:     "no matching object in a complete listing of the target",
	txdomain.ReasonListingCut:       "the target's listing was incomplete",
	txdomain.ReasonNotFoundYet:      "the object was not found within the verifier's window",
	txdomain.ReasonNotFoundAccepted: "the target accepted, then the object was not found",
	txdomain.ReasonReadFailed:       "the read failed (timeout or error); it proves nothing",
	txdomain.ReasonMismatch:         "the object differs from what was asked",
	txdomain.ReasonStatusConfirmed:  "the target shows the effect as done",
	txdomain.ReasonStatusPending:    "the target shows the effect as still pending",
	"NOTHING_CONCLUSIVE":            "no read was conclusive before the verifier's deadline",
	"STILL_PENDING_AT_DEADLINE":     "still pending at the verifier's deadline",
	"RESOLVED_BY_PERSON":            "a person recorded that it happened",
	"RELEASED_BY_PERSON":            "a person confirmed that it did not happen",
}

// refusalWords says why the viewer may not release the outcome now.
var refusalWords = map[string]string{
	txapp.RefusalBrowserSession: "Only a person signed in on this page releases an unknown outcome.",
	txapp.RefusalPermission:     "You cannot release it: that needs transaction.reconcile where the agent lives (the Reconciler or Security Admin role).",
	txapp.RefusalIndependence:   "You cannot release it: the run's launcher, the person it acted for and the agent's owners never release their own run's outcome.",
	txapp.RefusalNotOpen:        "This reconciliation is resolved.",
	txapp.RefusalNotReleasable:  "Only an unknown outcome is released; a conflicting effect's budget stays committed.",
}

const pageTime = "2006-01-02 15:04:05 UTC"

// reconciliationPage shows one reconciliation; anyone who may not see it
// gets "not found" (T-037).
func (h *Handler) reconciliationPage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		h.toLogin(w, r) // a link for another org: sign in there
		return
	}
	id, err := ids.ParseUUID(r.PathValue("id"))
	var v txapp.ReleaseView
	if err == nil {
		v, err = h.reconciliations.View(callerContext(r, s), id)
	} else {
		err = txapp.ErrReconciliationNotFound
	}
	switch {
	case pcerr.CodeOf(err) == pcerr.NotFound || pcerr.CodeOf(err) == pcerr.PermissionDenied:
		h.render(w, http.StatusNotFound, "error.html", page{
			Title: "Reconciliation", Message: "This reconciliation does not exist, or you cannot see it.",
		})
		return
	case err != nil:
		h.fail(w, r, err)
		return
	}
	p := reconciliationView{
		page: page{Title: "Reconciliation", Session: s}, ReleaseView: v, BasisLabel: BasisLabel, MaxBasis: txdomain.MaxBasis,
		RefusalText: refusalWords[v.Refusal],
	}
	var dispatched *time.Time
	if x := v.Evidence.Execution; x != nil && x.Dispatched != nil {
		dispatched = x.Dispatched
		p.Dispatched = x.Dispatched.UTC().Format(pageTime)
	}
	for _, o := range v.Evidence.Observations {
		p.Observations = append(p.Observations, observation(o, dispatched))
	}
	for _, e := range v.Evidence.Effects {
		reason := txapp.EffectReason(e.JWS)
		p.Effects = append(p.Effects, effectRow{
			Seq: e.Seq, State: string(e.State), Basis: e.Basis, Reason: reason, Words: reasonWords[reason],
			Created: e.Created.UTC().Format(pageTime),
		})
	}
	if v.Reconciliation.Basis != "" {
		p.Basis = apdomain.Clean("basis", v.Reconciliation.Basis, txdomain.MaxBasis)
	}
	h.renderAny(w, http.StatusOK, "reconciliation.html", p)
}

// observation is how the page shows one observation.
func observation(o txapp.ObservationRecord, dispatched *time.Time) observationRow {
	row := observationRow{
		ID: o.ID.String(), Observed: o.Observed.UTC().Format(pageTime), Source: o.Source, Found: yesNo(o.Found),
		Complete: yesNo(o.Complete),
	}
	if dispatched != nil && !o.Observed.Before(*dispatched) {
		row.After = o.Observed.Sub(*dispatched).Truncate(time.Second).String() + " after dispatch"
	}
	if o.HTTPStatus > 0 {
		row.Status = strconv.Itoa(o.HTTPStatus)
	}
	if o.Outcome != "" {
		row.Status += " (reported " + o.Outcome + ")"
	}
	for _, k := range slices.Sorted(maps.Keys(o.Fields)) {
		row.Fields = append(row.Fields, fieldRow{Name: k, Value: o.Fields[k]})
	}
	return row
}

func yesNo(b *bool) string {
	switch {
	case b == nil:
		return ""
	case *b:
		return "yes"
	}
	return "no"
}

// releaseRequest is the body of the release actions.
type releaseRequest struct {
	Basis     string         `json:"basis"`
	Evidence  []string       `json:"evidence"`
	Ceremony  string         `json:"ceremony,omitzero"`
	Response  jsontext.Value `json:"response,omitzero"`
	ExpiresAt string         `json:"expires_at,omitzero"`
}

// readRelease decodes a strict JSON body (unknown members, duplicate names
// and invalid UTF-8 are refused) into the use case's request.
func readRelease(r *http.Request, id ids.UUID) (releaseRequest, txapp.ReleaseRequest, error) {
	var body releaseRequest
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return body, txapp.ReleaseRequest{}, err
	}
	if err := json.Unmarshal(b, &body, json.RejectUnknownMembers(true)); err != nil {
		return body, txapp.ReleaseRequest{}, err
	}
	out := txapp.ReleaseRequest{Reconciliation: id, Basis: body.Basis}
	if len(body.Evidence) > txdomain.MaxEvidence {
		return body, out, errors.New("webhttp: too much evidence")
	}
	for _, e := range body.Evidence {
		x, err := ids.ParseUUID(e)
		if err != nil {
			return body, out, err
		}
		out.Evidence = append(out.Evidence, x)
	}
	return body, out, nil
}

// releaseErrors maps the release's errors to the page's error codes.
var releaseErrors = []struct {
	err    error
	status int
	code   string
}{
	{txapp.ErrReconciliationNotFound, http.StatusNotFound, "not_found"},
	{txapp.ErrBrowserSession, http.StatusForbidden, "human_session"},
	{txapp.ErrNotIndependent, http.StatusForbidden, "not_independent"},
	{txapp.ErrNotOpen, http.StatusConflict, "not_open"},
	{txapp.ErrNotReleasable, http.StatusConflict, "not_releasable"},
	{txapp.ErrBasis, http.StatusBadRequest, "invalid_basis"},
	{txapp.ErrEvidence, http.StatusConflict, "evidence_changed"},
	{txapp.ErrReleaseExpired, http.StatusConflict, "expired"},
	{txapp.ErrReleaseAssertion, http.StatusBadRequest, "ceremony_invalid"},
	{authnapp.ErrNoCredentials, http.StatusConflict, "no_keys"},
	{authnapp.ErrCeremonyInvalid, http.StatusBadRequest, "ceremony_invalid"},
	{authnapp.ErrWebAuthnFailed, http.StatusBadRequest, "verification_failed"},
	{authnapp.ErrCredentialSuspended, http.StatusForbidden, "key_suspended"},
}

func (h *Handler) releaseError(w http.ResponseWriter, r *http.Request, err error) {
	for _, e := range releaseErrors {
		if errors.Is(err, e.err) {
			h.jsonError(w, e.status, e.code)
			return
		}
	}
	if pcerr.CodeOf(err) == pcerr.PermissionDenied {
		h.jsonError(w, http.StatusForbidden, "not_permitted")
		return
	}
	h.log.ErrorContext(r.Context(), "web.reconciliations", pclog.Err(err))
	h.jsonError(w, http.StatusInternalServerError, "internal")
}

// visible answers "not found" instead of a refusal to someone who may not
// see the reconciliation (T-037).
func (h *Handler) visible(ctx context.Context, id ids.UUID, err error) error {
	if pcerr.CodeOf(err) != pcerr.PermissionDenied {
		return err
	}
	if _, verr := h.reconciliations.View(ctx, id); verr != nil {
		return txapp.ErrReconciliationNotFound
	}
	return err
}

// releaseCeremony is what the page passes to navigator.credentials, and
// back to release: the release document's expiry and evidence, as signed.
type releaseCeremony struct {
	Ceremony  string         `json:"ceremony"`
	Options   jsontext.Value `json:"options"`
	ExpiresAt string         `json:"expires_at"`
	Evidence  []string       `json:"evidence"`
}

// releaseOptions starts the BINDING ceremony of a release: its challenge
// is exactly the release binding of this basis and the evidence shown, for
// a person who may release it now.
func (h *Handler) releaseOptions(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	_, req, err := readRelease(r, id)
	if err != nil {
		h.jsonError(w, http.StatusBadRequest, "bad_request")
		return
	}
	ctx := callerContext(r, s)
	offer, err := h.reconciliations.BeginRelease(ctx, req)
	if err != nil {
		h.releaseError(w, r, h.visible(ctx, id, err))
		return
	}
	c, err := h.releaseBindings.BeginBinding(ctx, s, authnapp.BindingSubject{Reconciliation: id}, offer.Binding)
	if err != nil {
		h.releaseError(w, r, err)
		return
	}
	out := releaseCeremony{
		Ceremony: c.ID.String(), Options: jsontext.Value(c.Options), ExpiresAt: offer.Release.ExpiresAt.UTC().Format(time.RFC3339),
		Evidence: []string{},
	}
	for _, e := range offer.Release.Evidence {
		out.Evidence = append(out.Evidence, e.String())
	}
	h.writeJSON(w, http.StatusOK, out)
}

// release verifies the assertion over the release binding (HR-153,
// HR-154) and records the release (HR-192). The ceremony is consumed with
// the release, or spent when it is refused or names another
// reconciliation.
func (h *Handler) release(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	body, req, err := readRelease(r, id)
	ceremony, cerr := ids.ParseUUID(body.Ceremony)
	expires, terr := time.Parse(time.RFC3339, body.ExpiresAt)
	if err != nil || cerr != nil || terr != nil || len(body.Response) == 0 {
		h.jsonError(w, http.StatusBadRequest, "bad_request")
		return
	}
	ctx := callerContext(r, s)
	a, err := h.releaseBindings.VerifyBinding(ctx, s, ceremony, body.Response)
	if err != nil {
		h.releaseError(w, r, err)
		return
	}
	if a.Subject.Reconciliation != id {
		h.releaseBindings.SpendBinding(ctx, s, ceremony)
		h.jsonError(w, http.StatusBadRequest, "ceremony_invalid")
		return
	}
	out, err := h.reconciliations.Release(ctx, req, expires, txapp.Assertion{
		Ceremony: a.Ceremony, Credential: a.Credential, AuthenticatorData: a.AuthenticatorData,
		ClientDataJSON: a.ClientDataJSON, Signature: a.Signature,
	})
	if err != nil {
		h.releaseBindings.SpendBinding(ctx, s, ceremony)
		h.releaseError(w, r, h.visible(ctx, id, err))
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"state": string(out.State)})
}
