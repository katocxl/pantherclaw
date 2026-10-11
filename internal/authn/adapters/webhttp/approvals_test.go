// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	apapp "github.com/katocxl/pantherclaw/internal/approvals/app"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// knownRequest is the one request fakeApprovals shows; knownBinding is its
// binding.
var (
	knownRequest = ids.NewV7()
	knownBinding = [32]byte{1, 2, 3}
	knownBatch   = ids.NewV7()
	batchHash    = [32]byte{4, 5, 6}
)

// fakeApprovals shows knownRequest, with agent text and evidence that try
// to inject markup, and an inbox holding it (or nothing, when empty). Its
// actions record what the page passed and fail with err when it is set.
type fakeApprovals struct {
	empty, readOnly bool
	err             error

	mu         sync.Mutex
	responders []apapp.Responder
	calls      []string
	deadline   time.Time
	params     string
	validate   bool
	assertion  apapp.Assertion
	batch      []ids.UUID
	batchErr   error
}

// record notes an action of the calling person and returns err.
func (f *fakeApprovals) record(ctx context.Context, call string) error {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return err
	}
	r, err := apapp.ResponderFrom(c)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responders, f.calls = append(f.responders, r), append(f.calls, call)
	return f.err
}

func (f *fakeApprovals) BeginApproval(_ context.Context, _ ids.OrgID, r apapp.Responder, id ids.UUID) ([32]byte, error) {
	if id != knownRequest {
		return [32]byte{}, apapp.ErrNotEligible
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responders = append(f.responders, r)
	return knownBinding, f.err
}

func (f *fakeApprovals) Approve(_ context.Context, _ ids.OrgID, r apapp.Responder, _ ids.UUID, a apapp.Assertion) (apapp.Request, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responders, f.assertion = append(f.responders, r), a
	return apapp.Request{State: "APPROVED"}, f.err
}

func (f *fakeApprovals) Decline(ctx context.Context, _ ids.UUID, reason, alternative, note string) (apapp.Request, error) {
	return apapp.Request{State: "DECLINED"}, f.record(ctx, "decline:"+reason+":"+alternative+":"+note)
}

func (f *fakeApprovals) RequestEvidence(ctx context.Context, _ ids.UUID, question, note string, deadline time.Time) (apapp.Request, error) {
	f.mu.Lock()
	f.deadline = deadline
	f.mu.Unlock()
	return apapp.Request{State: "EVIDENCE_REQUESTED"}, f.record(ctx, "evidence:"+question+":"+note)
}

func (f *fakeApprovals) ProposeNarrower(ctx context.Context, _ ids.UUID, params []byte, _ string, validateOnly bool) (apapp.Proposal, error) {
	f.mu.Lock()
	f.params, f.validate = string(params), validateOnly
	f.mu.Unlock()
	return apapp.Proposal{
		Request:    apapp.Request{State: "PENDING"},
		Simulation: apapp.Simulation{Params: params, Decision: "ALLOW", Reasons: []apapp.Reason{{Code: "WITHIN_LIMITS"}}},
	}, f.record(ctx, "narrower")
}

func (f *fakeApprovals) BeginBatch(_ context.Context, _ ids.OrgID, r apapp.Responder, requests []ids.UUID) (ids.UUID, [32]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responders, f.batch = append(f.responders, r), requests
	return knownBatch, batchHash, f.batchErr
}

func (f *fakeApprovals) ApproveBatch(_ context.Context, _ ids.OrgID, r apapp.Responder, _ ids.UUID, a apapp.Assertion) ([]apapp.Request, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responders, f.assertion = append(f.responders, r), a
	return make([]apapp.Request, len(f.batch)), f.batchErr
}

// fakeBindings is the BINDING ceremony: it records the challenge and the
// subject, and verifies any response as an assertion over names (or the
// batch, or the reconciliation).
type fakeBindings struct {
	mu             sync.Mutex
	challenge      [32]byte
	subject        authnapp.BindingSubject
	names          ids.UUID
	batch          ids.UUID
	reconciliation ids.UUID
	verifyErr      error
	spent          []ids.UUID
}

func (b *fakeBindings) BeginBinding(_ context.Context, _ authnapp.BrowserSession, subject authnapp.BindingSubject, challenge [32]byte) (authnapp.Ceremony, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.challenge, b.subject = challenge, subject
	return authnapp.Ceremony{ID: ids.NewV7(), Options: []byte(`{"publicKey":{"challenge":"AQID"}}`)}, nil
}

func (b *fakeBindings) VerifyBinding(_ context.Context, _ authnapp.BrowserSession, ceremony ids.UUID, _ []byte) (authnapp.BindingAssertion, error) {
	if b.verifyErr != nil {
		return authnapp.BindingAssertion{}, b.verifyErr
	}
	return authnapp.BindingAssertion{
		Ceremony: ceremony, Subject: authnapp.BindingSubject{Request: b.names, Batch: b.batch, Reconciliation: b.reconciliation},
		Challenge: knownBinding, Credential: responderKey,
		AuthenticatorData: make([]byte, 37), ClientDataJSON: []byte(`{}`), Signature: []byte{1},
	}, nil
}

func (b *fakeBindings) SpendBinding(_ context.Context, _ authnapp.BrowserSession, ceremony ids.UUID) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.spent = append(b.spent, ceremony)
}

func (f *fakeApprovals) Inbox(ctx context.Context) (apapp.Inbox, error) {
	if _, err := tapp.CallerFrom(ctx); err != nil {
		return apapp.Inbox{}, err
	}
	in := apapp.Inbox{Scopes: []td.Binding{{Role: td.RoleApprover, Scope: td.Scope{Type: td.ScopeOrg, ID: testOrg.UUID()}}}}
	if !f.empty {
		in.Waiting = []apapp.Summary{{
			ID: knownRequest, Title: `Refund <b>40.00 USD</b>`, Operation: "payments.refund.create", State: "PENDING", Priority: 2,
		}}
	}
	return in, nil
}

func (f *fakeApprovals) View(ctx context.Context, id ids.UUID) (apapp.View, error) {
	if _, err := tapp.CallerFrom(ctx); err != nil {
		return apapp.View{}, err
	}
	if id != knownRequest {
		return apapp.View{}, apapp.ErrNotFound
	}
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	may := !f.readOnly
	return apapp.View{
		MayRespond: may, MayApprove: may, Params: apdomain.Untrusted{Text: `{"amount":{"value":"40.00","currency":"USD"}}`},
		Request: apapp.Request{ID: id, SubjectKind: "ACTION", DeadlineAt: now.Add(time.Hour)},
		Display: apdomain.Display{
			V: 1, Kind: "ACTION", Title: "Refund 40.00 USD",
			Consequence: apdomain.Consequence{
				Operation: "payments.refund.create", Target: actionir.Target{Type: "charge", ID: "ch_123"}, Reversibility: "irreversible",
			},
			Fields: []apdomain.Field{{Name: "amount", Value: "40.00 USD"}},
			Facts: []apdomain.FactLine{{
				Name: "charge.amount", Subject: "ch_123", Value: "40.00 USD", Provider: "stripe",
				ObservedAt: now.Add(-90 * time.Second).Format(time.RFC3339),
			}},
			Deciders: []apdomain.DeciderRule{{Kind: "approval", Role: "approver", Count: 1}},
			Untrusted: apdomain.UntrustedBlock{Label: apdomain.UntrustedLabel, Items: []apdomain.Untrusted{
				{Source: "task_label", Text: `<script>alert(1)</script>`},
				{Source: "param:memo", Text: "p" + string(rune(0x0430)) + "ypal", MixedScript: true},
			}},
		},
		State: "PENDING", Now: now,
		Evidence: []apapp.EvidenceLine{{Author: "instance:x", Note: apdomain.Untrusted{Source: "evidence", Text: `"><img src=x onerror=alert(1)>`}, At: now}},
	}, nil
}

func newApprovalsHandler(t *testing.T, fa *fakeApprovals) http.Handler {
	t.Helper()
	mux, _ := newApprovalsHandlerWith(t, fa)
	return mux
}

func newApprovalsHandlerWith(t *testing.T, fa *fakeApprovals) (http.Handler, *fakeBindings) {
	t.Helper()
	h, err := webhttp.New(&fakeBrowser{}, origin, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	fb := &fakeBindings{names: knownRequest}
	h.WithApprovals(fa, fb)
	mux := http.NewServeMux()
	h.Mount(mux)
	return mux, fb
}

func getAs(t *testing.T, mux http.Handler, path, cookie string) result {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, origin+path, nil)
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: cookie})
	}
	return do(t, mux, r)
}

// TestHR034_TheApprovalPageShowsTheStoredDisplayAndMarksUntrustedText: the
// page shows the consequence, fields and facts (with their age) of the
// stored display, puts agent text under the fixed label, escapes it, flags
// mixed scripts, and carries the page policy.
func TestHR034_TheApprovalPageShowsTheStoredDisplayAndMarksUntrustedText(t *testing.T) {
	mux := newApprovalsHandler(t, &fakeApprovals{})
	resp := getAs(t, mux, authnapp.ApprovalsPath+"/"+knownRequest.String(), "good")
	body := resp.Body
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Security-Policy") != webhttp.PageCSP ||
		resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v", resp.StatusCode, resp.Header)
	}
	for _, want := range []string{
		"Refund 40.00 USD", "payments.refund.create", "ch_123", "irreversible", "40.00 USD", "stripe", "<td>1m</td>",
		apdomain.UntrustedLabel, "&lt;script&gt;alert(1)&lt;/script&gt;", "mixes writing systems", "You can approve",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if strings.Contains(body, "<script>alert") || strings.Contains(body, "<img src=x") {
		t.Fatal("untrusted text is not escaped")
	}
	if i, j := strings.Index(body, "What will happen"), strings.Index(body, apdomain.UntrustedLabel); i < 0 || j < i {
		t.Fatal("the consequence must come first, before the untrusted block")
	}
}

// TestT037_AnUnknownOrHiddenRequestIsNotFound: an id the person may not see,
// an unknown id and a malformed id all get the same "not found".
func TestT037_AnUnknownOrHiddenRequestIsNotFound(t *testing.T) {
	mux := newApprovalsHandler(t, &fakeApprovals{})
	for _, path := range []string{authnapp.ApprovalsPath + "/" + ids.NewV7().String(), authnapp.ApprovalsPath + "/not-an-id"} {
		resp := getAs(t, mux, path, "good")
		if resp.StatusCode != http.StatusNotFound || !strings.Contains(resp.Body, "does not exist, or you cannot see it") {
			t.Errorf("%s: %d", path, resp.StatusCode)
		}
	}
}

// TestF626_TheListSaysWhatWasChecked: the list links the waiting requests
// and, empty or not, names the scopes it checked.
func TestF626_TheListSaysWhatWasChecked(t *testing.T) {
	resp := getAs(t, newApprovalsHandler(t, &fakeApprovals{}), authnapp.ApprovalsPath, "good")
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, `href="/approvals/`+knownRequest.String()+`"`) ||
		!strings.Contains(resp.Body, "Refund &lt;b&gt;40.00 USD&lt;/b&gt;") || !strings.Contains(resp.Body, "What was checked") {
		t.Fatalf("list: %d %s", resp.StatusCode, resp.Body)
	}
	resp = getAs(t, newApprovalsHandler(t, &fakeApprovals{empty: true}), authnapp.ApprovalsPath, "good")
	if !strings.Contains(resp.Body, "Nothing is waiting for your decision") || !strings.Contains(resp.Body, "<code>approver</code> at ORG") {
		t.Fatalf("empty list: %s", resp.Body)
	}
}

// TestHR152_SignInReturnsToTheApprovalPage: without a session, a link that
// names the org goes to sign-in with the page as next.
func TestHR152_SignInReturnsToTheApprovalPage(t *testing.T) {
	mux := newApprovalsHandler(t, &fakeApprovals{})
	path := authnapp.ApprovalsPath + "/" + knownRequest.String()
	resp := getAs(t, mux, path+"?org="+testOrg.String(), "")
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(loc, "next=%2Fapprovals%2F"+knownRequest.String()) {
		t.Fatalf("%d %s", resp.StatusCode, loc)
	}
	if !authnapp.ValidReturnPath(path) {
		t.Fatal("the approval page must be a valid return path")
	}
}

// TestHR033_ApprovingSignsTheBindingOnThePage: approve-options starts a
// ceremony over exactly the request's binding for the browser session's
// person; approve hands the verified assertion to the use case; a refused
// approval or an assertion over another request spends the ceremony.
func TestHR033_ApprovingSignsTheBindingOnThePage(t *testing.T) {
	fa := &fakeApprovals{}
	mux, fb := newApprovalsHandlerWith(t, fa)
	base := authnapp.ApprovalsPath + "/" + knownRequest.String()
	resp := do(t, mux, postAs(base+"/approve-options", "responder", "{}"))
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, `"ceremony":`) || fb.challenge != knownBinding ||
		fb.subject != (authnapp.BindingSubject{Request: knownRequest}) {
		t.Fatalf("approve-options: %d %s", resp.StatusCode, resp.Body)
	}
	if r := fa.responders[0]; r.User != responderID || r.Browser.IsZero() || !r.CLI.IsZero() {
		t.Fatalf("responder %+v", r)
	}
	ceremony := ids.NewV7()
	body := `{"ceremony":"` + ceremony.String() + `","response":{"id":"x"}}`
	resp = do(t, mux, postAs(base+"/approve", "responder", body))
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, `"state":"APPROVED"`) || fa.assertion.Ceremony != ceremony ||
		fa.assertion.Credential != responderKey || len(fa.assertion.AuthenticatorData) != 37 || len(fb.spent) != 0 {
		t.Fatalf("approve: %d %s %+v", resp.StatusCode, resp.Body, fa.assertion)
	}
	fa.err = apapp.ErrNotEligible
	if resp = do(t, mux, postAs(base+"/approve", "responder", body)); resp.StatusCode != http.StatusForbidden ||
		!strings.Contains(resp.Body, "not_eligible") || len(fb.spent) != 1 {
		t.Fatalf("a refused approval: %d %s %d", resp.StatusCode, resp.Body, len(fb.spent))
	}
	fa.err, fb.names = nil, ids.NewV7()
	if resp = do(t, mux, postAs(base+"/approve", "responder", body)); resp.StatusCode != http.StatusBadRequest ||
		!strings.Contains(resp.Body, "ceremony_invalid") || len(fb.spent) != 2 {
		t.Fatalf("an assertion over another request: %d %s", resp.StatusCode, resp.Body)
	}
	fb.verifyErr = authnapp.ErrWebAuthnFailed
	calls := len(fa.responders)
	if resp = do(t, mux, postAs(base+"/approve", "responder", body)); resp.StatusCode != http.StatusBadRequest ||
		!strings.Contains(resp.Body, "verification_failed") || len(fa.responders) != calls {
		t.Fatalf("an assertion that does not verify: %d %s", resp.StatusCode, resp.Body)
	}
	if resp = do(t, mux, postAs(base+"/approve", "responder", `{"ceremony":"x"}`)); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("no response: %d", resp.StatusCode)
	}
}

// TestT037_AStrangerCannotStartTheCeremony: approve-options for a request
// the person may not see answers "not found"; one they may see but not
// decide answers "not eligible".
func TestT037_AStrangerCannotStartTheCeremony(t *testing.T) {
	mux, fb := newApprovalsHandlerWith(t, &fakeApprovals{})
	resp := do(t, mux, postAs(authnapp.ApprovalsPath+"/"+ids.NewV7().String()+"/approve-options", "good", "{}"))
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(resp.Body, "not_found") || !fb.subject.Request.IsZero() {
		t.Fatalf("a hidden request: %d %s", resp.StatusCode, resp.Body)
	}
	mux, _ = newApprovalsHandlerWith(t, &fakeApprovals{err: apapp.ErrNotEligible})
	resp = do(t, mux, postAs(authnapp.ApprovalsPath+"/"+knownRequest.String()+"/approve-options", "good", "{}"))
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(resp.Body, "not_eligible") {
		t.Fatalf("a visible request: %d %s", resp.StatusCode, resp.Body)
	}
}

// TestHR172_ResponsesThatGrantNothingNeedOnlyTheSignedInPerson: declining,
// asking for evidence and proposing a narrower action reach the use cases
// as the browser session's person, with exactly the fields the page sent.
func TestHR172_ResponsesThatGrantNothingNeedOnlyTheSignedInPerson(t *testing.T) {
	fa := &fakeApprovals{}
	mux := newApprovalsHandler(t, fa)
	base := authnapp.ApprovalsPath + "/" + knownRequest.String()
	resp := do(t, mux, postAs(base+"/decline", "responder", `{"reason":"TOO_RISKY","alternative":"PERSON_PERFORMS","note":"no"}`))
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, "DECLINED") || fa.calls[0] != "decline:TOO_RISKY:PERSON_PERFORMS:no" {
		t.Fatalf("decline: %d %s %v", resp.StatusCode, resp.Body, fa.calls)
	}
	if r := fa.responders[0]; r.User != responderID || r.Browser.IsZero() || !r.CLI.IsZero() {
		t.Fatalf("responder %+v", r)
	}
	before := time.Now()
	resp = do(t, mux, postAs(base+"/evidence-request", "responder", `{"question":"WHY_NEEDED","note":"which ticket?","minutes":30}`))
	if resp.StatusCode != http.StatusOK || fa.calls[1] != "evidence:WHY_NEEDED:which ticket?" ||
		fa.deadline.Before(before.Add(30*time.Minute)) || fa.deadline.After(time.Now().Add(30*time.Minute)) {
		t.Fatalf("evidence: %d %s %v", resp.StatusCode, resp.Body, fa.deadline)
	}
	for _, bad := range []string{`{"question":"WHY_NEEDED","minutes":0}`, `{"question":"WHY_NEEDED","minutes":20000}`} {
		if resp = do(t, mux, postAs(base+"/evidence-request", "responder", bad)); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %d", bad, resp.StatusCode)
		}
	}
	resp = do(t, mux, postAs(base+"/narrower", "responder", `{"params":{"amount":{"value":"30.00","currency":"USD"}},"validate_only":true}`))
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, `"decision":"ALLOW"`) || !strings.Contains(resp.Body, "WITHIN_LIMITS") ||
		fa.params != `{"amount":{"value":"30.00","currency":"USD"}}` || !fa.validate {
		t.Fatalf("narrower: %d %s %s", resp.StatusCode, resp.Body, fa.params)
	}
	if resp = do(t, mux, postAs(base+"/decline", "responder", `{"reason":"TOO_RISKY","approve":true}`)); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("an unknown member: %d", resp.StatusCode)
	}
	fa.err = apapp.ErrNotWaiting
	if resp = do(t, mux, postAs(base+"/decline", "responder", `{"reason":"TOO_RISKY"}`)); resp.StatusCode != http.StatusConflict ||
		!strings.Contains(resp.Body, "not_waiting") {
		t.Fatalf("a request no longer waiting: %d %s", resp.StatusCode, resp.Body)
	}
}

// TestHR151_TheApprovalPageLoadsOnlyItsScriptAndOffersOnlyAllowedActions:
// one script, the static approvals.js; the buttons appear only for what
// the person may do.
func TestHR151_TheApprovalPageLoadsOnlyItsScriptAndOffersOnlyAllowedActions(t *testing.T) {
	path := authnapp.ApprovalsPath + "/" + knownRequest.String()
	body := getAs(t, newApprovalsHandler(t, &fakeApprovals{}), path, "good").Body
	if strings.Count(body, "<script") != 1 || !strings.Contains(body, `<script src="/static/approvals.js"></script>`) {
		t.Fatal("the approval page must load exactly one script, the static file")
	}
	buttons := []string{`id="approve"`, `id="decline"`, `id="request-evidence"`, `id="narrower-check"`, `id="narrower-propose"`}
	for _, b := range buttons {
		if !strings.Contains(body, b) {
			t.Errorf("a decider's page lacks %s", b)
		}
	}
	body = getAs(t, newApprovalsHandler(t, &fakeApprovals{readOnly: true}), path, "good").Body
	for _, b := range buttons {
		if strings.Contains(body, b) {
			t.Errorf("a reader's page offers %s", b)
		}
	}
	resp := getAs(t, newApprovalsHandler(t, &fakeApprovals{}), "/static/approvals.js", "")
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/javascript") ||
		strings.Contains(resp.Body, "innerHTML") {
		t.Fatalf("approvals.js: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
}

// TestHR175_ABatchApprovalSignsTheBatchHash: batch-options starts one
// ceremony over the batch's hash for the session's person; batch hands the
// verified assertion to the use case; a request that must be reviewed alone
// is named by its code; an assertion over another batch is spent.
func TestHR175_ABatchApprovalSignsTheBatchHash(t *testing.T) {
	fa := &fakeApprovals{}
	mux, fb := newApprovalsHandlerWith(t, fa)
	other := ids.NewV7()
	body := `{"ids":["` + knownRequest.String() + `","` + other.String() + `"]}`
	resp := do(t, mux, postAs(authnapp.ApprovalsPath+"/batch-options", "responder", body))
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, `"batch":"`+knownBatch.String()+`"`) ||
		fb.challenge != batchHash || fb.subject != (authnapp.BindingSubject{Batch: knownBatch}) || len(fa.batch) != 2 {
		t.Fatalf("batch-options: %d %s", resp.StatusCode, resp.Body)
	}
	if r := fa.responders[0]; r.User != responderID || r.Browser.IsZero() {
		t.Fatalf("responder %+v", r)
	}
	ceremony := ids.NewV7()
	approve := `{"batch":"` + knownBatch.String() + `","ceremony":"` + ceremony.String() + `","response":{"id":"x"}}`
	fb.batch = knownBatch
	resp = do(t, mux, postAs(authnapp.ApprovalsPath+"/batch", "responder", approve))
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, `"approved":2`) || fa.assertion.Ceremony != ceremony || len(fb.spent) != 0 {
		t.Fatalf("batch: %d %s", resp.StatusCode, resp.Body)
	}
	fb.batch = ids.NewV7()
	if resp = do(t, mux, postAs(authnapp.ApprovalsPath+"/batch", "responder", approve)); resp.StatusCode != http.StatusBadRequest ||
		!strings.Contains(resp.Body, "ceremony_invalid") || len(fb.spent) != 1 {
		t.Fatalf("an assertion over another batch: %d %s", resp.StatusCode, resp.Body)
	}
	fa.batchErr = pcerr.New(pcerr.FailedPrecondition, apdomain.BatchOverCeiling, "alone")
	if resp = do(t, mux, postAs(authnapp.ApprovalsPath+"/batch-options", "responder", body)); resp.StatusCode != http.StatusConflict ||
		!strings.Contains(resp.Body, `"reason":"OVER_BATCH_CEILING"`) {
		t.Fatalf("a request to review alone: %d %s", resp.StatusCode, resp.Body)
	}
	fa.batchErr = apapp.ErrEditionRequired
	if resp = do(t, mux, postAs(authnapp.ApprovalsPath+"/batch-options", "responder", body)); resp.StatusCode != http.StatusForbidden ||
		!strings.Contains(resp.Body, "edition_required") {
		t.Fatalf("Community: %d %s", resp.StatusCode, resp.Body)
	}
	if resp = do(t, mux, postAs(authnapp.ApprovalsPath+"/batch-options", "responder", `{"ids":["x"]}`)); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a bad id: %d", resp.StatusCode)
	}
}
