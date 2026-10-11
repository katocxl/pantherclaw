// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp_test

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
	txdomain "github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// knownReconciliation is the one reconciliation fakeReconciliations shows,
// with one observation; a release of it is bound to releaseBinding and
// expires at releaseExpiry.
var (
	knownReconciliation = ids.NewV7()
	knownObservation    = ids.NewV7()
	releaseBinding      = [32]byte{7, 8, 9}
	releaseExpiry       = time.Date(2026, 10, 10, 12, 5, 0, 0, time.UTC)
)

// fakeReconciliations shows knownReconciliation with an observation and a
// basis that try to inject markup. Its actions record what the page passed
// and fail with err when it is set.
type fakeReconciliations struct {
	refusal string
	err     error

	mu        sync.Mutex
	callers   []tapp.Caller
	requests  []txapp.ReleaseRequest
	expiry    time.Time
	assertion txapp.Assertion
}

func (f *fakeReconciliations) note(ctx context.Context, req txapp.ReleaseRequest) {
	c, _ := tapp.CallerFrom(ctx)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callers, f.requests = append(f.callers, c), append(f.requests, req)
}

func (f *fakeReconciliations) View(ctx context.Context, id ids.UUID) (txapp.ReleaseView, error) {
	if _, err := tapp.CallerFrom(ctx); err != nil {
		return txapp.ReleaseView{}, err
	}
	if id != knownReconciliation {
		return txapp.ReleaseView{}, txapp.ErrReconciliationNotFound
	}
	dispatched := time.Date(2026, 10, 10, 11, 48, 0, 0, time.UTC)
	found, complete := false, true
	v := txapp.ReleaseView{
		Reconciliation: txapp.Reconciliation{
			ID: id, Transaction: ids.NewV7(), Kind: txdomain.KindUnknownOutcome, State: txdomain.TaskOpen, Opened: dispatched,
		},
		Evidence: txapp.Evidence{
			Transaction: txapp.Summary{Operation: "payments.refund.create", Execution: txdomain.Dispatched, Effect: txdomain.NoneConfirmed},
			Execution:   &txapp.ExecutionRecord{Outcome: "unknown", RecordedBy: "gateway", Dispatched: &dispatched},
			Observations: []txapp.ObservationRecord{{
				ID: knownObservation, Source: "verifier", HTTPStatus: 200, Found: &found, Complete: &complete,
				Fields: map[string]string{"/status": `<script>alert(1)</script>`}, Observed: dispatched.Add(12 * time.Minute),
			}},
		},
		MayRelease: f.refusal == "", Refusal: f.refusal,
	}
	if f.refusal == txapp.RefusalNotOpen {
		person := ids.NewV7()
		v.Reconciliation.State, v.Reconciliation.Via, v.Reconciliation.User = txdomain.TaskNotOccurred, txdomain.ViaPerson, &person
		v.Reconciliation.Basis = `"><img src=x onerror=alert(1)> checked p` + string(rune(0x0430)) + "ypal"
	}
	return v, nil
}

func (f *fakeReconciliations) BeginRelease(ctx context.Context, req txapp.ReleaseRequest) (txapp.ReleaseOffer, error) {
	f.note(ctx, req)
	if req.Reconciliation != knownReconciliation {
		return txapp.ReleaseOffer{}, td.ErrPermissionDenied(td.PermTransactionReconcile)
	}
	return txapp.ReleaseOffer{
		Binding: releaseBinding,
		Release: txdomain.Release{Reconciliation: req.Reconciliation, Basis: req.Basis, Evidence: req.Evidence, ExpiresAt: releaseExpiry},
	}, f.err
}

func (f *fakeReconciliations) Release(ctx context.Context, req txapp.ReleaseRequest, expiresAt time.Time, a txapp.Assertion) (txapp.Reconciliation, error) {
	f.note(ctx, req)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.expiry, f.assertion = expiresAt, a
	return txapp.Reconciliation{State: txdomain.TaskNotOccurred}, f.err
}

func newReconciliationsHandler(t *testing.T, fr *fakeReconciliations) (http.Handler, *fakeBindings) {
	t.Helper()
	h, err := webhttp.New(&fakeBrowser{}, origin, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	fb := &fakeBindings{}
	h.WithReconciliations(fr, fb)
	mux := http.NewServeMux()
	h.Mount(mux)
	return mux, fb
}

// TestHR192_TheReconciliationPageShowsTheEvidenceAndAnUntrustedBasis: the
// page shows the transaction, the verifier's observation (target data,
// escaped) with how long after dispatch it was read, and the effect state;
// a person who may release gets the form and only the static script; a
// resolved reconciliation shows its basis under the fixed label, escaped.
func TestHR192_TheReconciliationPageShowsTheEvidenceAndAnUntrustedBasis(t *testing.T) {
	mux, _ := newReconciliationsHandler(t, &fakeReconciliations{})
	path := authnapp.ReconciliationsPath + "/" + knownReconciliation.String()
	resp := getAs(t, mux, path, "good")
	body := resp.Body
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Security-Policy") != webhttp.PageCSP || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v", resp.StatusCode, resp.Header)
	}
	for _, want := range []string{
		"payments.refund.create", "NONE_CONFIRMED", "12m0s after dispatch", `data-evidence="` + knownObservation.String() + `"`,
		"&lt;script&gt;alert(1)&lt;/script&gt;", `id="release"`, `id="release-basis"`, `maxlength="2000"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if strings.Count(body, "<script") != 1 || !strings.Contains(body, `<script src="/static/reconciliations.js"></script>`) ||
		strings.Contains(body, "<script>alert") {
		t.Fatal("the page must load exactly one script, the static file, and escape target data")
	}

	for refusal, text := range map[string]string{
		txapp.RefusalIndependence: "never release their own run",
		txapp.RefusalPermission:   "transaction.reconcile",
	} {
		mux, _ := newReconciliationsHandler(t, &fakeReconciliations{refusal: refusal})
		body := getAs(t, mux, path, "good").Body
		if strings.Contains(body, `id="release"`) || !strings.Contains(body, text) {
			t.Errorf("%s: the page offers the release or does not say why not", refusal)
		}
	}
	mux, _ = newReconciliationsHandler(t, &fakeReconciliations{refusal: txapp.RefusalNotOpen})
	body = getAs(t, mux, path, "good").Body
	if !strings.Contains(body, webhttp.BasisLabel) || !strings.Contains(body, "&#34;&gt;&lt;img src=x") || strings.Contains(body, "<img src=x") ||
		!strings.Contains(body, "mixes writing systems") || strings.Contains(body, `id="release"`) {
		t.Fatalf("a released reconciliation's page: %s", body)
	}
	resp = getAs(t, mux, "/static/reconciliations.js", "")
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/javascript") ||
		strings.Contains(resp.Body, "innerHTML") {
		t.Fatalf("reconciliations.js: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
}

// TestT037_AnUnknownOrHiddenReconciliationIsNotFound: an id of another org
// (which the use case does not find), an unknown id and a malformed id all
// get the same "not found"; so does an action on one the person cannot see.
func TestT037_AnUnknownOrHiddenReconciliationIsNotFound(t *testing.T) {
	mux, fb := newReconciliationsHandler(t, &fakeReconciliations{})
	for _, path := range []string{authnapp.ReconciliationsPath + "/" + ids.NewV7().String(), authnapp.ReconciliationsPath + "/not-an-id"} {
		resp := getAs(t, mux, path, "good")
		if resp.StatusCode != http.StatusNotFound || !strings.Contains(resp.Body, "does not exist, or you cannot see it") {
			t.Errorf("%s: %d", path, resp.StatusCode)
		}
	}
	resp := do(t, mux, postAs(authnapp.ReconciliationsPath+"/"+ids.NewV7().String()+"/release-options", "good", `{"basis":"x","evidence":[]}`))
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(resp.Body, "not_found") || !fb.subject.Reconciliation.IsZero() {
		t.Fatalf("release-options on a hidden reconciliation: %d %s", resp.StatusCode, resp.Body)
	}
}

// TestHR152_SignInReturnsToTheReconciliationPage: without a session, a link
// that names the org goes to sign-in with the page as next.
func TestHR152_SignInReturnsToTheReconciliationPage(t *testing.T) {
	mux, _ := newReconciliationsHandler(t, &fakeReconciliations{})
	path := authnapp.ReconciliationsPath + "/" + knownReconciliation.String()
	resp := getAs(t, mux, path+"?org="+testOrg.String(), "")
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || !strings.Contains(loc, "next=%2Freconciliations%2F"+knownReconciliation.String()) {
		t.Fatalf("%d %s", resp.StatusCode, loc)
	}
	if !authnapp.ValidReturnPath(path) {
		t.Fatal("the reconciliation page must be a valid return path")
	}
}

// TestHR192_ReleasingSignsTheReleaseBindingOnThePage: release-options starts
// a ceremony over exactly the offer's binding, bound to the
// reconciliation, for the browser session's person, and returns the
// document's expiry and evidence; release hands the verified assertion with
// them to the use case; a refused release, or an assertion over another
// reconciliation, spends the ceremony; an assertion that does not verify
// never reaches the use case.
func TestHR192_ReleasingSignsTheReleaseBindingOnThePage(t *testing.T) {
	fr := &fakeReconciliations{}
	mux, fb := newReconciliationsHandler(t, fr)
	base := authnapp.ReconciliationsPath + "/" + knownReconciliation.String()
	resp := do(t, mux, postAs(base+"/release-options", "good", `{"basis":"not in the dashboard","evidence":["`+knownObservation.String()+`"]}`))
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, `"ceremony":`) || !strings.Contains(resp.Body, `"expires_at":"2026-10-10T12:05:00Z"`) ||
		!strings.Contains(resp.Body, `"evidence":["`+knownObservation.String()+`"]`) || fb.challenge != releaseBinding ||
		fb.subject != (authnapp.BindingSubject{Reconciliation: knownReconciliation}) {
		t.Fatalf("release-options: %d %s", resp.StatusCode, resp.Body)
	}
	if c := fr.callers[0]; c.Credential != tapp.CredBrowserSession || c.Session.IsZero() || fr.requests[0].Basis != "not in the dashboard" ||
		len(fr.requests[0].Evidence) != 1 || fr.requests[0].Evidence[0] != knownObservation {
		t.Fatalf("begin: %+v %+v", c, fr.requests[0])
	}

	ceremony := ids.NewV7()
	fb.reconciliation = knownReconciliation
	body := `{"ceremony":"` + ceremony.String() + `","response":{"id":"x"},"basis":"not in the dashboard","evidence":["` +
		knownObservation.String() + `"],"expires_at":"2026-10-10T12:05:00Z"}`
	resp = do(t, mux, postAs(base+"/release", "good", body))
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, `"state":"NOT_OCCURRED"`) || fr.assertion.Ceremony != ceremony ||
		fr.assertion.Credential != responderKey || len(fr.assertion.AuthenticatorData) != 37 || !fr.expiry.Equal(releaseExpiry) ||
		fr.requests[1].Reconciliation != knownReconciliation || len(fb.spent) != 0 {
		t.Fatalf("release: %d %s %+v", resp.StatusCode, resp.Body, fr.assertion)
	}

	for err, code := range map[error]string{
		txapp.ErrNotIndependent: "not_independent", txapp.ErrReleaseAssertion: "ceremony_invalid", txapp.ErrReleaseExpired: "expired",
		txapp.ErrNotOpen: "not_open", txapp.ErrBrowserSession: "human_session",
	} {
		fr.err = err
		spent := len(fb.spent)
		if resp = do(t, mux, postAs(base+"/release", "good", body)); !strings.Contains(resp.Body, code) || len(fb.spent) != spent+1 {
			t.Errorf("%v: %d %s (spent %d)", err, resp.StatusCode, resp.Body, len(fb.spent)-spent)
		}
	}
	fr.err, fb.reconciliation = nil, ids.NewV7()
	spent, calls := len(fb.spent), len(fr.requests)
	if resp = do(t, mux, postAs(base+"/release", "good", body)); resp.StatusCode != http.StatusBadRequest ||
		!strings.Contains(resp.Body, "ceremony_invalid") || len(fb.spent) != spent+1 || len(fr.requests) != calls {
		t.Fatalf("an assertion over another reconciliation: %d %s", resp.StatusCode, resp.Body)
	}
	fb.reconciliation, fb.verifyErr = knownReconciliation, authnapp.ErrWebAuthnFailed
	if resp = do(t, mux, postAs(base+"/release", "good", body)); resp.StatusCode != http.StatusBadRequest ||
		!strings.Contains(resp.Body, "verification_failed") || len(fr.requests) != calls {
		t.Fatalf("an assertion that does not verify: %d %s", resp.StatusCode, resp.Body)
	}
	fb.verifyErr = nil
	for _, bad := range []string{
		`{"ceremony":"x","response":{"id":"x"},"basis":"b","evidence":[],"expires_at":"2026-10-10T12:05:00Z"}`,
		`{"ceremony":"` + ceremony.String() + `","basis":"b","evidence":[],"expires_at":"2026-10-10T12:05:00Z"}`,
		`{"ceremony":"` + ceremony.String() + `","response":{"id":"x"},"basis":"b","evidence":[],"expires_at":"soon"}`,
		`{"ceremony":"` + ceremony.String() + `","response":{"id":"x"},"basis":"b","evidence":["x"],"expires_at":"2026-10-10T12:05:00Z"}`,
		`{"ceremony":"` + ceremony.String() + `","response":{"id":"x"},"basis":"b","evidence":[],"expires_at":"2026-10-10T12:05:00Z","release":true}`,
	} {
		if resp = do(t, mux, postAs(base+"/release", "good", bad)); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %d", bad, resp.StatusCode)
		}
	}
	// A person who may see it but not release it is refused, not hidden.
	fr.err = td.ErrPermissionDenied(td.PermTransactionReconcile)
	if resp = do(t, mux, postAs(base+"/release-options", "good", `{"basis":"b","evidence":[]}`)); resp.StatusCode != http.StatusForbidden ||
		!strings.Contains(resp.Body, "not_permitted") {
		t.Fatalf("a reader: %d %s", resp.StatusCode, resp.Body)
	}
}
