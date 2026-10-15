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
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

var (
	knownChange   = ids.NewV7()
	changeBinding = [32]byte{4, 5, 6}
	// rlo is RIGHT-TO-LEFT OVERRIDE and cyrillicA a look-alike of "a".
	rlo, cyrillicA = string(rune(0x202e)), string(rune(0x0430))
)

// fakePolicyChanges shows knownChange with a summary that tries to inject
// markup; its actions record what the page passed and fail with err when
// it is set.
type fakePolicyChanges struct {
	err error

	mu        sync.Mutex
	callers   []tapp.Caller
	assertion policyapp.Assertion
	reason    string
}

func (f *fakePolicyChanges) note(ctx context.Context) {
	c, _ := tapp.CallerFrom(ctx)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callers = append(f.callers, c)
}

func (f *fakePolicyChanges) request() policyapp.ChangeRequest {
	return policyapp.ChangeRequest{
		ID: knownChange, Kind: policyapp.ChangePublish, Subject: ids.NewV7(), Binding: changeBinding, Required: 2,
		State: policyapp.ChangePending, RequestedBy: "user:alice", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour),
		Summary: []byte("{\"changes\":[{\"rule_id\":\"x\",\"sentence\":\"<script>alert(1)</script>\",\"before\":\"amount " + rlo + "05 >\",\"after\":\"p" + cyrillicA + "ypal\"}]}"),
	}
}

func (f *fakePolicyChanges) Pending(ctx context.Context) ([]policyapp.ChangeRequest, error) {
	f.note(ctx)
	return []policyapp.ChangeRequest{f.request()}, nil
}

func (f *fakePolicyChanges) Get(ctx context.Context, id ids.UUID) (policyapp.ChangeRequest, error) {
	f.note(ctx)
	if id != knownChange {
		return policyapp.ChangeRequest{}, policyapp.ErrChangeNotFound
	}
	return f.request(), nil
}

func (f *fakePolicyChanges) BeginConfirm(ctx context.Context, id ids.UUID) (policyapp.ChangeRequest, error) {
	f.note(ctx)
	if id != knownChange {
		return policyapp.ChangeRequest{}, policyapp.ErrChangeNotFound
	}
	return f.request(), f.err
}

func (f *fakePolicyChanges) Confirm(ctx context.Context, _ ids.UUID, a policyapp.Assertion) (policyapp.ChangeRequest, error) {
	f.note(ctx)
	f.mu.Lock()
	f.assertion = a
	f.mu.Unlock()
	r := f.request()
	r.State = policyapp.ChangeApproved
	return r, f.err
}

func (f *fakePolicyChanges) Decline(ctx context.Context, _ ids.UUID, reason string) (policyapp.ChangeRequest, error) {
	f.note(ctx)
	f.mu.Lock()
	f.reason = reason
	f.mu.Unlock()
	r := f.request()
	r.State = policyapp.ChangeDeclined
	return r, f.err
}

func newPolicyChangesHandler(t *testing.T, fc *fakePolicyChanges) (http.Handler, *webhttp.Handler, *fakeBindings) {
	t.Helper()
	h, err := webhttp.New(&fakeBrowser{}, origin, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	fb := &fakeBindings{}
	h.WithPolicyChanges(fc, fb)
	mux := http.NewServeMux()
	h.Mount(mux)
	return mux, h, fb
}

// TestHR231_ThePolicyChangePageShowsAnUntrustedSummary (HR-151): the pages
// need a browser session, every action is a CSRF-checked POST, the
// summary is escaped inside the untrusted box under the fixed label, and
// the page loads only its static script.
func TestHR231_ThePolicyChangePageShowsAnUntrustedSummary(t *testing.T) {
	fc := &fakePolicyChanges{}
	mux, h, _ := newPolicyChangesHandler(t, fc)
	for _, r := range h.Routes() {
		if !strings.HasPrefix(r.Path, policyapp.ChangesPath) {
			continue
		}
		if !r.Session || r.CSRF != (r.Method == http.MethodPost) {
			t.Errorf("%s %s: session %v, csrf %v", r.Method, r.Path, r.Session, r.CSRF)
		}
	}
	resp := getAs(t, mux, policyapp.ChangesPath+"/"+knownChange.String(), "good")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Security-Policy") != webhttp.PageCSP {
		t.Fatalf("%d %v", resp.StatusCode, resp.Header)
	}
	body := resp.Body
	if !strings.Contains(body, webhttp.SummaryLabel) || !strings.Contains(body, `<pre class="untrusted">`) ||
		!strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") || strings.Contains(body, "<script>alert") {
		t.Fatalf("the summary is not shown as escaped untrusted text: %s", body)
	}
	if strings.ContainsRune(body, 0x202e) || !strings.Contains(body, "amount 05 &gt;") || !strings.Contains(body, "mixes writing systems") {
		t.Fatal("the summary keeps a bidi override or does not flag mixed script (HR-034)")
	}
	if strings.Count(body, "<script") != 1 || !strings.Contains(body, `<script src="/static/policy_changes.js"></script>`) {
		t.Fatal("the page must load exactly one script, the static file")
	}
	if c := fc.callers[0]; c.Credential != tapp.CredBrowserSession || c.Session.IsZero() {
		t.Fatalf("caller %+v", c)
	}
	if resp := getAs(t, mux, policyapp.ChangesPath+"/"+ids.NewV7().String(), "good"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("an unknown change: %d", resp.StatusCode)
	}
	if resp := getAs(t, mux, policyapp.ChangesPath, "good"); resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, knownChange.String()) {
		t.Fatalf("the list: %d", resp.StatusCode)
	}
	if resp := getAs(t, mux, policyapp.ChangesPath, ""); resp.StatusCode == http.StatusOK {
		t.Fatal("the list without a session")
	}
	resp = getAs(t, mux, "/static/policy_changes.js", "")
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/javascript") ||
		strings.Contains(resp.Body, "innerHTML") {
		t.Fatalf("policy_changes.js: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
}

// TestHR231_ConfirmingSignsTheChangeBindingOnThePage: confirm-options
// starts a ceremony over exactly the request's binding, bound to the
// request; confirm hands the verified assertion to the use case; a refused
// confirmation, or an assertion over another request, spends the
// ceremony; a CSRF-less POST never reaches the use case.
func TestHR231_ConfirmingSignsTheChangeBindingOnThePage(t *testing.T) {
	fc := &fakePolicyChanges{}
	mux, _, fb := newPolicyChangesHandler(t, fc)
	base := policyapp.ChangesPath + "/" + knownChange.String()
	resp := do(t, mux, postAs(base+"/confirm-options", "good", `{}`))
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, `"ceremony":`) || fb.challenge != changeBinding ||
		fb.subject != (authnapp.BindingSubject{PolicyChange: knownChange}) {
		t.Fatalf("confirm-options: %d %s", resp.StatusCode, resp.Body)
	}
	ceremony := ids.NewV7()
	fb.policyChange = knownChange
	body := `{"ceremony":"` + ceremony.String() + `","response":{"id":"x"}}`
	resp = do(t, mux, postAs(base+"/confirm", "good", body))
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, `"state":"APPROVED"`) || fc.assertion.Ceremony != ceremony ||
		fc.assertion.Credential != responderKey || len(fb.spent) != 0 {
		t.Fatalf("confirm: %d %s %+v", resp.StatusCode, resp.Body, fc.assertion)
	}
	for err, code := range map[error]string{
		policyapp.ErrSamePerson: "same_person", policyapp.ErrSameKey: "same_key", policyapp.ErrChangeExpired: "expired",
		policyapp.ErrChangeAssertion: "ceremony_invalid", policyapp.ErrBrowserSession: "human_session",
		policyapp.ErrChangeVoided: "voided",
	} {
		fc.err = err
		spent := len(fb.spent)
		if resp = do(t, mux, postAs(base+"/confirm", "good", body)); !strings.Contains(resp.Body, code) || len(fb.spent) != spent+1 {
			t.Errorf("%v: %d %s (spent %d)", err, resp.StatusCode, resp.Body, len(fb.spent)-spent)
		}
	}
	fc.err, fb.policyChange = nil, ids.NewV7()
	spent, calls := len(fb.spent), len(fc.callers)
	if resp = do(t, mux, postAs(base+"/confirm", "good", body)); resp.StatusCode != http.StatusBadRequest ||
		!strings.Contains(resp.Body, "ceremony_invalid") || len(fb.spent) != spent+1 || len(fc.callers) != calls {
		t.Fatalf("an assertion over another request: %d %s", resp.StatusCode, resp.Body)
	}
	r := postAs(base+"/confirm", "good", body)
	r.Header.Del(webhttp.CSRFHeader)
	if resp = do(t, mux, r); resp.StatusCode == http.StatusOK || len(fc.callers) != calls {
		t.Fatalf("a POST without the CSRF header: %d", resp.StatusCode)
	}
	if resp = do(t, mux, postAs(base+"/decline", "good", `{"reason":"not now"}`)); resp.StatusCode != http.StatusOK || fc.reason != "not now" {
		t.Fatalf("decline: %d %s", resp.StatusCode, resp.Body)
	}
}
