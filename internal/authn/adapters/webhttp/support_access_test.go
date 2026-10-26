// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	"github.com/katocxl/pantherclaw/internal/support"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// fakeSupport records the step-ups the pages pass and refuses without
// one, as the use cases do.
type fakeSupport struct {
	decided []*stepup.StepUp
	asked   []*stepup.StepUp
	opened  []*stepup.StepUp
}

func (f *fakeSupport) IsStaff(context.Context, tapp.Caller) (bool, error) { return true, nil }

func (f *fakeSupport) Request(_ context.Context, st support.Staff, _ support.RequestInput) (support.Request, error) {
	f.asked = append(f.asked, st.StepUp)
	if st.StepUp == nil {
		return support.Request{}, stepup.ErrStepUp
	}
	return support.Request{ID: ids.NewV7()}, nil
}

func (f *fakeSupport) StaffRequest(_ context.Context, _ tapp.Caller, _, id ids.UUID) (support.Request, error) {
	return support.Request{ID: id, State: support.StateApproved, Task: "<b>task</b>", Hours: 2, CreatedAt: time.Now()}, nil
}

func (f *fakeSupport) Open(_ context.Context, st support.Staff, _ ids.OrgID, _ ids.UUID) (support.Opened, error) {
	f.opened = append(f.opened, st.StepUp)
	if st.StepUp == nil {
		return support.Opened{}, stepup.ErrStepUp
	}
	return support.Opened{Secret: "pcp_secret"}, nil
}

func (f *fakeSupport) GetRequest(_ context.Context, id ids.UUID) (support.Request, *support.Grant, error) {
	return support.Request{
		ID: id, State: support.StatePending, Task: `<script>alert(1)</script>`, Email: "staff@support.test", Hours: 4,
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}, nil, nil
}

func (f *fakeSupport) Decide(_ context.Context, id ids.UUID, _ bool, su *stepup.StepUp) (support.Request, *support.Grant, error) {
	f.decided = append(f.decided, su)
	if su == nil {
		return support.Request{}, nil, stepup.ErrStepUp
	}
	return support.Request{ID: id, State: support.StateApproved}, nil, nil
}

func (f *fakeSupport) Logout(context.Context, string) error { return nil }

// TestHR386_SupportPagesPassOnlyTheSessionsStepUp: asking, opening,
// approving and denying are session routes with the CSRF proof, and the
// pages pass the session's own step-up (none without one, which the use
// cases refuse as STEP_UP_REQUIRED). The confirm page escapes the task.
func TestHR386_SupportPagesPassOnlyTheSessionsStepUp(t *testing.T) {
	h, _, mux := newHandler(t, origin)
	fake := &fakeSupport{}
	m := mux.(*http.ServeMux)
	h.MountSupportAccess(m, fake)
	for _, want := range []webhttp.Route{
		{Method: http.MethodGet, Path: "/support-access/request", Session: true},
		{Method: http.MethodPost, Path: "/support-access/request", Session: true, CSRF: true},
		{Method: http.MethodPost, Path: "/support-access/requests/{org}/{id}/open", Session: true, CSRF: true},
		{Method: http.MethodGet, Path: "/support-access/{id}", Session: true},
		{Method: http.MethodPost, Path: "/support-access/{id}/approve", Session: true, CSRF: true},
		{Method: http.MethodPost, Path: "/support-access/{id}/deny", Session: true, CSRF: true},
		{Method: http.MethodPost, Path: "/support-access/logout", CSRF: true},
	} {
		if !slices.Contains(h.Routes(), want) {
			t.Errorf("route %+v is not mounted", want)
		}
	}
	id := ids.NewV7().String()
	for _, path := range []string{"/support-access/" + id + "/approve", "/support-access/" + id + "/deny"} {
		r := post(path)
		r.Header.Del(webhttp.CSRFHeader)
		if resp := do(t, m, r); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s without CSRF: %d", path, resp.StatusCode)
		}
		if resp := do(t, m, post(path)); resp.StatusCode != http.StatusForbidden || !strings.Contains(resp.Body, "step_up_required") {
			t.Fatalf("%s without a step-up: %d %s", path, resp.StatusCode, resp.Body)
		}
		resp := do(t, m, withCookie(post(path), "responder"))
		if su := fake.decided[len(fake.decided)-1]; resp.StatusCode != http.StatusOK || su == nil || su.Credential != responderKey {
			t.Fatalf("%s stepped up: %d %s %+v", path, resp.StatusCode, resp.Body, su)
		}
	}
	org := ids.New[ids.Org]().String()
	open := "/support-access/requests/" + org + "/" + id + "/open"
	if resp := do(t, m, post(open)); resp.StatusCode != http.StatusForbidden || fake.opened[0] != nil {
		t.Fatalf("open without a step-up: %d", resp.StatusCode)
	}
	resp := do(t, m, withCookie(post(open), "responder"))
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, `"next":"/app/"`) {
		t.Fatalf("open: %d %s", resp.StatusCode, resp.Body)
	}
	page := httptest.NewRequest(http.MethodGet, origin+"/support-access/"+id, nil)
	page.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: "good"})
	if resp := do(t, m, page); resp.StatusCode != http.StatusOK || strings.Contains(resp.Body, "<script>alert") ||
		!strings.Contains(resp.Body, "/static/support_access.js") {
		t.Fatalf("confirm page: %d", resp.StatusCode)
	}
	for _, p := range []string{"/support-access/request", "/support-access/requests/" + org + "/" + id} {
		page := httptest.NewRequest(http.MethodGet, origin+p, nil)
		page.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: "good"})
		if resp := do(t, m, page); resp.StatusCode != http.StatusOK || strings.Contains(resp.Body, "<b>task") {
			t.Fatalf("%s: %d %s", p, resp.StatusCode, resp.Body)
		}
	}
}
