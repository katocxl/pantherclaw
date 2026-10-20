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
	"github.com/katocxl/pantherclaw/internal/enforcementpoints"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
)

// fakePoints records the step-up the confirmation received and refuses
// without one, as the use case does.
type fakePoints struct{ got []*stepup.StepUp }

func (f *fakePoints) Get(_ context.Context, id ids.UUID) (enforcementpoints.Point, error) {
	return enforcementpoints.Point{
		ID: id, Name: "edge-pep", Description: `<script>alert(1)</script>`, State: enforcementpoints.StatePending,
		Proposed: []ids.UUID{ids.NewV7()}, RatePerSecond: 50, CreatedAt: time.Now(),
	}, nil
}

func (f *fakePoints) Activate(_ context.Context, id ids.UUID, su *stepup.StepUp) (enforcementpoints.Point, error) {
	f.got = append(f.got, su)
	if su == nil {
		return enforcementpoints.Point{}, stepup.ErrStepUp
	}
	return enforcementpoints.Point{ID: id, State: enforcementpoints.StateActive}, nil
}

// TestD29_EnforcementPointConfirmationNeedsThePagesStepUp: confirming a
// point's proposed connections is a session route with the CSRF proof, and
// the page passes the session's step-up (none when the session has not
// stepped up, which the use case refuses as STEP_UP_REQUIRED). The page
// escapes the point's untrusted description.
func TestD29_EnforcementPointConfirmationNeedsThePagesStepUp(t *testing.T) {
	h, _, mux := newHandler(t, origin)
	fake := &fakePoints{}
	m := mux.(*http.ServeMux)
	h.MountEnforcementPoints(m, fake)
	for _, want := range []webhttp.Route{
		{Method: http.MethodGet, Path: "/enforcement-points/{id}/confirm", Session: true},
		{Method: http.MethodPost, Path: "/enforcement-points/{id}/activate", Session: true, CSRF: true},
	} {
		if !slices.Contains(h.Routes(), want) {
			t.Errorf("route %+v is not mounted", want)
		}
	}
	id := ids.NewV7().String()
	path := "/enforcement-points/" + id + "/activate"
	r := post(path)
	r.Header.Del(webhttp.CSRFHeader)
	if resp := do(t, m, r); resp.StatusCode != http.StatusForbidden || len(fake.got) != 0 {
		t.Fatalf("without CSRF: %d, %d calls", resp.StatusCode, len(fake.got))
	}
	if resp := do(t, m, post(path)); resp.StatusCode != http.StatusForbidden || !strings.Contains(resp.Body, "step_up_required") || fake.got[0] != nil {
		t.Fatalf("without a step-up: %d %s", resp.StatusCode, resp.Body)
	}
	resp := do(t, m, withCookie(post(path), "responder"))
	if su := fake.got[len(fake.got)-1]; resp.StatusCode != http.StatusOK || su == nil || su.Credential != responderKey || !su.At.Equal(steppedUpAt) {
		t.Fatalf("stepped up: %d %s %+v", resp.StatusCode, resp.Body, su)
	}
	page := httptest.NewRequest(http.MethodGet, origin+"/enforcement-points/"+id+"/confirm", nil)
	page.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: "good"})
	if resp := do(t, m, page); resp.StatusCode != http.StatusOK || strings.Contains(resp.Body, "<script>alert") ||
		!strings.Contains(resp.Body, "/static/automation_endpoints.js") {
		t.Fatalf("page: %d", resp.StatusCode)
	}
	bad := httptest.NewRequest(http.MethodGet, origin+"/enforcement-points/nope/confirm", nil)
	bad.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: "good"})
	if resp := do(t, m, bad); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a bad id: %d", resp.StatusCode)
	}
}
