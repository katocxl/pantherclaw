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

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	"github.com/katocxl/pantherclaw/internal/support"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type fakeBreakGlass struct {
	su    []*stepup.StepUp
	calls int
}

func (f *fakeBreakGlass) MyBreakGlass(context.Context) (*support.Holder, *support.Activation, error) {
	return &support.Holder{Role: td.RoleAuditor}, nil, nil
}
func (f *fakeBreakGlass) BreakGlassCall(_ context.Context, c tapp.Caller, _ string) (tapp.Caller, error) {
	f.calls++
	return c, nil
}
func (f *fakeBreakGlass) ActivateBreakGlass(_ context.Context, _ string, _ int, su *stepup.StepUp) (support.Activation, error) {
	f.su = append(f.su, su)
	if su == nil {
		return support.Activation{}, stepup.ErrStepUp
	}
	return support.Activation{ID: ids.NewV7()}, nil
}

func TestHR389_BreakGlassPageRequiresCSRFAndSessionsOwnStepUp(t *testing.T) {
	h, _, mux := newHandler(t, origin)
	f := &fakeBreakGlass{}
	h.MountBreakGlass(mux.(*http.ServeMux), f)
	for _, route := range []webhttp.Route{
		{Method: http.MethodGet, Path: "/break-glass/activate", Session: true},
		{Method: http.MethodPost, Path: "/break-glass/activate", Session: true, CSRF: true},
	} {
		if !slices.Contains(h.Routes(), route) {
			t.Fatalf("missing route: %+v", route)
		}
	}
	r := post("/break-glass/activate")
	r.Header.Del(webhttp.CSRFHeader)
	if resp := do(t, mux, r); resp.StatusCode != http.StatusForbidden || len(f.su) != 0 {
		t.Fatal("activation without CSRF reached service")
	}
	if resp := do(t, mux, post("/break-glass/activate")); resp.StatusCode != http.StatusForbidden || !strings.Contains(resp.Body, "step_up_required") {
		t.Fatalf("no key: %+v", resp)
	}
	if resp := do(t, mux, withCookie(post("/break-glass/activate"), "responder")); resp.StatusCode != http.StatusOK || f.su[len(f.su)-1].Credential != responderKey {
		t.Fatalf("own key: %+v", resp)
	}
	r = httptest.NewRequest(http.MethodGet, origin+"/break-glass/activate", nil)
	r.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: "good"})
	if resp := do(t, mux, r); resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, "Two-person rules") || !strings.Contains(resp.Body, "auditor") {
		t.Fatalf("confirm: %+v", resp)
	}
	if f.calls != 3 {
		t.Fatalf("page calls audited: %d", f.calls)
	}
}
