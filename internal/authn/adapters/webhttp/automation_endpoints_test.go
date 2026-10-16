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
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/triggers"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/endpoints"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
)

// fakeAutomationEndpoints records the step-up each action received and
// refuses without one, as the use cases do.
type fakeAutomationEndpoints struct {
	got   []*stepup.StepUp
	start triggers.ManualStart
}

func (f *fakeAutomationEndpoints) need(su *stepup.StepUp) error {
	f.got = append(f.got, su)
	if su == nil {
		return stepup.ErrStepUp
	}
	return nil
}

func (f *fakeAutomationEndpoints) EventSource(_ context.Context, id ids.UUID) (endpoints.Source, error) {
	return endpoints.Source{
		ID: id, Name: "support", Description: `<script>alert(1)</script>`, Types: []string{"ticket.created"},
		RatePerMinute: 60, State: endpoints.StatePending, CreatedAt: time.Now(),
	}, nil
}

func (f *fakeAutomationEndpoints) ActivateEventSource(_ context.Context, id ids.UUID, su *stepup.StepUp) (endpoints.Source, error) {
	return endpoints.Source{ID: id, State: endpoints.StateActive}, f.need(su)
}

func (f *fakeAutomationEndpoints) RotateEventSourceSecret(_ context.Context, _ ids.UUID, su *stepup.StepUp) (string, error) {
	return "whsec_new", f.need(su)
}

func (f *fakeAutomationEndpoints) Destination(_ context.Context, id ids.UUID) (endpoints.Destination, error) {
	return endpoints.Destination{
		ID: id, Name: "hooks", URL: "https://hooks.example.test/x", Purposes: []string{"LAUNCH"},
		State: endpoints.StatePending, CreatedAt: time.Now(),
	}, nil
}

func (f *fakeAutomationEndpoints) ActivateDestination(_ context.Context, id ids.UUID, su *stepup.StepUp) (endpoints.Destination, error) {
	return endpoints.Destination{ID: id, State: endpoints.StateActive}, f.need(su)
}

func (f *fakeAutomationEndpoints) RotateDestinationSecret(_ context.Context, _ ids.UUID, su *stepup.StepUp) (string, error) {
	return "whsec_new", f.need(su)
}

func (f *fakeAutomationEndpoints) Form(_ context.Context, id ids.UUID) (triggers.ManualForm, error) {
	return triggers.ManualForm{Automation: id, Name: "refunds", StepUp: true, Params: map[string]autodomain.ParamSpec{
		"ticket": {Type: autodomain.ParamString}, "tier": {Type: autodomain.ParamEnum, Values: []string{"gold", "silver"}},
	}}, nil
}

func (f *fakeAutomationEndpoints) StartExecution(_ context.Context, in triggers.ManualStart, su *stepup.StepUp) (triggers.Outcome, error) {
	f.start = in
	return triggers.Outcome{Trigger: ids.NewV7(), State: triggers.StateAccepted, Execution: ids.NewV7()}, f.need(su)
}

func automationMux(t *testing.T) (*webhttp.Handler, *fakeAutomationEndpoints, http.Handler) {
	t.Helper()
	h, _, mux := newHandler(t, origin)
	fake := &fakeAutomationEndpoints{}
	m := mux.(*http.ServeMux)
	h.MountAutomationEndpoints(m, fake)
	return h, fake, m
}

func withCookie(r *http.Request, v string) *http.Request {
	r.Header.Del("Cookie")
	r.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: v})
	return r
}

// TestD53_AutomationEndpointActionsNeedThePagesStepUp: activating and
// rotating sources and destinations, and starting a step-up version, are
// session routes with the CSRF proof, and the page passes the session's
// step-up (none when the session has not stepped up, which the use case
// refuses as STEP_UP_REQUIRED).
func TestD53_AutomationEndpointActionsNeedThePagesStepUp(t *testing.T) {
	h, fake, mux := automationMux(t)
	for _, want := range []webhttp.Route{
		{Method: http.MethodGet, Path: "/automations/sources/{id}/confirm", Session: true},
		{Method: http.MethodPost, Path: "/automations/sources/{id}/activate", Session: true, CSRF: true},
		{Method: http.MethodPost, Path: "/automations/sources/{id}/rotate", Session: true, CSRF: true},
		{Method: http.MethodGet, Path: "/automations/destinations/{id}/confirm", Session: true},
		{Method: http.MethodPost, Path: "/automations/destinations/{id}/activate", Session: true, CSRF: true},
		{Method: http.MethodPost, Path: "/automations/destinations/{id}/rotate", Session: true, CSRF: true},
		{Method: http.MethodGet, Path: "/automations/{id}/start", Session: true},
		{Method: http.MethodPost, Path: "/automations/{id}/start", Session: true, CSRF: true},
	} {
		if !slices.Contains(h.Routes(), want) {
			t.Errorf("route %+v is not mounted", want)
		}
	}
	id := ids.NewV7().String()
	// No CSRF proof: refused before any use case runs.
	r := post("/automations/sources/" + id + "/activate")
	r.Header.Del(webhttp.CSRFHeader)
	if resp := do(t, mux, r); resp.StatusCode != http.StatusForbidden || len(fake.got) != 0 {
		t.Fatalf("without CSRF: %d, %d calls", resp.StatusCode, len(fake.got))
	}
	// A session without a step-up passes none: STEP_UP_REQUIRED.
	if resp := do(t, mux, post("/automations/sources/"+id+"/activate")); resp.StatusCode != http.StatusForbidden ||
		!strings.Contains(resp.Body, "step_up_required") || fake.got[0] != nil {
		t.Fatalf("without a step-up: %d %s", resp.StatusCode, resp.Body)
	}
	// A stepped-up session passes its key and time.
	for _, path := range []string{
		"/automations/sources/" + id + "/activate", "/automations/sources/" + id + "/rotate",
		"/automations/destinations/" + id + "/activate", "/automations/destinations/" + id + "/rotate",
	} {
		resp := do(t, mux, withCookie(post(path), "responder"))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, resp.Body)
		}
		su := fake.got[len(fake.got)-1]
		if su == nil || su.Credential != responderKey || !su.At.Equal(steppedUpAt) {
			t.Fatalf("%s: step-up %+v", path, su)
		}
		if strings.HasSuffix(path, "rotate") && !strings.Contains(resp.Body, "whsec_new") {
			t.Fatalf("%s: the new secret is not in the answer", path)
		}
	}
	// The start page posts declared values and the idempotency key.
	r = withCookie(post("/automations/"+id+"/start"), "responder")
	r.Body = httpBody(`{"params":{"ticket":"T-1"},"idempotency_key":"k1"}`)
	if resp := do(t, mux, r); resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, "ACCEPTED") {
		t.Fatalf("start: %d %s", resp.StatusCode, resp.Body)
	}
	if fake.start.IdempotencyKey != "k1" || fake.start.Params["ticket"] != "T-1" {
		t.Fatalf("start request: %+v", fake.start)
	}
	r = withCookie(post("/automations/"+id+"/start"), "responder")
	r.Body = httpBody(`{"params":{"ticket":"T-1"},"idempotency_key":"k1","agent":"x"}`)
	if resp := do(t, mux, r); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown member: %d", resp.StatusCode)
	}
}

func TestD53_AutomationPagesEscapeUntrustedText(t *testing.T) {
	_, _, mux := automationMux(t)
	id := ids.NewV7().String()
	for _, path := range []string{"/automations/sources/" + id + "/confirm", "/automations/destinations/" + id + "/confirm", "/automations/" + id + "/start"} {
		r := httptest.NewRequest(http.MethodGet, origin+path, nil)
		r.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: "good"})
		resp := do(t, mux, r)
		if resp.StatusCode != http.StatusOK || strings.Contains(resp.Body, "<script>alert") {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
		if !strings.Contains(resp.Body, "/static/automation_endpoints.js") {
			t.Fatalf("%s: no page script", path)
		}
	}
	r := httptest.NewRequest(http.MethodGet, origin+"/static/automation_endpoints.js", nil)
	if resp := do(t, mux, r); resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "javascript") {
		t.Fatalf("script: %d", resp.StatusCode)
	}
}
