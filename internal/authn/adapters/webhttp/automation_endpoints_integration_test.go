// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package webhttp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/triggers"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/endpoints"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/triggerstest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// automationBrowser signs in the fixture's person as an automation author
// and operator; "stepped" has stepped up with their key just now.
type automationBrowser struct {
	fakeBrowser
	f *triggerstest.Fixture
}

func (b *automationBrowser) Authenticate(_ context.Context, cookie string) (authnapp.BrowserSession, error) {
	if cookie != "author" && cookie != "stepped" {
		return authnapp.BrowserSession{}, authnapp.ErrUnauthenticated
	}
	scope := td.Scope{Type: td.ScopeOrg, ID: b.f.Org.UUID()}
	s := authnapp.BrowserSession{
		Caller: tapp.Caller{
			Subject: td.Subject{Org: b.f.Org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: b.f.User}, Bindings: []td.Binding{
				{Role: td.RoleAutomationAuthor, Scope: scope}, {Role: td.RoleAutomationOperator, Scope: scope},
			}},
			Credential: authnapp.CredBrowserSession,
		},
		ID: ids.NewV7(),
	}
	if cookie == "stepped" {
		s.StepUpCredential, s.StepUpAt = b.f.Cred, time.Now()
	}
	return s, nil
}

type realAutomationPages struct {
	trig *triggers.Service
	ep   *endpoints.Service
}

func (p realAutomationPages) EventSource(ctx context.Context, id ids.UUID) (endpoints.Source, error) {
	return p.ep.GetEventSource(ctx, id)
}

func (p realAutomationPages) ActivateEventSource(ctx context.Context, id ids.UUID, su *stepup.StepUp) (endpoints.Source, error) {
	return p.ep.ActivateEventSource(ctx, id, su)
}

func (p realAutomationPages) RotateEventSourceSecret(ctx context.Context, id ids.UUID, su *stepup.StepUp) (string, error) {
	return p.ep.RotateEventSourceSecret(ctx, id, su)
}

func (p realAutomationPages) Destination(ctx context.Context, id ids.UUID) (endpoints.Destination, error) {
	return p.ep.GetDestination(ctx, id)
}

func (p realAutomationPages) ActivateDestination(ctx context.Context, id ids.UUID, su *stepup.StepUp) (endpoints.Destination, error) {
	return p.ep.ActivateDestination(ctx, id, su)
}

func (p realAutomationPages) RotateDestinationSecret(ctx context.Context, id ids.UUID, su *stepup.StepUp) (string, error) {
	return p.ep.RotateDestinationSecret(ctx, id, su)
}

func (p realAutomationPages) Form(ctx context.Context, id ids.UUID) (triggers.ManualForm, error) {
	return p.trig.Form(ctx, id)
}

func (p realAutomationPages) StartExecution(ctx context.Context, in triggers.ManualStart, su *stepup.StepUp) (triggers.Outcome, error) {
	return p.trig.StartExecution(ctx, in, su)
}

// TestHR275_SourcesActivateOnlyOnThePageWithAStepUp: the API cannot
// activate a source or start a step-up version (STEP_UP_REQUIRED); the
// page does, with the session's fresh step-up checked against the
// person's own key by the database clock (D53).
func TestHR275_SourcesActivateOnlyOnThePageWithAStepUp(t *testing.T) {
	f := triggerstest.New(t)
	st := &triggerstest.Starter{}
	trig := triggers.New(triggers.Deps{Pool: f.Pool, Starter: st, Editions: triggerstest.Team})
	ep, err := endpoints.New(f.Pool, f.Envelope, trig, triggerstest.Team, endpoints.Config{PublicURL: origin}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := &automationBrowser{f: f}
	h, err := webhttp.New(b, origin, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.Mount(mux)
	h.MountAutomationEndpoints(mux, realAutomationPages{trig: trig, ep: ep})

	author := f.As(td.KindUser, td.RoleAutomationAuthor)
	c, err := ep.CreateEventSource(author, endpoints.NewSource{Name: "support", Types: []string{"ticket.created"}})
	if err != nil {
		t.Fatal(err)
	}
	src := c.Source.ID.String()
	// Over the API (no step-up): refused.
	if _, err := ep.ActivateEventSource(author, c.Source.ID, nil); !stepup.Is(err) {
		t.Fatalf("API activation: %v", err)
	}
	page := httptest.NewRequest(http.MethodGet, origin+"/automations/sources/"+src+"/confirm?org="+url.QueryEscape(f.Org.String()), nil)
	page.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: "author"})
	if resp := do(t, mux, page); resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, "Activate with your security key") {
		t.Fatalf("page: %d", resp.StatusCode)
	}
	// The page without a step-up: refused.
	if resp := do(t, mux, withCookie(post("/automations/sources/"+src+"/activate"), "author")); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("no step-up: %d %s", resp.StatusCode, resp.Body)
	}
	// With one: ACTIVE, activated with that key.
	if resp := do(t, mux, withCookie(post("/automations/sources/"+src+"/activate"), "stepped")); resp.StatusCode != http.StatusOK {
		t.Fatalf("stepped up: %d %s", resp.StatusCode, resp.Body)
	}
	got, err := ep.GetEventSource(author, c.Source.ID)
	if err != nil || got.State != endpoints.StateActive || got.ActivatedCredential == nil || *got.ActivatedCredential != f.Cred {
		t.Fatalf("source: %+v %v", got, err)
	}
	// Rotation on the page returns the new secret once.
	resp := do(t, mux, withCookie(post("/automations/sources/"+src+"/rotate"), "stepped"))
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, "whsec_") {
		t.Fatalf("rotate: %d %s", resp.StatusCode, resp.Body)
	}

	// A manual version that requires a step-up starts only on the page.
	a := f.Automation(t, "refunds", f.Definition(`"manual":{"step_up":true,"params":{"ticket":{"type":"string","pattern":"T-[0-9]+"}}}`, ""),
		autodomain.RolloutFull)
	op := f.As(td.KindUser, td.RoleAutomationOperator)
	if _, err := trig.StartExecution(op, triggers.ManualStart{Automation: a.ID, Params: map[string]string{"ticket": "T-1"}, IdempotencyKey: "k"}, nil); !stepup.Is(err) {
		t.Fatalf("API start of a step-up version: %v", err)
	}
	r := withCookie(post("/automations/"+a.ID.String()+"/start"), "stepped")
	r.Body = httpBody(`{"params":{"ticket":"T-1"},"idempotency_key":"k"}`)
	if resp := do(t, mux, r); resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, "ACCEPTED") {
		t.Fatalf("page start: %d %s", resp.StatusCode, resp.Body)
	}
	if st.Count() != 1 {
		t.Fatalf("starts: %d", st.Count())
	}
	if n := f.Count(t, "SELECT count(*) FROM pc.automation_triggers WHERE org_id = $1 AND authenticity = 'USER_STEP_UP' AND authenticity_detail ->> 'credential' = $2", f.Cred.String()); n != 1 {
		t.Fatal("the start does not record the security key")
	}
}

func (p realAutomationPages) RetryExecution(ctx context.Context, id ids.UUID, idem string, su *stepup.StepUp) (triggers.Outcome, error) {
	return p.trig.RetryExecution(ctx, id, idem, su)
}
