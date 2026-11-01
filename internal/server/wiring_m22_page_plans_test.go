// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// statusGate is the plan gate of an org in one status, by the real class table.
type statusGate struct {
	status entitlements.Status
	asked  *[]string
}

func (g statusGate) Check(_ context.Context, _ ids.OrgID, procedure string) error {
	*g.asked = append(*g.asked, procedure)
	if !entitlements.Allows(g.status, procedureClass(procedure)) {
		return entitlements.ErrPlanRequired
	}
	return nil
}

// plainSessions leaves every session as it is.
type plainSessions struct{ webhttp.BreakGlass }

func (plainSessions) BreakGlassCall(_ context.Context, c tapp.Caller, _ string) (tapp.Caller, error) {
	return c, nil
}

// allPages mounts every page group over nil use cases: the refusal comes
// before any is called.
func allPages(t *testing.T, h *webhttp.Handler, mux *http.ServeMux) {
	t.Helper()
	h.WithKeys(struct{ webhttp.Keys }{}).
		WithContainment(struct{ webhttp.Containment }{}).
		WithApprovals(struct{ webhttp.Approvals }{}, struct{ webhttp.Bindings }{}).
		WithReconciliations(struct{ webhttp.Reconciliations }{}, struct{ webhttp.Bindings }{}).
		WithPolicyChanges(struct{ webhttp.PolicyChanges }{}, struct{ webhttp.Bindings }{}).
		WithChanges(struct{ webhttp.Changes }{}, struct{ webhttp.Bindings }{}).
		WithPlaybook(struct{ webhttp.PlaybookRequests }{}, struct{ webhttp.Bindings }{}).
		WithIntegrations(struct{ webhttp.Integrations }{}).
		WithExportDestinations(struct{ webhttp.ExportDestinations }{}).
		WithExportSecrets(struct{ webhttp.ExportSecrets }{}).
		WithIdentityProviderSecrets(struct {
			webhttp.IdentityProviderSecrets
		}{}).
		WithCredentialRotations(struct{ webhttp.CredentialRotations }{}).
		WithModelDrafting(struct{ webhttp.ModelDrafting }{}).
		WithPromotions(struct{ webhttp.Promotions }{}).
		WithProtect(struct{ webhttp.Protect }{}).
		WithSlackChannels(struct{ webhttp.SlackChannels }{}).
		WithTeamsChannels(struct{ webhttp.TeamsChannels }{})
	h.Mount(mux)
	h.MountA2APins(mux, struct{ webhttp.A2APins }{})
	h.MountAutomationEndpoints(mux, struct{ webhttp.AutomationEndpoints }{})
	h.MountBreakGlass(mux, plainSessions{})
	h.MountEnforcementPoints(mux, struct{ webhttp.EnforcementPoints }{})
	h.MountExternalChecks(mux, struct{ webhttp.ExternalChecks }{})
	h.MountPostgresManifests(mux, struct{ webhttp.PostgresManifests }{})
	h.MountSupportAccess(mux, struct{ webhttp.SupportAccess }{})
}

// sendPost posts to a page and reports its answer; a panic is a nil use case
// reached, which means the gate let it through.
func sendPost(mux *http.ServeMux, path string) (code int, body string) {
	defer func() {
		if recover() != nil {
			code, body = 0, "reached the page"
		}
	}()
	req := httptest.NewRequest(http.MethodPost, uiWebOrigin+path, strings.NewReader("{}"))
	req.Header.Set("Origin", uiWebOrigin)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set(webhttp.CSRFHeader, "1")
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "pc_session", Value: "good"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

var pathValue = regexp.MustCompile(`\{[a-z]+\}`)

// TestEveryStateChangingPageNamesItsProcedure (G0 M22 D77, D80, HR-356): a lapsed
// org is refused on a page that stands in for a change and keeps the safety
// pages, an org with no plan keeps only the allow list and the open pages,
// and no state-changing page goes unnamed.
func TestEveryStateChangingPageNamesItsProcedure(t *testing.T) {
	seen := 0
	for _, status := range []entitlements.Status{entitlements.StatusLapsed, entitlements.StatusNone} {
		var asked []string
		h, _ := uiWebHandler(t)
		h.WithPlanGate(statusGate{status: status, asked: &asked})
		mux := http.NewServeMux()
		allPages(t, h, mux)
		seen = 0
		for _, rt := range h.Routes() {
			if !rt.CSRF || !rt.Session {
				continue
			}
			seen++
			t.Run(string(status)+rt.Path, func(t *testing.T) {
				plan, named := webhttp.PagePlanOf(rt.Path)
				if !named {
					t.Fatal("this page names no procedure")
				}
				if plan.Open != "" && plan.Procedure != "" {
					t.Fatal("a page is either open or names a procedure")
				}
				if plan.Open == "" && plan.Procedure != webhttp.ChangePage && procedureClass(plan.Procedure) == entitlements.ClassUnknown {
					t.Fatalf("%s is not a classified procedure", plan.Procedure)
				}
				want := plan.Open == "" && !entitlements.Allows(status, procedureClass(plan.Procedure))
				path := pathValue.ReplaceAllString(rt.Path, ids.NewV7().String())
				asked = nil
				code, body := sendPost(mux, path)
				if refused := code == http.StatusConflict && strings.Contains(body, "plan_required"); refused != want {
					t.Fatalf("refusal wanted %v: %d %s", want, code, body)
				}
				if plan.Open != "" && len(asked) != 0 {
					t.Fatalf("an open page asked the gate: %v", asked)
				}
				if plan.Open == "" && (len(asked) != 1 || asked[0] != plan.Procedure) {
					t.Fatalf("asked the gate %v, want %s", asked, plan.Procedure)
				}
			})
		}
	}

	// Every registration in the package is in the walk above, so a new page
	// group has to join allPages.
	sources, err := filepath.Glob("../authn/adapters/webhttp/*.go")
	if err != nil {
		t.Fatal(err)
	}
	mounted := 0
	registration := regexp.MustCompile(`\.withSession\(\w+, http\.MethodPost,`)
	for _, f := range sources {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		mounted += len(registration.FindAll(b, -1))
	}
	if seen != mounted {
		t.Fatalf("walked %d state-changing pages of %d registered", seen, mounted)
	}
}

// TestNoGateRefusesNoPage (G0 M22 D77): without a gate the pages behave as
// with billing.require_plan off.
func TestNoGateRefusesNoPage(t *testing.T) {
	h, _ := uiWebHandler(t)
	mux := http.NewServeMux()
	allPages(t, h, mux)
	path := webhttp.ExportDestinationsPath + "/new"
	if code, body := sendPost(mux, path); strings.Contains(body, "plan_required") {
		t.Fatalf("%d %s", code, body)
	}
}
