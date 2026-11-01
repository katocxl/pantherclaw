// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	credapp "github.com/katocxl/pantherclaw/internal/credentials/app"
	creddomain "github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/protect"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// rotationBrowser signs in a person who may rotate ("person"), the same
// person after a step-up ("stepped"), or a viewer ("viewer").
type rotationBrowser struct {
	fakeBrowser
	key ids.UUID
	// roles are the person's roles; none means gateway admin.
	roles []td.RoleName
}

func (b *rotationBrowser) Authenticate(_ context.Context, cookie string) (authnapp.BrowserSession, error) {
	roles := b.roles
	if len(roles) == 0 {
		roles = []td.RoleName{td.RoleGatewayAdmin}
	}
	if cookie == "viewer" {
		roles = []td.RoleName{td.RoleViewer}
	}
	bindings := make([]td.Binding, 0, len(roles))
	for _, role := range roles {
		bindings = append(bindings, td.Binding{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: testOrg.UUID()}})
	}
	s := authnapp.BrowserSession{
		Caller: tapp.Caller{
			Subject:    td.Subject{Org: testOrg, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()}, Bindings: bindings},
			Credential: authnapp.CredBrowserSession,
		},
		ID: ids.NewV7(),
	}
	if cookie == "stepped" {
		s.StepUpCredential, s.StepUpAt = b.key, time.Now()
	}
	return s, nil
}

// fakeRotations refuses what has no step-up, as the use cases do, and holds
// when told to.
type fakeRotations struct {
	row    credapp.Rotation
	su     stepup.StepUp
	reason string
	held   bool
}

func (f *fakeRotations) GetRotation(context.Context, ids.UUID) (credapp.Rotation, error) {
	return f.row, nil
}

func (f *fakeRotations) gate(su stepup.StepUp) error {
	f.su = su
	if su.Credential.IsZero() {
		return stepup.ErrStepUp
	}
	if f.held {
		return &protect.PendingError{Change: ids.NewV7(), Request: ids.NewV7()}
	}
	return nil
}

func (f *fakeRotations) ActivateRotation(_ context.Context, _ ids.UUID, su stepup.StepUp) (credapp.Rotation, error) {
	return f.row, f.gate(su)
}

func (f *fakeRotations) RollBackRotation(_ context.Context, _ ids.UUID, reason string, su stepup.StepUp) (credapp.Rotation, error) {
	f.reason = reason
	return f.row, f.gate(su)
}

func rotationBody(r *http.Request, body string) *http.Request {
	r.Body = httpBody(body)
	return r
}

// TestHR553_TheRotationPageCarriesTheSessionsStepUp: activating and rolling
// back reach the use case with this session's own step-up, a missing one is
// refused, and a change the org protects says it waits for a second person.
//
// Covers: F831
func TestHR553_TheRotationPageCarriesTheSessionsStepUp(t *testing.T) {
	key := ids.NewV7()
	passed := time.Now()
	fake := &fakeRotations{row: credapp.Rotation{ID: ids.NewV7(), State: string(creddomain.RotationTesting), TestPassedAt: &passed, CreatedAt: passed}}
	h, err := webhttp.New(&rotationBrowser{key: key}, origin, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.WithCredentialRotations(fake)
	mux := http.NewServeMux()
	h.Mount(mux)
	path := webhttp.CredentialRotationsPath + "/" + fake.row.ID.String()

	view := func(cookie string) string {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, origin+path, nil)
		r.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: cookie})
		resp := do(t, mux, r)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("page: %d %s", resp.StatusCode, resp.Body)
		}
		return resp.Body
	}
	if body := view("person"); !strings.Contains(body, "Activate with your security key") || strings.Contains(body, "Roll back with") {
		t.Fatalf("a tested rotation's page: %s", body)
	}
	if body := view("viewer"); strings.Contains(body, "with your security key") {
		t.Fatalf("a viewer is offered an action: %s", body)
	}

	if resp := do(t, mux, withCookie(post(path+"/activate"), "person")); resp.StatusCode != http.StatusForbidden || !strings.Contains(resp.Body, "step_up_required") {
		t.Fatalf("no step-up: %d %s", resp.StatusCode, resp.Body)
	}
	if resp := do(t, mux, withCookie(post(path+"/activate"), "stepped")); resp.StatusCode != http.StatusOK || fake.su.Credential != key {
		t.Fatalf("stepped up: %d %s, %+v", resp.StatusCode, resp.Body, fake.su)
	}

	fake.row.State = string(creddomain.RotationActivating)
	if body := view("person"); !strings.Contains(body, "Roll back with your security key") || strings.Contains(body, "Activate with") {
		t.Fatalf("an activated rotation's page: %s", body)
	}
	back := func() *http.Request {
		return rotationBody(withCookie(post(path+"/rollback"), "stepped"), `{"reason":"dispatches fail"}`)
	}
	if resp := do(t, mux, back()); resp.StatusCode != http.StatusOK || fake.reason != "dispatches fail" {
		t.Fatalf("rollback: %d %s, %q", resp.StatusCode, resp.Body, fake.reason)
	}
	fake.held = true
	if resp := do(t, mux, back()); resp.StatusCode != http.StatusConflict || !strings.Contains(resp.Body, "protected_change_pending") {
		t.Fatalf("held: %d %s", resp.StatusCode, resp.Body)
	}
}
