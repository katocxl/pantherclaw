// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	"github.com/katocxl/pantherclaw/internal/exports"
	"github.com/katocxl/pantherclaw/internal/idps"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// fakeSecrets refuses what has no step-up, as the use cases do, and keeps
// what reached it.
type fakeSecrets struct {
	dest  exports.NewDestination
	cred  exports.Credential
	input idps.Input
	calls int
}

func (f *fakeSecrets) gate(su stepup.StepUp) error {
	f.calls++
	if su.Credential.IsZero() {
		return stepup.ErrStepUp
	}
	return nil
}

func (f *fakeSecrets) CreateOnPage(_ context.Context, in exports.NewDestination, su stepup.StepUp) (exports.Destination, error) {
	f.dest = in
	return exports.Destination{ID: ids.NewV7(), State: exports.StatePending}, f.gate(su)
}

func (f *fakeSecrets) ReplaceCredentialOnPage(_ context.Context, id ids.UUID, c exports.Credential, su stepup.StepUp) (exports.Destination, error) {
	f.cred = c
	return exports.Destination{ID: id, State: exports.StatePending}, f.gate(su)
}

func (f *fakeSecrets) Get(_ context.Context, id ids.UUID) (exports.Destination, error) {
	return exports.Destination{ID: id, Name: "dest", Kind: "https_put", State: exports.StatePending}, nil
}

func (f *fakeSecrets) Activate(context.Context, ids.UUID, stepup.StepUp) (exports.Destination, error) {
	return exports.Destination{}, nil
}

type fakeProviders struct {
	fakeSecrets
}

func (f *fakeProviders) CreateOnPage(_ context.Context, in idps.Input, su stepup.StepUp) (idps.Provider, idps.Filed, error) {
	f.input = in
	return idps.Provider{ID: ids.NewV7(), State: "PENDING"}, idps.Filed{Change: ids.NewV7(), Request: ids.NewV7()}, f.gate(su)
}

// TestSecretPagesKeepTheSessionStepUpAndPermission (G0 M22 D57): each form posts its
// secret to the core's own page: a viewer sees no form and is refused before
// the use case, a person needs a step-up and the CSRF proof, and no answer
// repeats the secret.
func TestSecretPagesKeepTheSessionStepUpAndPermission(t *testing.T) {
	const token = "tok-not-to-be-repeated"
	key := ids.NewV7()
	secrets, providers := &fakeSecrets{}, &fakeProviders{}
	h, err := webhttp.New(&rotationBrowser{key: key, roles: []td.RoleName{td.RoleSecurityAdmin, td.RoleOrgAdmin}}, origin, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.WithExportDestinations(secrets).WithExportSecrets(secrets).WithIdentityProviderSecrets(providers)
	mux := http.NewServeMux()
	h.Mount(mux)

	dest := ids.NewV7().String()
	for _, c := range []struct {
		name, path, body string
		form             string
		calls            func() int
		saw              func() string
	}{
		{
			name: "create destination", path: webhttp.ExportDestinationsPath + "/new", form: `id="bearer_token"`,
			body:  `{"name":"d","kind":"https_put","url":"https://x.test","data_classes":["audit"],"bearer_token":"` + token + `"}`,
			calls: func() int { return secrets.calls }, saw: func() string { return secrets.dest.Credential.BearerToken },
		},
		{
			name: "replace credential", path: webhttp.ExportDestinationsPath + "/" + dest + "/credential", form: `id="bearer_token"`,
			body:  `{"bearer_token":"` + token + `"}`,
			calls: func() int { return secrets.calls }, saw: func() string { return secrets.cred.BearerToken },
		},
		{
			name: "create provider", path: webhttp.IdentityProvidersPath + "/new", form: `id="client_secret"`,
			body:  `{"name":"p","issuer":"https://i.test","client_id":"c","client_secret":"` + token + `"}`,
			calls: func() int { return providers.calls }, saw: func() string { return string(providers.input.ClientSecret.Reveal()) },
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			view := func(cookie string) string {
				t.Helper()
				r := httptest.NewRequest(http.MethodGet, origin+c.path, nil)
				r.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: cookie})
				resp := do(t, mux, r)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("page: %d %s", resp.StatusCode, resp.Body)
				}
				return resp.Body
			}
			if !strings.Contains(view("person"), c.form) {
				t.Fatal("a person sees no form")
			}
			if strings.Contains(view("viewer"), c.form) {
				t.Fatal("a viewer sees the form")
			}

			before := c.calls()
			send := func(cookie string) *http.Request { return rotationBody(withCookie(post(c.path), cookie), c.body) }
			if resp := do(t, mux, send("viewer")); resp.StatusCode != http.StatusForbidden || !strings.Contains(resp.Body, "forbidden") || c.calls() != before {
				t.Fatalf("without the permission: %d %s, %d calls", resp.StatusCode, resp.Body, c.calls()-before)
			}
			if resp := do(t, mux, send("person")); resp.StatusCode != http.StatusForbidden || !strings.Contains(resp.Body, "step_up_required") {
				t.Fatalf("no step-up: %d %s", resp.StatusCode, resp.Body)
			}
			noCSRF := send("stepped")
			noCSRF.Header.Del(webhttp.CSRFHeader)
			calls := c.calls()
			if resp := do(t, mux, noCSRF); resp.StatusCode == http.StatusOK || c.calls() != calls {
				t.Fatalf("no CSRF proof: %d", resp.StatusCode)
			}
			resp := do(t, mux, send("stepped"))
			if resp.StatusCode != http.StatusOK || c.saw() != token {
				t.Fatalf("stepped up: %d %s, saw %q", resp.StatusCode, resp.Body, c.saw())
			}
			if strings.Contains(resp.Body, token) {
				t.Fatalf("the answer repeats the secret: %s", resp.Body)
			}
		})
	}
}
