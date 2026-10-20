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
	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/connections/pgmanifest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
)

// fakeManifests records what a confirmation received and refuses without
// a step-up, as the use case does.
type fakeManifests struct {
	steps   []*stepup.StepUp
	digests []string
}

func (f *fakeManifests) Get(_ context.Context, id ids.UUID) (pgmanifest.Manifest, error) {
	return pgmanifest.Manifest{
		Connection: id, Name: `warehouse<script>`, State: "ACTIVE", Digest: strings.Repeat("cd", 32),
		Proposed: &capp.PostgresConfig{
			Host: "db.example.test", Port: 5432, Database: "shop", User: "reader", SSLMode: "verify-full",
			Tables: []capp.PostgresTable{{Schema: "shop", Name: "customers", Columns: []capp.PostgresColumn{{Name: "id", Type: "bigint", Class: "public"}}}},
		},
		Widening: []string{"a first configuration: the connection serves nothing until it is confirmed"},
	}, nil
}

func (f *fakeManifests) Confirm(_ context.Context, _ ids.UUID, digest string, su *stepup.StepUp) error {
	f.steps, f.digests = append(f.steps, su), append(f.digests, digest)
	if su == nil {
		return stepup.ErrStepUp
	}
	return nil
}

// TestD84_PostgresManifestConfirmationNeedsThePagesStepUp: the confirm page
// is a session route, its POST needs the CSRF proof, passes the session's
// step-up (refused without one) and the digest the page showed, and the
// page escapes the connection's name.
func TestD84_PostgresManifestConfirmationNeedsThePagesStepUp(t *testing.T) {
	h, _, mux := newHandler(t, origin)
	fake := &fakeManifests{}
	m := mux.(*http.ServeMux)
	h.MountPostgresManifests(m, fake)
	for _, want := range []webhttp.Route{
		{Method: http.MethodGet, Path: "/connections/{id}/postgres/confirm", Session: true},
		{Method: http.MethodPost, Path: "/connections/{id}/postgres/confirm", Session: true, CSRF: true},
	} {
		if !slices.Contains(h.Routes(), want) {
			t.Errorf("route %+v is not mounted", want)
		}
	}
	id := ids.NewV7().String()
	path := "/connections/" + id + "/postgres/confirm?digest=" + strings.Repeat("cd", 32)
	r := post(path)
	r.Header.Del(webhttp.CSRFHeader)
	if resp := do(t, m, r); resp.StatusCode != http.StatusForbidden || len(fake.steps) != 0 {
		t.Fatalf("without CSRF: %d, %d calls", resp.StatusCode, len(fake.steps))
	}
	if resp := do(t, m, post(path)); resp.StatusCode != http.StatusForbidden || !strings.Contains(resp.Body, "step_up_required") || fake.steps[0] != nil {
		t.Fatalf("without a step-up: %d %s", resp.StatusCode, resp.Body)
	}
	resp := do(t, m, withCookie(post(path), "responder"))
	if su := fake.steps[len(fake.steps)-1]; resp.StatusCode != http.StatusOK || su == nil || su.Credential != responderKey ||
		fake.digests[len(fake.digests)-1] != strings.Repeat("cd", 32) {
		t.Fatalf("stepped up: %d %s %+v", resp.StatusCode, resp.Body, su)
	}
	page := httptest.NewRequest(http.MethodGet, origin+"/connections/"+id+"/postgres/confirm", nil)
	page.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: "good"})
	if resp := do(t, m, page); resp.StatusCode != http.StatusOK || strings.Contains(resp.Body, "warehouse<script>") ||
		!strings.Contains(resp.Body, "shop.customers") {
		t.Fatalf("page: %d", resp.StatusCode)
	}
	bad := httptest.NewRequest(http.MethodGet, origin+"/connections/nope/postgres/confirm", nil)
	bad.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: "good"})
	if resp := do(t, m, bad); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a bad id: %d", resp.StatusCode)
	}
}
