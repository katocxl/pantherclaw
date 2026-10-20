// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webguard"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// connect sends one Connect JSON call from the browser the way the
// console does: same origin, PC-CSRF: 1, its session cookie from the jar.
func (b *browser) connect(t *testing.T, procedure, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, b.s.url+procedure, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(webguard.CSRFHeader, "1")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Origin", b.s.url)
	res, err := b.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(out)
}

// TestHR347_TheConsoleUsesTheAPIWithItsSession (G0 UI D11, D21): a person
// signed in in a browser calls the Connect API with the session cookie
// alone. WhoAmI reports an org browser session and the deployment; a
// change made that way is audited with auth_kind browser_session; the
// same call from another site is refused and changes nothing.
func TestHR347_TheConsoleUsesTheAPIWithItsSession(t *testing.T) {
	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", people: &p})
	people := &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p}
	org := s.org.String()
	var out, errb bytes.Buffer
	if code := runServerCmd(&out, &errb, "org", "admin-invite", "--config", s.serverCfg, "--org", org); code != 0 {
		t.Fatalf("org admin-invite: %d %s", code, errb.String())
	}
	alice := people.user(t, "alice", "alice@example.test")
	alice.login(t, org, pciToken.FindStringSubmatch(out.String())[1])
	b := newBrowser(people)
	b.signIn(t, org, "alice", "alice@example.test", false)

	code, body := b.connect(t, pantherclawv1connect.AccessServiceWhoAmIProcedure, "{}")
	for _, want := range []string{`"credential":"browser_session"`, `"sessionKind":"CALLER_SESSION_KIND_ORG_BROWSER"`,
		`"deployment":"DEPLOYMENT_DEVELOPMENT"`, org} {
		if code != http.StatusOK || !strings.Contains(body, want) {
			t.Fatalf("WhoAmI = %d %s, want %s", code, body, want)
		}
	}
	if code, body := b.connect(t, pantherclawv1connect.TenancyServiceUpdateOrgProcedure, `{"name":"Renamed from the console"}`); code != http.StatusOK {
		t.Fatalf("UpdateOrg = %d %s", code, body)
	}
	got := s.row(t, `SELECT convert_from(body, 'UTF8') FROM pc.ledger_entries WHERE kind = 'audit.tenancy.org_updated'
		ORDER BY occurred_at DESC LIMIT 1`)
	if !strings.Contains(got, `"auth_kind":"browser_session"`) {
		t.Fatalf("org_updated audit body %s lacks auth_kind", got)
	}

	// Another site's page sends the same change with the cookie.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, b.s.url+pantherclawv1connect.TenancyServiceUpdateOrgProcedure,
		strings.NewReader(`{"name":"Renamed by an attacker"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(webguard.CSRFHeader, "1")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Origin", "https://attacker.example")
	res, err := b.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode == http.StatusOK {
		t.Fatal("a cross-site call with the session cookie was accepted")
	}
	if name := s.row(t, "SELECT name FROM pc.orgs WHERE id = $1", s.org); name != "Renamed from the console" {
		t.Fatalf("org name %q after the cross-site call", name)
	}
}
