// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// m33PathSHA is a page compare's path digest (sha256 hex).
const m33PathSHA = "3333333333333333333333333333333333333333333333333333333333333333"

// TestE2E_M33_BrowserAndComputerUse is the M33 exit scenario (G0 M33),
// through the native host the managed extension talks to:
//   - a navigation on a listed site is allowed, and one on an unlisted site
//     is held for a person (FQ33-2); once bob approves, the same call with
//     the same action id is allowed;
//   - a form submit with a password field is refused at the gateway before
//     the Authority is asked (FQ33-4), and a person takes the tab over: the
//     takeover holds even on a listed site, and is allowed once approved;
//   - a computer-use action is decided through the computer hook;
//   - the cloaking compare only alerts (FQ33-3): the navigation on a compare
//     site is allowed whatever the compare finds, and the gateway's report
//     is recorded as digests and numbers only, once an hour.
func TestE2E_M33_BrowserAndComputerUse(t *testing.T) {
	bs := startBrowserStack(t)
	bs.listBrowserSites(t, m33Site{host: "docs.example.com"}, m33Site{host: "shop.example.com", subdomains: true, compare: true})
	host := bs.startHost(t, "browser")
	if st := host.send(map[string]any{"type": "status"}); !st.OK || st.Run != bs.run {
		t.Fatalf("host status: %+v", st)
	}

	// A listed site.
	if r := host.navigate(ids.NewV7().String(), "nav-listed", "https://docs.example.com/guide?q=1"); r.Decision != "allow" || r.Held {
		t.Fatalf("listed navigation: %+v", r)
	}
	// An unlisted site holds; the approved repeat is allowed.
	act := ids.NewV7().String()
	held := host.navigate(act, "nav-unlisted", "https://unlisted.example.net/login")
	if held.Decision != "deny" || !held.Held || held.TransactionID == "" {
		t.Fatalf("unlisted navigation: %+v", held)
	}
	if got := bs.reasonOf(t, held.TransactionID); got != pipeline.ReasonSiteNotListed {
		t.Fatalf("unlisted navigation reason %s", got)
	}
	if st := bs.approveBrowser(t, held.TransactionID, "browser.navigate"); st != `"APPROVED"` {
		t.Fatalf("approval state %s", st)
	}
	again := host.navigate(act, "nav-unlisted", "https://unlisted.example.net/login")
	if again.Decision != "allow" || again.TransactionID != held.TransactionID {
		t.Fatalf("approved navigation asked again: %+v (held %s)", again, held.TransactionID)
	}

	// A form with a password field is refused before the Authority is asked.
	before := bs.txnCount(t)
	secret := host.decide("browser_submit", ids.NewV7().String(), map[string]any{
		"url": "https://docs.example.com/session", "page_url": "https://docs.example.com/login", "method": "post",
		"fields": []string{"user", "password"}, "secret_fields": true, "call": "submit-secret",
	})
	if secret.Decision != "deny" || secret.Held || secret.Code != dispatch.CodeBrowserSecretField ||
		!strings.Contains(secret.Reason, "take over this tab") {
		t.Fatalf("secret submit: %+v", secret)
	}
	if n := bs.txnCount(t); n != before {
		t.Fatalf("the secret submit made %d transactions", n-before)
	}
	bs.waitLedger(t, auditkind.ConnectionBrowserSecretFieldRefused, 1)
	// A form without one, on a listed site, is allowed.
	if r := host.decide("browser_submit", ids.NewV7().String(), map[string]any{
		"url": "https://docs.example.com/search", "page_url": "https://docs.example.com/", "method": "get",
		"fields": []string{"q"}, "secret_fields": false, "call": "submit-plain",
	}); r.Decision != "allow" {
		t.Fatalf("plain submit: %+v", r)
	}

	// The takeover: a person types the password. It holds on a listed site.
	tact := ids.NewV7().String()
	takeover := map[string]any{"page_url": "https://docs.example.com/login", "minutes": 10, "call": "takeover-1"}
	tk := host.decide("browser_takeover", tact, takeover)
	if tk.Decision != "deny" || !tk.Held || bs.reasonOf(t, tk.TransactionID) != pipeline.ReasonBrowserTakeover {
		t.Fatalf("takeover: %+v", tk)
	}
	if st := bs.approveBrowser(t, tk.TransactionID, "browser.takeover"); st != `"APPROVED"` {
		t.Fatalf("takeover approval %s", st)
	}
	if r := host.decide("browser_takeover", tact, takeover); r.Decision != "allow" || r.TransactionID != tk.TransactionID {
		t.Fatalf("approved takeover asked again: %+v", r)
	}

	// A computer-use action, through the computer hook.
	computer := bs.startHost(t, "computer")
	if r := computer.decide("computer", ids.NewV7().String(), map[string]any{
		"kind": "click", "button": "left", "x": 120, "y": 40, "call": "toolu_e2e_click",
	}); r.Decision != "allow" || r.TransactionID == "" {
		t.Fatalf("computer click: %+v", r)
	}
	if r := computer.decide("computer", ids.NewV7().String(), map[string]any{"kind": "teleport", "call": "toolu_e2e_bad"}); r.Decision != "deny" {
		t.Fatalf("an unknown computer action: %+v", r)
	}

	// The cloaking compare alerts only: the navigation on a compare site is
	// allowed (the gateway cannot fetch the page from here, which only
	// counts), and its report is recorded once an hour, digests only.
	if r := host.navigate(ids.NewV7().String(), "nav-compare", "https://www.shop.example.com/item/7"); r.Decision != "allow" {
		t.Fatalf("compare-site navigation: %+v", r)
	}
	ctl := bs.gatewayControl(t)
	ctx := context.Background()
	for range 2 {
		if _, err := ctl.Gateway.ReportPageCompare(ctx, bs.pageCompare("www.shop.example.com", m33PathSHA)); err != nil {
			t.Fatalf("ReportPageCompare: %v", err)
		}
	}
	bs.waitLedger(t, auditkind.BrowserCloakingSuspected, 1)
	if n := bs.ledgerCount(t, auditkind.BrowserCloakingSuspected); n != 1 {
		t.Fatalf("%d cloaking entries for one page in an hour, want 1", n)
	}
	if _, err := ctl.Gateway.ReportPageCompare(ctx, bs.pageCompare("docs.example.com", m33PathSHA)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("a report for a site not marked for the compare: %v", err)
	}
	if body := bs.row(t, `SELECT convert_from(body, 'UTF8') FROM pc.ledger_entries WHERE org_id = $1 AND kind = $2`,
		bs.org, "audit."+auditkind.BrowserCloakingSuspected); !strings.Contains(body, m33PathSHA) || !strings.Contains(body, "120") {
		t.Fatalf("cloaking entry %s", body)
	}
	// Still allowed after the report: the compare never holds or blocks.
	if r := host.navigate(ids.NewV7().String(), "nav-compare-2", "https://www.shop.example.com/item/7"); r.Decision != "allow" {
		t.Fatalf("compare-site navigation after a report: %+v", r)
	}
}
