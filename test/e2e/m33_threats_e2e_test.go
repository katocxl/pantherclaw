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

// The M33 threats (THREAT_MODEL T-340..T-344), through the native host the
// managed extension talks to.

// TestT340_AnAgentLuredToAnAttackerPageIsHeld: a page on a site nobody
// listed, a look-alike name, an IP address and a link carrying a listed
// name as userinfo never open without a person; an approval of one held
// page lets that call through and no other.
func TestT340_AnAgentLuredToAnAttackerPageIsHeld(t *testing.T) {
	bs := startBrowserStack(t)
	bs.listBrowserSites(t, m33Site{host: "docs.example.com"})
	host := bs.startHost(t, "browser")
	for _, url := range []string{
		"https://prize-claim.example.net/win", "https://docs.example.com.prize-claim.example.net/", "http://203.0.113.7/",
		"https://login-docs.example.com/",
	} {
		r := host.navigate(ids.NewV7().String(), "lure-"+ids.NewV7().String()[:8], url)
		if r.Decision != "deny" || !r.Held || bs.reasonOf(t, r.TransactionID) != pipeline.ReasonSiteNotListed {
			t.Errorf("%s: %+v", url, r)
		}
	}
	before := bs.txnCount(t)
	if r := host.navigate(ids.NewV7().String(), "lure-userinfo", "https://docs.example.com@prize-claim.example.net/"); r.Decision != "deny" || r.Held {
		t.Errorf("a link with userinfo: %+v", r)
	}
	if n := bs.txnCount(t); n != before {
		t.Errorf("a link with userinfo was decided (%d transactions)", n-before)
	}
	act := ids.NewV7().String()
	held := host.navigate(act, "lure-approved", "https://prize-claim.example.net/one")
	if !held.Held {
		t.Fatalf("held: %+v", held)
	}
	if st := bs.approveBrowser(t, held.TransactionID, "browser.navigate"); st != `"APPROVED"` {
		t.Fatalf("approval %s", st)
	}
	if r := host.navigate(act, "lure-approved", "https://prize-claim.example.net/one"); r.Decision != "allow" {
		t.Fatalf("the approved call: %+v", r)
	}
	if r := host.navigate(ids.NewV7().String(), "lure-other", "https://prize-claim.example.net/two"); r.Decision == "allow" || !r.Held {
		t.Fatalf("another call to the approved site: %+v", r)
	}
}

// TestT341_AnAgentNeverSubmitsSecretFields: a submit with a password,
// one-time-code or payment field is refused at the gateway, before the
// Authority is asked and whatever the site, with the reason to hand the
// tab to a person, and recorded; nothing of the fields but their names
// is ever asked about.
func TestT341_AnAgentNeverSubmitsSecretFields(t *testing.T) {
	bs := startBrowserStack(t)
	bs.listBrowserSites(t, m33Site{host: "docs.example.com"})
	host := bs.startHost(t, "browser")
	before := bs.txnCount(t)
	for i, site := range []string{"https://docs.example.com/pay", "https://unlisted.example.net/login"} {
		r := host.decide("browser_submit", ids.NewV7().String(), map[string]any{
			"url": site, "page_url": site, "method": "post", "fields": []string{"card_number", "cvc"}, "secret_fields": true,
			"call": "secret-" + string(rune('a'+i)),
		})
		if r.Decision != "deny" || r.Held || r.Code != dispatch.CodeBrowserSecretField || !strings.Contains(r.Reason, "take over this tab") {
			t.Errorf("%s: %+v", site, r)
		}
	}
	if n := bs.txnCount(t); n != before {
		t.Errorf("secret submits made %d transactions", n-before)
	}
	bs.waitLedger(t, auditkind.ConnectionBrowserSecretFieldRefused, 2)
	if r := host.decide("browser_submit", ids.NewV7().String(), map[string]any{
		"url": "https://docs.example.com/search", "page_url": "https://docs.example.com/", "method": "get",
		"fields": []string{"q"}, "secret_fields": false, "call": "plain",
	}); r.Decision != "allow" {
		t.Fatalf("a plain submit: %+v", r)
	}
}

// TestT342_ATakeoverIsAlwaysHeldAndBounded: a takeover holds for a person
// even on a listed site and under a grant naming it; its approval answers
// only that call; and it lasts at most ten minutes.
func TestT342_ATakeoverIsAlwaysHeldAndBounded(t *testing.T) {
	bs := startBrowserStack(t)
	bs.listBrowserSites(t, m33Site{host: "docs.example.com", subdomains: true})
	host := bs.startHost(t, "browser")
	act := ids.NewV7().String()
	in := map[string]any{"page_url": "https://docs.example.com/login", "minutes": 10, "call": "takeover-a"}
	tk := host.decide("browser_takeover", act, in)
	if !tk.Held || bs.reasonOf(t, tk.TransactionID) != pipeline.ReasonBrowserTakeover {
		t.Fatalf("takeover: %+v", tk)
	}
	if st := bs.approveBrowser(t, tk.TransactionID, "browser.takeover"); st != `"APPROVED"` {
		t.Fatalf("approval %s", st)
	}
	if r := host.decide("browser_takeover", act, in); r.Decision != "allow" {
		t.Fatalf("the approved takeover: %+v", r)
	}
	if r := host.decide("browser_takeover", ids.NewV7().String(), map[string]any{
		"page_url": "https://docs.example.com/login", "minutes": 10, "call": "takeover-b",
	}); !r.Held || bs.reasonOf(t, r.TransactionID) != pipeline.ReasonBrowserTakeover {
		t.Fatalf("a second takeover: %+v", r)
	}
	before := bs.txnCount(t)
	if r := host.decide("browser_takeover", ids.NewV7().String(), map[string]any{
		"page_url": "https://docs.example.com/login", "minutes": 11, "call": "takeover-c",
	}); r.Decision != "deny" || r.Held {
		t.Fatalf("an eleven-minute takeover: %+v", r)
	}
	if n := bs.txnCount(t); n != before {
		t.Fatalf("an eleven-minute takeover was decided (%d transactions)", n-before)
	}
}

// TestT343_NoComputerUseActionWithoutADecision: every computer-use action
// is decided and recorded as its own transaction; one the run's grant does
// not name is denied, one the package does not know is refused, and one
// held for a person is released by its approval for that call only.
func TestT343_NoComputerUseActionWithoutADecision(t *testing.T) {
	bs := startBrowserStack(t)
	computer := bs.startHost(t, "computer")
	before := bs.txnCount(t)
	for _, in := range []map[string]any{
		{"kind": "click", "button": "left", "x": 10, "y": 10, "call": "toolu_a"},
		{"kind": "type", "text": "hello", "call": "toolu_b"},
		{"kind": "key", "keys": "ctrl+l", "call": "toolu_c"},
	} {
		if r := computer.decide("computer", ids.NewV7().String(), in); r.Decision != "allow" || r.TransactionID == "" {
			t.Errorf("%v: %+v", in, r)
		}
	}
	if n := bs.txnCount(t); n != before+3 {
		t.Errorf("%d transactions for three computer actions", n-before)
	}
	if r := computer.decide("computer", ids.NewV7().String(), map[string]any{"kind": "teleport", "call": "toolu_d"}); r.Decision != "deny" {
		t.Errorf("an unknown action: %+v", r)
	}
	// A run whose grant names no computer action.
	bs.grantRun(t, `{"operations": ["browser.navigate"]}`, false)
	narrow := bs.startHost(t, "computer")
	if r := narrow.decide("computer", ids.NewV7().String(), map[string]any{"kind": "click", "button": "left", "call": "toolu_e"}); r.Decision != "deny" || r.Held {
		t.Errorf("a click outside the grant: %+v", r)
	}
	// A grant whose computer actions need a person: the held action is
	// released by its approval for the same call only (D1221 L6).
	bs.grantRunRequiring(t, m33Bounds, `[{"operations": ["computer.input"], "reason": "COMPUTER_INPUT_NEEDS_A_PERSON",
		"approval": {"role": "approver", "count": 1}}]`, false)
	held := bs.startHost(t, "computer")
	act, typed := ids.NewV7().String(), map[string]any{"kind": "type", "text": "hello", "call": "toolu_held"}
	h := held.decide("computer", act, typed)
	if h.Decision != "deny" || !h.Held {
		t.Fatalf("a computer action needing a person: %+v", h)
	}
	if st := bs.approveBrowser(t, h.TransactionID, "computer.input"); st != `"APPROVED"` {
		t.Fatalf("approval %s", st)
	}
	if r := held.decide("computer", act, typed); r.Decision != "allow" {
		t.Fatalf("the approved call: %+v", r)
	}
	if r := held.decide("computer", ids.NewV7().String(), map[string]any{"kind": "type", "text": "hello", "call": "toolu_other"}); r.Decision == "allow" || !r.Held {
		t.Fatalf("another call of the approved kind: %+v", r)
	}
}

// TestT344_CloakingTowardAgentsIsReportedOnlyAsDigests: the gateway's
// compare report is accepted only from the gateway serving the connection
// and for a site marked for the compare, is recorded as digests and
// numbers once an hour, and never changes a decision.
func TestT344_CloakingTowardAgentsIsReportedOnlyAsDigests(t *testing.T) {
	bs := startBrowserStack(t)
	bs.listBrowserSites(t, m33Site{host: "shop.example.com", subdomains: true, compare: true}, m33Site{host: "docs.example.com"})
	host := bs.startHost(t, "browser")
	if r := host.navigate(ids.NewV7().String(), "cloak-a", "https://shop.example.com/item/7"); r.Decision != "allow" {
		t.Fatalf("compare-site navigation: %+v", r)
	}
	ctl := bs.gatewayControl(t)
	ctx := context.Background()
	if _, err := ctl.Gateway.ReportPageCompare(ctx, bs.pageCompare("docs.example.com", m33PathSHA)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("a site not marked for the compare: %v", err)
	}
	other := bs.pageCompare("shop.example.com", m33PathSHA)
	other.ConnectionId = ids.NewV7().String()
	if _, err := ctl.Gateway.ReportPageCompare(ctx, other); err == nil {
		t.Errorf("a connection the gateway does not serve was accepted")
	}
	for range 3 {
		if _, err := ctl.Gateway.ReportPageCompare(ctx, bs.pageCompare("shop.example.com", m33PathSHA)); err != nil {
			t.Fatalf("ReportPageCompare: %v", err)
		}
	}
	bs.waitLedger(t, auditkind.BrowserCloakingSuspected, 1)
	if n := bs.ledgerCount(t, auditkind.BrowserCloakingSuspected); n != 1 {
		t.Errorf("%d cloaking entries for one page in an hour", n)
	}
	body := bs.row(t, `SELECT convert_from(body, 'UTF8') FROM pc.ledger_entries WHERE org_id = $1 AND kind = $2`,
		bs.org, "audit."+auditkind.BrowserCloakingSuspected)
	for _, want := range []string{m33PathSHA, "shop.example.com", "120"} {
		if !strings.Contains(body, want) {
			t.Errorf("cloaking entry lacks %q: %s", want, body)
		}
	}
	if strings.Contains(body, "item/7") {
		t.Errorf("cloaking entry carries the page address: %s", body)
	}
	if r := host.navigate(ids.NewV7().String(), "cloak-b", "https://shop.example.com/item/7"); r.Decision != "allow" {
		t.Fatalf("compare-site navigation after a report: %+v", r)
	}
}
