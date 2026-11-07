// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline_test

import (
	"context"
	"encoding/hex"
	"encoding/json/jsontext"
	"errors"
	"testing"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	pcbrowser "github.com/katocxl/pantherclaw/packages/pc-browser"
)

// browserWorld is the test world with the org's browser site list (the
// pipeline's BrowserSites port).
type browserWorld struct {
	*pipelinetest.World
	sites []pipeline.BrowserSite
	err   error
	reads int
}

func (w *browserWorld) BrowserSites(context.Context, ids.OrgID) ([]pipeline.BrowserSite, error) {
	w.reads++
	return w.sites, w.err
}

// browserGrantBounds grants every pc.browser operation on every site, so
// only the browser step can hold.
const browserGrantBounds = `{
  "operations": ["browser.navigate", "browser.form.submit", "browser.download", "browser.click", "browser.takeover"],
  "targets": {"browser.site": {"prefixes": ["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","0","1","2","3","4","5","6","7","8","9","["]}}
}`

// browserFx is fx with pc.browser behind a local (hook) connection.
func browserFx(t *testing.T) (*fx, *browserWorld) {
	t.Helper()
	pkg, err := manifest.Decode(pcbrowser.Package)
	if err != nil {
		t.Fatal(err)
	}
	m, err := mapping.New(pkg, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	f := &fx{
		t: t, w: pipelinetest.New(org, pkg, now), mapper: m, pkg: pkg,
		agent: ids.NewV7(), instance: ids.NewV7(), env: ids.NewV7(), team: ids.NewV7(),
		alice: gdomain.Principal{Kind: gdomain.PrincipalUser, ID: ids.NewV7()}, provider: ids.NewV7(),
		gateway: ids.NewV7(), conn: ids.NewV7(),
	}
	f.w.PutConnection(pipeline.Connection{
		ID: f.conn, Gateway: f.gateway, Kind: "local", Package: pkg.Name, State: "ACTIVE", AccessMode: "none",
		DefaultMode: pipeline.ModeEnforce, Modes: map[string]string{},
	})
	bw := &browserWorld{World: f.w}
	f.p = &pipeline.Pipeline{Reader: bw}
	f.w.AddAgent(f.agent, pipeline.Agent{State: "VERIFIED", TeamID: f.team, BusinessUnitID: ids.NewV7()})
	f.grant = f.newGrant(browserGrantBounds)
	f.w.Grants.Put(f.grant)
	f.run = f.newRun(f.grant.ID)
	return f, bw
}

// hook maps a hook tool call in the fixture's run and evaluates it.
func (f *fx) hook(tool, input string) *pipeline.Evaluation {
	f.t.Helper()
	p, err := f.mapper.Hook(context.Background(), mapping.Context{
		Org: org.String(), Env: f.env.String(), RunID: f.run.String(), ActionID: ids.NewV7().String(), AgentInstance: f.instance.String(),
		Connection: f.conn.String(),
	}, tool, jsontext.Value(input))
	if err != nil {
		f.t.Fatal(err)
	}
	return f.eval(pipeline.Request{
		Org: org, Action: p, Gateway: f.gateway.String(),
		Identity: pipeline.Identity{InstanceID: f.instance, AgentID: f.agent, AttestationLevel: 1, JKT: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"},
	})
}

func navigate(url string) string { return `{"url":"` + url + `","call":"c1"}` }

// browserHold returns the browser step's hold item, if any.
func browserHold(ev *pipeline.Evaluation) (pipeline.Item, bool) {
	for _, it := range ev.Checklist {
		if it.Level == pipeline.BrowserLevel {
			return it, true
		}
	}
	return pipeline.Item{}, false
}

// TestHR745_AListedSiteGoesThroughTheBrowserStep: a host equal to an entry,
// or a subdomain of an entry that includes subdomains, matches; the grant
// then decides.
func TestHR745_AListedSiteGoesThroughTheBrowserStep(t *testing.T) {
	f, w := browserFx(t)
	w.sites = []pipeline.BrowserSite{{Host: "docs.example.com"}, {Host: "example.org", IncludeSubdomains: true}}
	for _, url := range []string{
		"https://docs.example.com/guide",
		"https://example.org/",
		"https://shop.example.org/cart",
		"https://a.b.example.org/x",
	} {
		ev := f.hook("browser_navigate", navigate(url))
		expect(t, ev, adomain.Allow, pipeline.ReasonGrantCovers)
		if it, ok := browserHold(ev); ok {
			t.Errorf("%s: held %+v", url, it)
		}
	}
	for tool, in := range map[string]string{
		"browser_submit":   `{"url":"https://docs.example.com/f","method":"post","fields":["q"],"secret_fields":false,"call":"c2"}`,
		"browser_download": `{"url":"https://docs.example.com/a.pdf","call":"c3"}`,
		"browser_click":    `{"page_url":"https://docs.example.com/p","selector":"button.go","call":"c4"}`,
	} {
		expect(t, f.hook(tool, in), adomain.Allow, pipeline.ReasonGrantCovers)
	}
}

// TestHR745_AnUnlistedSiteHolds: a host that matches no entry holds for an
// approver (SITE_NOT_LISTED): another host, a subdomain of an entry without
// include_subdomains, a host that only ends with the entry's name, an IP
// host even when listed, every host on an empty list, and every host when
// the Reader has no site-list port.
func TestHR745_AnUnlistedSiteHolds(t *testing.T) {
	f, w := browserFx(t)
	w.sites = []pipeline.BrowserSite{{Host: "example.com"}, {Host: "10.0.0.1"}, {Host: "example.org", IncludeSubdomains: true}}
	for _, url := range []string{
		"https://evil.test/",
		"https://shop.example.com/",
		"https://notexample.org/",
		"https://example.org.evil.test/",
		"https://10.0.0.1/",
		"http://[::1]/",
	} {
		ev := f.hook("browser_navigate", navigate(url))
		expect(t, ev, adomain.RequireApproval, pipeline.ReasonSiteNotListed)
		if len(ev.Approvals) != 1 || ev.Approvals[0].Role != "approver" || ev.Approvals[0].Count != 1 {
			t.Errorf("%s: approvals %+v", url, ev.Approvals)
		}
	}
	expect(t, f.hook("browser_download", `{"url":"https://files.evil.test/a","call":"c2"}`), adomain.RequireApproval, pipeline.ReasonSiteNotListed)

	w.sites = nil
	expect(t, f.hook("browser_navigate", navigate("https://example.com/")), adomain.RequireApproval, pipeline.ReasonSiteNotListed)

	// A Reader without the port lists nothing: everything holds.
	f.p = &pipeline.Pipeline{Reader: f.w}
	expect(t, f.hook("browser_navigate", navigate("https://example.com/")), adomain.RequireApproval, pipeline.ReasonSiteNotListed)
}

// TestHR745_AnUnreadableSiteListIsMissingEvidence: a read error is a
// missing fact: the action cannot be allowed.
func TestHR745_AnUnreadableSiteListIsMissingEvidence(t *testing.T) {
	f, w := browserFx(t)
	w.sites = []pipeline.BrowserSite{{Host: "example.com"}}
	w.err = errors.New("db down")
	expect(t, f.hook("browser_navigate", navigate("https://example.com/")), adomain.CannotAuthorize, pipeline.ReasonEvidenceUnavailable)
}

// TestHR745_TheBrowserStepOnlyAddsHolds: an action the grant does not
// cover on a listed site is still refused by the grant; the browser step
// never turns a deny into an allow, and actions of other packages never
// read the list.
func TestHR745_TheBrowserStepOnlyAddsHolds(t *testing.T) {
	f, w := browserFx(t)
	w.sites = []pipeline.BrowserSite{{Host: "example.com"}}
	g := f.newGrant(`{"operations": ["browser.navigate"], "targets": {"browser.site": {"ids": ["example.com"]}}}`)
	f.w.Grants.Put(g)
	f.run = f.newRun(g.ID)
	expect(t, f.hook("browser_download", `{"url":"https://example.com/a","call":"c1"}`), adomain.Deny, gdomain.ReasonOperationNotGranted)
	expect(t, f.hook("browser_navigate", navigate("https://other.example.net/")), adomain.Deny, gdomain.ReasonTargetNotGranted)
	expect(t, f.hook("browser_navigate", navigate("https://example.com/")), adomain.Allow, pipeline.ReasonGrantCovers)

	// The payments package never reads the site list.
	p := newFx(t)
	bw := &browserWorld{World: p.w}
	p.p = &pipeline.Pipeline{Reader: bw}
	expect(t, p.call(p.run, "create_refund", refund("ch_1", "30.00")), adomain.Allow, pipeline.ReasonGrantCovers)
	if bw.reads != 0 {
		t.Fatalf("a payments action read the browser site list %d times", bw.reads)
	}
}

// TestHR746_ATakeoverAlwaysHolds: a takeover holds for one approver
// (BROWSER_TAKEOVER, level browser) on a listed site with a grant naming
// it, with a policy exception naming it, and on an unlisted site.
func TestHR746_ATakeoverAlwaysHolds(t *testing.T) {
	f, w := browserFx(t)
	w.sites = []pipeline.BrowserSite{{Host: "bank.example.com"}}
	r := pdomain.Rule{
		ID: "no-takeover-at-night", Kind: pdomain.Forbid, Summary: "x", Operations: []string{"browser.takeover"},
		When: `false`, Reason: "NIGHT", Exceptable: true,
	}
	if err := f.w.SetPolicy([]pdomain.Rule{r}, nil); err != nil {
		t.Fatal(err)
	}
	d := pdomain.RuleDigest(r)
	f.w.SetExceptions([]pdomain.Exception{{
		ID: exceptionID, Bundle: "org-policy", Rule: r.ID, RuleDigest: hex.EncodeToString(d[:]), Operations: []string{"browser.takeover"},
		ExpiresAt: now.Add(time.Hour),
	}})
	for _, url := range []string{"https://bank.example.com/login", "https://unlisted.example.net/"} {
		ev := f.hook("browser_takeover", `{"page_url":"`+url+`","minutes":10,"call":"c1"}`)
		expect(t, ev, adomain.RequireApproval, pipeline.ReasonBrowserTakeover)
		it, ok := browserHold(ev)
		if !ok || it.Code != pipeline.ReasonBrowserTakeover || it.Step != pipeline.StepRequirements {
			t.Fatalf("%s: hold %+v in %+v", url, it, ev.Checklist)
		}
		if len(ev.Approvals) != 1 || ev.Approvals[0].Role != "approver" || ev.Approvals[0].Count != 1 {
			t.Fatalf("%s: approvals %+v", url, ev.Approvals)
		}
	}
}

// TestHR746_ANavigationOnTheSameSiteDoesNotHold: what a takeover holds is
// the takeover alone: a navigation on the listed site, under the same grant,
// is decided by the grant.
func TestHR746_ANavigationOnTheSameSiteDoesNotHold(t *testing.T) {
	f, w := browserFx(t)
	w.sites = []pipeline.BrowserSite{{Host: "bank.example.com"}}
	expect(t, f.hook("browser_navigate", navigate("https://bank.example.com/login")), adomain.Allow, pipeline.ReasonGrantCovers)
}
