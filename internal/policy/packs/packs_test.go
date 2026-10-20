// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package packs

import (
	"encoding/json/v2"
	"slices"
	"testing"

	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/policy/packs/render"
)

const (
	env   = "0192aaaa-bbbb-7ccc-8ddd-0000000000e1"
	agent = "0192aaaa-bbbb-7ccc-8ddd-0000000000a1"
)

// TestPacksRenderToValidBundles: each pack renders, for an environment and
// an agent, rules and tests that form a valid policy bundle whose tests
// expect allows and denials (and holds where the pack has them).
func TestPacksRenderToValidBundles(t *testing.T) {
	ps, err := List()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range ps {
		names = append(names, p.Name)
	}
	want := []string{"aggregate-reporting", "coding-to-production", "read-only-diagnostics", "research-disclosure", "support-resolution", "treasury-payments"}
	if !slices.Equal(names, want) {
		t.Fatalf("packs %v", ps)
	}
	params := map[string]map[string]string{
		"coding-to-production":  {ParamRepos: "acme/api,acme/web", ParamDefaultBranch: "main,acme/web=develop"},
		"read-only-diagnostics": {ParamWorkspace: "/srv/app"},
		"treasury-payments":     {ParamPayees: "acct_ExamplePayee02, acct_ExamplePayee01"},
		"support-resolution":    {ParamCustomers: "cus-1001"},
		"research-disclosure":   {ParamRepos: "acme/research", ParamSlackChannels: "C0EXAMPLE01"},
	}
	wantDecisions := map[string][]string{
		"coding-to-production":  {"ALLOW", "DENY", "REQUIRE_APPROVAL"},
		"read-only-diagnostics": {"ALLOW", "DENY"},
		"aggregate-reporting":   {"ALLOW", "ALLOW_WITH_OBLIGATIONS", "DENY"},
		"treasury-payments":     {"ALLOW", "ALLOW_WITH_OBLIGATIONS", "DENY", "REQUIRE_APPROVAL"},
		"support-resolution":    {"ALLOW", "ALLOW_WITH_OBLIGATIONS", "CANNOT_AUTHORIZE", "DENY", "REQUIRE_APPROVAL"},
		"research-disclosure":   {"ALLOW", "ALLOW_WITH_OBLIGATIONS", "DENY", "REQUIRE_APPROVAL"},
	}
	for _, p := range ps {
		o, err := p.options(params[p.Name])
		if err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
		o.Environment, o.EnvironmentID, o.Agent = "production", env, agent
		d, err := render.Render(o)
		if err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
		raw, err := json.Marshal(map[string]any{"id": p.Name, "version": 1, "rules": d.Rules, "tests": d.Tests})
		if err != nil {
			t.Fatal(err)
		}
		var b pdomain.Bundle
		if err := json.Unmarshal(raw, &b, json.RejectUnknownMembers(true)); err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
		if err := b.Validate(); err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
		var decisions []string
		for _, tc := range b.Tests {
			decisions = append(decisions, tc.Expect.Decision)
		}
		slices.Sort(decisions)
		if got := slices.Compact(decisions); !slices.Equal(got, wantDecisions[p.Name]) {
			t.Errorf("%s: test decisions %v, want %v", p.Name, got, wantDecisions[p.Name])
		}
		if len(d.Grant.Bounds) < 3 || p.BaselineTTLSeconds <= 0 {
			t.Errorf("%s: no grant baseline", p.Name)
		}
	}
}

// TestPackParametersAreChecked: a pack refuses parameters it does not take
// and needs those it does; values go through the template's own checks.
func TestPackParametersAreChecked(t *testing.T) {
	c2p, err := Get("coding-to-production")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c2p.Needs(), []string{ParamDefaultBranch, ParamRepos, ParamTimeZone}) {
		t.Errorf("needs %v", c2p.Needs())
	}
	if _, err := c2p.options(map[string]string{}); err == nil {
		t.Error("no repos accepted")
	}
	if _, err := c2p.options(map[string]string{ParamRepos: "acme/api", ParamWorkspace: "/srv"}); err == nil {
		t.Error("a workspace accepted")
	}
	if _, err := c2p.options(map[string]string{ParamRepos: "acme/api", ParamDefaultBranch: "acme/web=main"}); err == nil {
		t.Error("a default branch of another repository accepted")
	}
	o, err := c2p.options(map[string]string{ParamRepos: "acme/we'b"})
	if err != nil {
		t.Fatal(err)
	}
	o.Environment, o.EnvironmentID = "production", env
	if _, err := render.Render(o); err == nil {
		t.Error("a repository with a quote rendered")
	}
	rod, err := Get("read-only-diagnostics")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rod.options(map[string]string{}); err == nil {
		t.Error("no workspace accepted")
	}
	if _, err := Get("nope"); err == nil {
		t.Error("an unknown pack found")
	}
	if _, err := Get("../templates"); err == nil {
		t.Error("a path found")
	}
}

// TestTreasuryPackPayees (D97): the treasury pack needs payees, checks
// each against the payee pattern, and names exactly them in the grant
// baseline's destinations.
func TestTreasuryPackPayees(t *testing.T) {
	tr, err := Get("treasury-payments")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(tr.Needs(), []string{ParamPayees}) {
		t.Errorf("needs %v", tr.Needs())
	}
	if _, err := tr.options(map[string]string{}); err == nil {
		t.Error("no payees accepted")
	}
	for _, bad := range []string{"acct_short", "cus_ExamplePayee01", "acct_Example'Payee1", render.OtherPayee} {
		o, err := tr.options(map[string]string{ParamPayees: bad})
		if err != nil {
			continue
		}
		o.Environment = "production"
		if _, err := render.Render(o); err == nil {
			t.Errorf("payee %q rendered", bad)
		}
	}
	o, err := tr.options(map[string]string{ParamPayees: "acct_ExamplePayee02,acct_ExamplePayee01"})
	if err != nil {
		t.Fatal(err)
	}
	o.Environment = "production"
	d, err := render.Render(o)
	if err != nil {
		t.Fatal(err)
	}
	var bounds struct {
		Destinations struct {
			IDs []string `json:"ids"`
		} `json:"destinations"`
	}
	if err := json.Unmarshal(d.Grant.Bounds, &bounds); err != nil {
		t.Fatal(err)
	}
	if want := []string{"acct_ExamplePayee01", "acct_ExamplePayee02"}; !slices.Equal(bounds.Destinations.IDs, want) {
		t.Errorf("destinations %v, want %v", bounds.Destinations.IDs, want)
	}
	c2p, err := Get("coding-to-production")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c2p.options(map[string]string{ParamRepos: "acme/api", ParamPayees: "acct_ExamplePayee01"}); err == nil {
		t.Error("coding-to-production took payees")
	}
}

// TestListPackParameters (D106, D107): support-resolution needs customers;
// research-disclosure needs repos and takes Slack channels optionally,
// rendering no channel test without them and allowing no channel.
func TestListPackParameters(t *testing.T) {
	sr, err := Get("support-resolution")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sr.Needs(), []string{ParamCustomers}) {
		t.Errorf("support-resolution needs %v", sr.Needs())
	}
	if _, err := sr.options(map[string]string{}); err == nil {
		t.Error("support-resolution without customers accepted")
	}
	rs, err := Get("research-disclosure")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{ParamDefaultBranch, ParamRepos, ParamSlackChannels}; !slices.Equal(rs.Needs(), want) {
		t.Errorf("research-disclosure needs %v, want %v", rs.Needs(), want)
	}
	o, err := rs.options(map[string]string{ParamRepos: "acme/research"})
	if err != nil {
		t.Fatal(err)
	}
	o.Environment, o.Agent = "production", agent
	d, err := render.Render(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range d.Tests {
		if id, _ := tc["id"].(string); id == "rs-post--"+agent || id == "rs-post-external--"+agent {
			t.Errorf("channel test %s rendered without a channel", id)
		}
	}
	found := false
	for _, r := range d.Rules {
		if r["id"] == "rs-channels--"+agent {
			found = r["when"] == "run.agent_id == '"+agent+"' && !(action.target.id in [])"
		}
	}
	if !found {
		t.Error("rs-channels does not refuse every channel without channels")
	}
}
