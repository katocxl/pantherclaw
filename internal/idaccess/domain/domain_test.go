// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"errors"
	"slices"
	"testing"

	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/idaccess/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func parse(t *testing.T, raw string) domain.Scope {
	t.Helper()
	s, err := domain.ParseScope(raw, true)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestHR620_AssertionOnlyUsesOrNarrowsAnExistingGrant: no candidate, a named
// grant that is no candidate and an empty intersection all refuse, and a
// result is never wider than the grant.
//
// Covers: F910
func TestHR620_AssertionOnlyUsesOrNarrowsAnExistingGrant(t *testing.T) {
	bound := gdomain.Ops{"payments.refund", "tickets.*"}
	g := domain.Candidate{ID: ids.NewV7(), Operations: &bound}

	if _, err := domain.Choose(nil, domain.Scope{}); !errors.Is(err, domain.ErrNoGrant) {
		t.Fatalf("no grant: %v", err)
	}
	other := ids.NewV7()
	if _, err := domain.Choose([]domain.Candidate{g}, domain.Scope{Present: true, Grant: &other}); !errors.Is(err, domain.ErrNoGrant) {
		t.Fatalf("a named grant that is no candidate: %v", err)
	}
	if _, err := domain.Choose([]domain.Candidate{g}, parse(t, "payments.charge")); !errors.Is(err, domain.ErrNoGrant) {
		t.Fatalf("empty intersection: %v", err)
	}
	// Scope values PantherClaw does not know never become the whole grant.
	if _, err := domain.Choose([]domain.Candidate{g}, parse(t, "openid profile")); !errors.Is(err, domain.ErrNoGrant) {
		t.Fatalf("unknown scope: %v", err)
	}
	c, err := domain.Choose([]domain.Candidate{g}, parse(t, "tickets.read payments.* wider.thing"))
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range c.Operations {
		if !bound.Matches(op) {
			t.Fatalf("%q is wider than the grant", op)
		}
	}
	if !slices.Contains(c.Operations, "tickets.read") || !slices.Contains(c.Operations, "payments.refund") {
		t.Fatalf("intersection = %v", c.Operations)
	}
	whole, err := domain.Choose([]domain.Candidate{g}, domain.Scope{})
	if err != nil || whole.Grant != g.ID || whole.Operations != nil {
		t.Fatalf("no scope is the whole grant: %+v %v", whole, err)
	}
}

// TestHR621_SeveralGrantsFailClosed: several candidates need a scope that
// names one (D408.3).
//
// Covers: F910
func TestHR621_SeveralGrantsFailClosed(t *testing.T) {
	a, b := domain.Candidate{ID: ids.NewV7()}, domain.Candidate{ID: ids.NewV7()}
	if _, err := domain.Choose([]domain.Candidate{a, b}, domain.Scope{}); !errors.Is(err, domain.ErrAmbiguousGrant) {
		t.Fatalf("no scope: %v", err)
	}
	if _, err := domain.Choose([]domain.Candidate{a, b}, parse(t, "payments.refund")); !errors.Is(err, domain.ErrAmbiguousGrant) {
		t.Fatalf("an operation scope tells no grant apart: %v", err)
	}
	c, err := domain.Choose([]domain.Candidate{a, b}, parse(t, "pc.grant:"+b.ID.String()))
	if err != nil || c.Grant != b.ID || c.Operations != nil {
		t.Fatalf("named: %+v %v", c, err)
	}
	if _, err := domain.ParseScope("pc.grant:"+a.ID.String()+" pc.grant:"+b.ID.String(), true); !errors.Is(err, domain.ErrAssertion) {
		t.Fatalf("two names: %v", err)
	}
}

func TestIssuerAndResourceNames(t *testing.T) {
	org := ids.New[ids.Org]()
	const public = "https://pc.example.com/"
	iss := domain.IssuerID(public, org)
	if got, ok := domain.OrgOf(public, iss); !ok || got != org {
		t.Fatalf("OrgOf(%q) = %v %v", iss, got, ok)
	}
	for _, bad := range []string{"https://other.example.com/orgs/" + org.String(), iss + "/", iss + "x", "https://pc.example.com/orgs/not-a-uuid"} {
		if _, ok := domain.OrgOf(public, bad); ok {
			t.Fatalf("OrgOf accepted %q", bad)
		}
	}
	res := domain.ResourceURL("https://gw.example.com", "github")
	if name, ok := domain.ConnectionOf("https://gw.example.com/", res); !ok || name != "github" {
		t.Fatalf("ConnectionOf = %q %v", name, ok)
	}
	for _, bad := range []string{
		"https://GW.example.com/mcp-oauth/github", "https://gw.example.com/mcp/github",
		"https://gw.example.com/mcp-oauth/github/", "https://gw.example.com/mcp-oauth/gi%74hub", "https://gw.example.com/mcp-oauth/",
	} {
		if _, ok := domain.ConnectionOf("https://gw.example.com", bad); ok {
			t.Fatalf("ConnectionOf accepted %q", bad)
		}
	}
}
