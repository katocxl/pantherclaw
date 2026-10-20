// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"encoding/json/v2"
	"flag"
	"io"
	"maps"
	"slices"
	"testing"

	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/policy/packs/render"
	pcstripe "github.com/katocxl/pantherclaw/packages/pc-stripe"
)

// The M14 templates (G0 M14 D40, F172): support and internal analysis,
// and the treasury, aggregate-reporting and research-disclosure templates
// the reference packs apply. They go through the same checks as the M11.1
// templates (template_m11_test.go): a complete disclosure, a policy that
// compiles against its packages, scenario tests in the D7 format, and the
// publish gate's mutation run with no survivors (HR-044).

// m14Templates are the M14 templates that carry scenario tests.
var m14Templates = []string{"customer-support", "treasury-payments"}

// m14Manifests are the business-connector packages the templates require.
var m14Manifests = [][]byte{pcstripe.Package}

// m14Facts are the facts the business-connector packages' gateway reads
// provide (the stripe.* facts of internal/gateway/stripefacts).
var m14Facts = map[string]fdomain.Type{
	"stripe.payment.refundable":             fdomain.TypeObject,
	"stripe.account.payout_details_changed": fdomain.TypeObject,
}

func init() { maps.Copy(m11Facts, m14Facts) }

// examplePayees are the connected accounts {{payee}} is rendered with.
var examplePayees = []string{"acct_ExamplePayee01", "acct_ExamplePayee02"}

// TestM14PayeesAreChecked (D97): --payee takes Stripe connected accounts
// only, never the tests' other payee, and only for a template that
// declares the payee placeholder; {{payees}} is a list of quoted literals
// in conditions, a {{payee}} list item is repeated for each payee, and a
// template that declares payees renders none without one.
func TestM14PayeesAreChecked(t *testing.T) {
	parse := func(name string, args ...string) (templateOptions, error) {
		t.Helper()
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		o := templateOptions{name: name}
		check := templateFlags(fs, &o)
		if err := fs.Parse(args); err != nil {
			return o, err
		}
		return o, check()
	}
	o, err := parse("treasury-payments", "--payee", "acct_ExamplePayee02", "--payee", "acct_ExamplePayee01", "--payee", "acct_ExamplePayee02")
	if err != nil || !slices.Equal(o.payees, examplePayees) {
		t.Fatalf("payees %v, %v", o.payees, err)
	}
	for _, args := range [][]string{
		{},
		{"--payee", "acct_short"},
		{"--payee", "acct_Example'Payee01"},
		{"--payee", "cus_ExamplePayee01"},
		{"--payee", render.OtherPayee},
	} {
		if _, err := parse("treasury-payments", args...); err == nil {
			t.Errorf("treasury-payments %v: accepted", args)
		}
	}
	if _, err := parse("refunds", "--payee", "acct_ExamplePayee01"); err == nil {
		t.Error("refunds took --payee")
	}
	if _, err := renderTemplate(templateOptions{name: "treasury-payments", environment: "production", timeZone: "UTC"}); err == nil {
		t.Error("treasury-payments rendered without a payee")
	}
	o.environment, o.timeZone = "production", "UTC"
	d, err := renderTemplate(o)
	if err != nil {
		t.Fatal(err)
	}
	var bounds struct {
		Targets map[string]struct {
			IDs []string `json:"ids"`
		} `json:"targets"`
		Destinations struct {
			IDs []string `json:"ids"`
		} `json:"destinations"`
	}
	if err := json.Unmarshal(d.Grant.Bounds, &bounds); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(bounds.Destinations.IDs, examplePayees) || !slices.Equal(bounds.Targets["stripe.account"].IDs, examplePayees) {
		t.Errorf("grant bounds %s", d.Grant.Bounds)
	}
	var when string
	for _, r := range d.Rules {
		if r["id"] == "tr-payees" {
			when, _ = r["when"].(string)
		}
	}
	if want := "!(action.target.id in ['acct_ExamplePayee01', 'acct_ExamplePayee02'])"; when != want {
		t.Errorf("tr-payees when %q, want %q", when, want)
	}
	r := renderer{o: o, spec: map[string]placeholderSpec{}}
	for _, s := range []string{"{{payees}}", "{{payee}}", "{{other_payee}}"} {
		if _, err := r.fill(s, true); err == nil {
			t.Errorf("%s filled without a declaration", s)
		}
	}
	r.spec = map[string]placeholderSpec{render.KindPayee: {Kind: render.KindPayee, Pattern: "^acct_[A-Za-z0-9]{8,64}$"}}
	if _, err := r.fill("{{payees}}", false); err == nil {
		t.Error("{{payees}} filled outside a condition")
	}
}
