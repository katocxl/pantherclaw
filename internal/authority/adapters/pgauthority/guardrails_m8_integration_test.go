// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	defpg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	factpg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	polpg "github.com/katocxl/pantherclaw/internal/policy/adapters/pgstore"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// TestHR206_GuardrailLimitsOnAConsequenceAreRefused: a guardrail's
// budget or counter on an operation that is only ever a consequence (the
// payout a refund may start) would never count, so an admin would believe
// in a cap that is not there. The guardrail service refuses it, as grant
// issue does, with the org's active definitions, and so it refuses a limit
// on an operation with no active definition. A limit on the action that
// causes the consequence, or on a prefix, stands.
func TestHR206_GuardrailLimitsOnAConsequenceAreRefused(t *testing.T) {
	w := newWorldWith(t, pipelinetest.PayoutConsequence)
	put := func(limits string) error {
		t.Helper()
		l, err := gdomain.DecodeLimits([]byte(limits))
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = w.grants.PutEnvelope(w.human, gapp.EnvelopeRequest{Scope: gdomain.Scope{Kind: gdomain.ScopeOrg}, Name: "caps", Limits: l})
		return err
	}
	for name, c := range map[string]struct{ limits, want string }{
		"a counter on the payout": {
			`{"counters": [{"id": "payouts", "operations": ["payments.payout.trigger"], "key": "run", "window": "day", "max": "3"}]}`,
			"payments.payout.trigger is a consequence",
		},
		"a budget naming the payout": {
			`{"budgets": [{"id": "payouts", "grouping": "org", "operations": ["payments.refund.create", "payments.payout.trigger"],
			  "max_count": "3", "period": "day"}]}`,
			"payments.payout.trigger is a consequence",
		},
		"a counter on an operation no package defines": {
			`{"counters": [{"id": "x", "operations": ["payments.payout.cancel"], "key": "run", "window": "day", "max": "3"}]}`,
			"payments.payout.cancel has no active definition",
		},
	} {
		if err := put(c.limits); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := w.count("SELECT count(*) FROM pc.envelopes"); n != 0 {
		t.Fatalf("%d guardrails stored", n)
	}
	if err := put(`{"counters": [{"id": "refunds", "operations": ["payments.refund.create"], "key": "run", "window": "day", "max": "3"},
	  {"id": "all", "operations": ["payments.*"], "key": "run", "window": "day", "max": "9"}]}`); err != nil {
		t.Fatalf("limits on the action and a prefix: %v", err)
	}
}

// TestHR206_APolicyOnAConsequenceReadsOnlyFactsAboutItsTarget: the policy
// service compiles a version with the subject types the org's providers
// declare. A rule on the payout, a consequence about a charge, may read a
// fact declared about charges; one that reads a fact declared about pull
// requests is refused when the version is created, since the Authority
// would never find it about the payout's target and every refund that may
// start a payout would be CANNOT_AUTHORIZE.
func TestHR206_APolicyOnAConsequenceReadsOnlyFactsAboutItsTarget(t *testing.T) {
	w := newWorldWith(t, pipelinetest.PayoutConsequence)
	sa := ids.NewV7()
	exec(t, w.pool, w.org, "INSERT INTO pc.service_accounts (org_id, id, name, created_by) VALUES ($1, $2, 'github', 'test')", w.org, sa)
	if _, err := w.facts.RegisterProvider(w.human, "github.gateway", sa, []fdomain.Declaration{
		{Name: "github.pull.head", Type: fdomain.TypeObject, SubjectType: "github.pull_request", MaxLag: time.Minute},
	}); err != nil {
		t.Fatal(err)
	}
	store := &factpg.Store{Pool: w.pool}
	v := &policyapp.Versions{
		Store: &polpg.Store{Pool: w.pool}, Facts: store, Subjects: store, Definitions: &defpg.Store{Pool: w.pool}, Authz: allow{},
		Limits: celenv.DefaultLimits,
	}
	create := func(fact, when string) error {
		t.Helper()
		raw, err := json.Marshal(pdomain.Bundle{ID: "org-policy", Rules: []pdomain.Rule{{
			ID: "payouts", Kind: pdomain.Forbid, Summary: "x", Operations: []string{"payments.payout.trigger"}, When: when, Reason: "NOPE",
			Facts: []pdomain.FactRef{{Name: fact, MaxAgeSeconds: 60}},
		}}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = v.Create(w.human, raw)
		return err
	}
	if err := create("github.pull.head", "facts.github_pull_head.draft == true"); err == nil ||
		!strings.Contains(err.Error(), `fact "github.pull.head" is declared about a github.pull_request`) {
		t.Fatalf("a fact about pull requests: %v", err)
	}
	if err := create("payments.charge.refundable", "!facts.payments_charge_refundable"); err != nil {
		t.Fatalf("a fact about charges: %v", err)
	}
}
