// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authority/consequences"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
)

// TestF410_ConsequencesAreLabelledApart: a predicted consequence is
// MAY_CAUSE without an enforced permit and AUTHORIZED with one; ACCEPTED
// once its consequence transaction was opened, CONFIRMED only once every
// such transaction's effect is CONFIRMED; an UNKNOWN one says why and
// where its chain stopped (G0 M17 D111). A receipt from before pipeline 6
// explains as a package rule's depth-1 consequence.
//
// Covers: F407, F409, F410
func TestF410_ConsequencesAreLabelledApart(t *testing.T) {
	deploy := receiptConsequence{
		Rule: "merge-triggers-deployment", State: "PREDICTED", Operation: "github.deployment.trigger", Target: "github.repository:acme/pay",
		Environments: []string{"production"}, Description: "Merging deploys", Evidence: []string{"github.repo.deploy_triggers"}, ValidUntil: "2027-10-11",
	}
	pager := receiptConsequence{
		Rule: "cx.deploy-pages", State: "UNKNOWN", Operation: "pager.page", Target: "pager.service:pay", Source: "customer",
		Chain: []string{"merge-triggers-deployment", "cx.deploy-pages"},
	}
	rows := []dbq.ExplanationConsequencesRow{
		{Position: 0, RuleID: deploy.Rule, Unknown: []byte(`[]`)},
		{Position: 1, RuleID: pager.Rule, Unknown: []byte(`["pager.on_call is not known","derivation stopped at cx.deploy-pages, depth 2: its consequences are not derived"]`)},
	}
	child := func(effect string) dbq.ExplanationConsequenceTransactionsRow {
		return dbq.ExplanationConsequenceTransactionsRow{Operation: deploy.Operation, TargetType: "github.repository", TargetID: "acme/pay", EffectState: effect}
	}
	label := func(permits bool, children ...dbq.ExplanationConsequenceTransactionsRow) consequences.Label {
		return explainedConsequences([]receiptConsequence{deploy}, permits, rows[:1], children)[0].Label
	}
	for name, tc := range map[string]struct {
		got, want consequences.Label
	}{
		"held":                  {label(false), consequences.LabelMayCause},
		"permitted":             {label(true), consequences.LabelAuthorized},
		"opened":                {label(true, child("")), consequences.LabelAccepted},
		"one of two confirmed":  {label(true, child("CONFIRMED"), child("UNCONFIRMED")), consequences.LabelAccepted},
		"confirmed":             {label(true, child("CONFIRMED")), consequences.LabelConfirmed},
		"another target opened": {label(true, dbq.ExplanationConsequenceTransactionsRow{Operation: deploy.Operation, TargetType: "github.repository", TargetID: "acme/other"}), consequences.LabelAuthorized},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: %s, want %s", name, tc.got, tc.want)
		}
	}
	out := explainedConsequences([]receiptConsequence{deploy, pager}, true, rows, []dbq.ExplanationConsequenceTransactionsRow{child("CONFIRMED")})
	d, p := out[0], out[1]
	if d.Source != "package" || !slices.Equal(d.Chain, []string{deploy.Rule}) || d.Description != "Merging deploys" ||
		!slices.Equal(d.Evidence, []string{"github.repo.deploy_triggers"}) || d.ValidUntil != "2027-10-11" || len(d.UnknownLinks) != 0 {
		t.Errorf("deploy: %+v", d)
	}
	if p.Label != consequences.LabelUnknown || p.Source != "customer" || len(p.Chain) != 2 || len(p.UnknownLinks) != 2 {
		t.Errorf("pager: %+v", p)
	}
}
