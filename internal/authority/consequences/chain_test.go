// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package consequences_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/consequences"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	pcgithub "github.com/katocxl/pantherclaw/packages/pc-github"
)

// chainPackage is pc.github with two more rules down the merge's chain: a
// deployment that changes the repository's settings when test.deploy.next
// says so (depth 2), and a settings change that reads its contents when
// test.settings.next says so (depth 3).
func chainPackage(t *testing.T) *defs.Package {
	t.Helper()
	p, err := manifest.Decode(pcgithub.Package)
	if err != nil {
		t.Fatal(err)
	}
	p.Consequences = append(p.Consequences,
		link("deploy-updates-settings", "github.deployment.trigger", "github.repo.settings.update", "test.deploy.next", 2),
		link("settings-read-contents", "github.repo.settings.update", "github.contents.read", "test.settings.next", 3),
	)
	return p
}

// link is a rule from op to the consequence next on the same repository,
// predicted when the boolean fact holds, applying down to depth.
func link(id, op, next, fact string, depth int) defs.ConsequenceRule {
	return defs.ConsequenceRule{
		ID: id, Operation: op, When: "facts." + strings.ReplaceAll(fact, ".", "_"), RequiresFacts: []string{fact},
		Consequence: defs.Consequence{Operation: next, Effect: "test.effect", Description: "a link"},
		ValidUntil:  "2027-10-11", MaxDepth: depth,
	}
}

// flag is a current boolean fact.
func flag(name string, v bool) fdomain.Fact {
	return fdomain.Fact{
		Name: name, SubjectType: "github.repository", SubjectID: "acme/payments",
		Value: fdomain.Value{Type: fdomain.TypeBoolean, Bool: v}, ObservedAt: now.Add(-time.Second),
	}
}

// reads is an Input.More that answers from facts and records each read.
type reads struct {
	facts map[string]fdomain.Fact
	err   error
	calls []string
}

func (r *reads) more(_ context.Context, on *defs.Definition, target string, names []string) (map[string]fdomain.Fact, map[string]time.Duration, error) {
	r.calls = append(r.calls, on.Operation+" "+target+" "+strings.Join(names, ","))
	return r.facts, nil, r.err
}

func derive(t *testing.T, p *defs.Package, r *reads) []consequences.Consequence {
	t.Helper()
	on, ok := p.Definition("github.pull.merge")
	if !ok {
		t.Fatal("no github.pull.merge")
	}
	return consequences.NewEvaluator(celenv.DefaultLimits).Evaluate(context.Background(), consequences.Of(p, on.Operation), consequences.Input{
		On: on, TargetID: "acme/payments#7", Now: now, More: r.more,
		Facts: triggers(map[string]any{"state": "triggered", "environments": []any{"production"}}, time.Second),
	})
}

func shape(cs []consequences.Consequence) string {
	var out []string
	for _, c := range cs {
		depth, parent, chained, _ := c.Chain()
		if !chained {
			parent = -1
		}
		out = append(out, fmt.Sprintf("%s:%s@%d<%d", c.Rule, c.State, depth, parent))
	}
	return strings.Join(out, " ")
}

// TestHR455_AChainFollowsPredictedConsequences: a predicted deployment
// that rules apply to at depth 2 is the next hop, with the facts about its
// own target, and so on to depth 3; each consequence names the one it
// follows from, which comes before it.
//
// Covers: F411
func TestHR455_AChainFollowsPredictedConsequences(t *testing.T) {
	r := &reads{facts: map[string]fdomain.Fact{"test.deploy.next": flag("test.deploy.next", true), "test.settings.next": flag("test.settings.next", true)}}
	cs := derive(t, chainPackage(t), r)
	want := "merge-triggers-deployment:PREDICTED@1<-1 deploy-updates-settings:PREDICTED@2<0 settings-read-contents:PREDICTED@3<1"
	if got := shape(cs); got != want {
		t.Fatalf("chain = %s\nwant    %s", got, want)
	}
	if !slices.Equal(r.calls, []string{
		"github.deployment.trigger acme/payments test.deploy.next", "github.repo.settings.update acme/payments test.settings.next",
	}) {
		t.Fatalf("reads = %q", r.calls)
	}
	for _, c := range cs {
		if c.Err != nil || c.Target.ID != "acme/payments" || c.Source != consequences.SourcePackage {
			t.Fatalf("%+v", c)
		}
	}
	// Not triggered ends the branch.
	r = &reads{facts: map[string]fdomain.Fact{"test.deploy.next": flag("test.deploy.next", false)}}
	if got := shape(derive(t, chainPackage(t), r)); got != "merge-triggers-deployment:PREDICTED@1<-1 deploy-updates-settings:NOT_TRIGGERED@2<0" {
		t.Fatalf("not triggered: %s", got)
	}
}

// TestHR455_AnUnknownLinkStopsTheChain: when a hop's fact cannot be used,
// its consequence is UNKNOWN and says derivation stopped there (rule and
// depth); nothing below it is derived. A fact read that fails is an error
// (CANNOT_AUTHORIZE), never "not triggered", and without a reader the
// facts are not known.
//
// Covers: F412
func TestHR455_AnUnknownLinkStopsTheChain(t *testing.T) {
	cs := derive(t, chainPackage(t), &reads{facts: map[string]fdomain.Fact{}})
	if got := shape(cs); got != "merge-triggers-deployment:PREDICTED@1<-1 deploy-updates-settings:UNKNOWN@2<0" {
		t.Fatalf("unknown: %s", got)
	}
	if u := cs[1].Unknown; cs[1].Reason != consequences.ReasonUnknown || len(u) != 2 || !strings.Contains(u[0], "test.deploy.next is not known") ||
		u[1] != "derivation stopped at deploy-updates-settings, depth 2: its consequences are not derived" {
		t.Fatalf("unknown: %q %s", u, cs[1].Reason)
	}
	cs = derive(t, chainPackage(t), &reads{err: errors.New("storage detail")})
	if len(cs) != 2 || !errors.Is(cs[1].Err, consequences.ErrRule) || strings.Contains(cs[1].Err.Error(), "storage") {
		t.Fatalf("read error: %s %v", shape(cs), cs[1].Err)
	}
	p := chainPackage(t)
	on, _ := p.Definition("github.pull.merge")
	cs = consequences.NewEvaluator(celenv.DefaultLimits).Evaluate(context.Background(), consequences.Of(p, on.Operation), consequences.Input{
		On: on, TargetID: "acme/payments#7", Now: now,
		Facts: triggers(map[string]any{"state": "triggered", "environments": []any{}}, time.Second),
	})
	if got := shape(cs); got != "merge-triggers-deployment:PREDICTED@1<-1 deploy-updates-settings:UNKNOWN@2<0" {
		t.Fatalf("no reader: %s", got)
	}
}

// TestHR455_ChainsAreBoundedAndAcyclic: a rule without max_depth applies
// only to an action itself; a consequence whose operation and target were
// already reached is kept but not derived from again; and past 16
// consequences the next is UNKNOWN, CONSEQUENCE_FANOUT, and derivation
// stops.
//
// Covers: F411
func TestHR455_ChainsAreBoundedAndAcyclic(t *testing.T) {
	p := chainPackage(t)
	p.Consequences[len(p.Consequences)-2].MaxDepth = 0
	if ids := consequences.IDs(consequences.Of(p, "github.pull.merge")); !slices.Equal(ids, []string{"merge-triggers-deployment"}) {
		t.Fatalf("depth 1 only: %q", ids)
	}

	p = chainPackage(t)
	p.Consequences = append(p.Consequences, link("settings-redeploy", "github.repo.settings.update", "github.deployment.trigger", "test.settings.next", 4))
	r := &reads{facts: map[string]fdomain.Fact{"test.deploy.next": flag("test.deploy.next", true), "test.settings.next": flag("test.settings.next", true)}}
	want := "merge-triggers-deployment:PREDICTED@1<-1 deploy-updates-settings:PREDICTED@2<0 settings-read-contents:PREDICTED@3<1 settings-redeploy:PREDICTED@3<1"
	if got := shape(derive(t, p, r)); got != want || len(r.calls) != 2 {
		t.Fatalf("cycle: %s (%d reads)\nwant   %s", got, len(r.calls), want)
	}

	p = chainPackage(t)
	first := p.Consequences[slices.IndexFunc(p.Consequences, func(r defs.ConsequenceRule) bool { return r.ID == "merge-triggers-deployment" })]
	for i := range consequences.MaxConsequences {
		more := first
		more.ID = fmt.Sprintf("merge-also-%02d", i)
		p.Consequences = append(p.Consequences, more)
	}
	cs := derive(t, p, &reads{})
	last := cs[len(cs)-1]
	if len(cs) != consequences.MaxConsequences+1 || last.State != consequences.Unknown || last.Reason != consequences.ReasonFanout ||
		last.Rule != "merge-also-15" || !strings.Contains(last.Unknown[0], "more than 16 consequences") || !strings.HasPrefix(last.FactsDigest, "sha256:") {
		t.Fatalf("fanout: %d %+v", len(cs), last)
	}
}

// TestHR456_AnExpiredRuleIsUnknown: a rule whose review expired (the day
// after valid_until) cannot rule its consequence out: UNKNOWN,
// CONSEQUENCE_RULE_EXPIRED, even when its condition would not hold; on its
// last day it still applies.
//
// Covers: F409
func TestHR456_AnExpiredRuleIsUnknown(t *testing.T) {
	none := triggers(map[string]any{"state": "none", "environments": []any{}}, time.Second)
	on, rules := merge(t)
	ev := consequences.NewEvaluator(celenv.DefaultLimits)
	for day, want := range map[string]consequences.State{"2026-10-11": consequences.Unknown, "2026-10-12": consequences.NotTriggered} {
		r := rules[0]
		r.ValidUntil = day
		c := ev.Evaluate(context.Background(), []consequences.Rule{r}, consequences.Input{On: on, TargetID: "acme/payments#7", Facts: none, Now: now})[0]
		if c.Err != nil || c.State != want || (want == consequences.Unknown && (c.Reason != consequences.ReasonExpired ||
			!slices.Equal(c.Unknown, []string{"the rule's review expired on 2026-10-11"}) || !strings.HasPrefix(c.FactsDigest, "sha256:"))) {
			t.Errorf("valid until %s: %+v", day, c)
		}
	}
}

// TestHR234_DirectDecidesAsVersion4: a replay of pipeline version 4
// inputs (G0 M17 D133) evaluates the rules for the action's operation
// only, without a chain and without expiry, as version 4 did.
//
// Covers: F411
func TestHR234_DirectDecidesAsVersion4(t *testing.T) {
	p := chainPackage(t)
	on, _ := p.Definition("github.pull.merge")
	r := &reads{facts: map[string]fdomain.Fact{"test.deploy.next": flag("test.deploy.next", true)}}
	rules := consequences.Of(p, on.Operation)
	rules[0].ValidUntil = "2026-01-01"
	cs := consequences.NewEvaluator(celenv.DefaultLimits).Evaluate(context.Background(), rules, consequences.Input{
		On: on, TargetID: "acme/payments#7", Now: now, More: r.more, Direct: true,
		Facts: triggers(map[string]any{"state": "triggered", "environments": []any{}}, time.Second),
	})
	if got := shape(cs); got != "merge-triggers-deployment:PREDICTED@1<-1" || len(r.calls) != 0 {
		t.Fatalf("direct: %s, %d reads", got, len(r.calls))
	}
}

// TestHR457_EveryLinkIsANamedRuleOverVerifiedFacts: a hop is derived only
// by a named rule for the consequence's own operation, from facts read
// about the consequence's own target: the action's facts are never reused
// down the chain, so a fact the hop's target lacks leaves it UNKNOWN, and
// a rule without a verified fact is refused before it is ever stored.
//
// Covers: F411, F413
func TestHR457_EveryLinkIsANamedRuleOverVerifiedFacts(t *testing.T) {
	p := chainPackage(t)
	// The deeper rule reads a fact the action's target has.
	p.Consequences[len(p.Consequences)-2].RequiresFacts = []string{"github.repo.deploy_triggers"}
	p.Consequences[len(p.Consequences)-2].When = "facts.github_repo_deploy_triggers.state != 'none'"
	r := &reads{facts: map[string]fdomain.Fact{}}
	cs := derive(t, p, r)
	if got := shape(cs); got != "merge-triggers-deployment:PREDICTED@1<-1 deploy-updates-settings:UNKNOWN@2<0" {
		t.Fatalf("the action's facts reused: %s", got)
	}
	if len(r.calls) != 1 || r.calls[0] != "github.deployment.trigger acme/payments github.repo.deploy_triggers" {
		t.Fatalf("reads %q", r.calls)
	}
	noFacts := link("cx.no-facts", "github.pull.merge", "github.deployment.trigger", "x.y", 1)
	noFacts.RequiresFacts = nil
	ops := map[string]*defs.Definition{}
	for _, op := range []string{"github.pull.merge", "github.deployment.trigger"} {
		ops[op], _ = p.Definition(op)
	}
	if err := noFacts.ValidateCustomer(ops); !errors.Is(err, defs.ErrInvalid) || !strings.Contains(err.Error(), "no invented causality") {
		t.Fatalf("a rule without facts: %v", err)
	}
	unnamed := link("deploys", "github.pull.merge", "github.deployment.trigger", "x.y", 1)
	if err := unnamed.ValidateCustomer(ops); !errors.Is(err, defs.ErrInvalid) {
		t.Fatalf("a customer rule without a cx. name: %v", err)
	}
	if err := link("cx.deploys", "github.pull.merge", "github.deployment.trigger", "x.y", 1).ValidateCustomer(ops); err != nil {
		t.Fatalf("a valid customer rule: %v", err)
	}
}
