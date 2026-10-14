// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"strings"
	"testing"

	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

func mustLimits(t *testing.T, s string) Limits {
	t.Helper()
	l, err := DecodeLimits([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

const taskBudget = `{"budgets": [{"id": "refunds", "grouping": "task", "operations": ["payments.refund.create"],
  "currency": "USD", "limit": "100.00", "max_count": "5", "period": "none"}]}`

func TestHR048_ChildActionDebitsEveryAncestor(t *testing.T) {
	root := rootGrant(t, refundBounds)
	root.Limits = mustLimits(t, taskBudget)
	child := childOf(t, root, `{}`)
	child.Limits = mustLimits(t, `{"budgets": [{"id": "mine", "grouping": "task", "operations": ["payments.*"], "currency": "USD", "limit": "20", "period": "day"}]}`)
	env := orgEnvelope(t, `{}`)
	env.Limits = mustLimits(t, `{
	  "budgets": [{"id": "per_person", "grouping": "principal", "operations": ["payments.refund.create"], "currency": "USD", "limit": "500", "period": "day"}],
	  "counters": [{"id": "per_charge", "operations": ["payments.refund.create"], "key": "target", "window": "day", "max": "3"}]}`)
	chain := Chain{Envelopes: []Envelope{env}, Grants: []Grant{root, child}}
	run := ids.NewV7()
	plan, f := chain.Debits(refund("12.50", "USD", "duplicate", mondayNoon), DebitContext{Now: mondayNoon, RunID: run, Principal: alice})
	if f != nil {
		t.Fatalf("Debits refused: %+v", f)
	}
	if len(plan.Budgets) != 3 || len(plan.Counters) != 1 {
		t.Fatalf("plan %+v, want the guardrail's, the root's and the child's budgets and one counter", plan)
	}
	wantRanks := []int{0, 1, 2}
	for i, d := range plan.Budgets {
		if d.Ref.Owner.Rank != wantRanks[i] || d.Amount.Cmp(money.MustParse("12.5")) != 0 {
			t.Fatalf("debit %d: %+v", i, d)
		}
	}
	rootDebit := plan.Budgets[1]
	if rootDebit.Ref.Owner.ID != root.ID.UUID() || rootDebit.Ref.Key != bdomain.KeyHash(rootDebit.Ref.Owner, "refunds", root.ID.String()) ||
		*rootDebit.MaxCount != 5 || rootDebit.Limit.Cmp(money.MustParse("100")) != 0 {
		t.Fatalf("the root's task budget must be shared by its children: %+v", rootDebit)
	}
	if got := plan.Budgets[2].Ref.Start; !got.Equal(bdomain.PeriodDay.Start(mondayNoon)) {
		t.Fatalf("the child's daily budget starts at %s", got)
	}

	// A second run of the same root grant shares the same accounts (F117).
	other, _ := chain.Debits(refund("1", "USD", "duplicate", mondayNoon), DebitContext{Now: mondayNoon, RunID: ids.NewV7(), Principal: alice})
	for i := range plan.Budgets {
		if other.Budgets[i].Ref != plan.Budgets[i].Ref {
			t.Fatalf("a new run id escaped budget %d", i)
		}
	}
}

func TestBudgetCoverageFailsClosed(t *testing.T) {
	root := rootGrant(t, refundBounds)
	root.Limits = mustLimits(t, taskBudget)
	chain := Chain{Grants: []Grant{root}}
	dc := DebitContext{Now: mondayNoon, RunID: ids.NewV7(), Principal: alice}

	if _, f := chain.Debits(refund("1", "EUR", "duplicate", mondayNoon), dc); f == nil || f.Reason() != ReasonBudgetCurrency || f.Finding.Outcome != Denied {
		t.Fatalf("a currency the budget does not cover: %+v", f)
	}

	a := refund("1", "USD", "duplicate", mondayNoon)
	a.Params["fee"] = defs.Value{Type: defs.TypeMoney, Money: money.Money{Amount: money.MustParse("1"), Currency: "USD"}}
	if _, f := chain.Debits(a, dc); f == nil || f.Reason() != ReasonBudgetValueAmbiguous || f.Finding.Outcome != Unknown {
		t.Fatalf("two money parameters: %+v", f)
	}

	env := orgEnvelope(t, `{}`)
	env.Limits = mustLimits(t, `{"budgets": [{"id": "per_account", "grouping": "account", "operations": ["payments.*"], "max_count": "10", "period": "day"}]}`)
	if _, f := (Chain{Envelopes: []Envelope{env}, Grants: []Grant{root}}).Debits(refund("1", "USD", "duplicate", mondayNoon), dc); f == nil || f.Reason() != ReasonLimitKeyMissing {
		t.Fatalf("an account budget on an action without an account: %+v", f)
	}

	// A count-only budget covers an action without a value.
	countOnly := rootGrant(t, `{}`)
	countOnly.Limits = mustLimits(t, `{"budgets": [{"id": "reads", "grouping": "task", "operations": ["payments.*"], "max_count": "2", "period": "none"}],
	  "counters": [{"id": "by_reason", "operations": ["payments.*"], "key": "params.reason", "window": "hour", "max": "1"}]}`)
	read := Action{Operation: "payments.refund.get", Params: defs.Values{}, Time: mondayNoon}
	if _, f := (Chain{Grants: []Grant{countOnly}}).Debits(read, dc); f == nil || f.Reason() != ReasonLimitKeyMissing {
		t.Fatalf("a counter keyed by a missing parameter: %+v", f)
	}
	read.Params["reason"] = defs.Value{Type: defs.TypeEnum, Str: "duplicate"}
	plan, f := (Chain{Grants: []Grant{countOnly}}).Debits(read, dc)
	if f != nil || len(plan.Budgets) != 1 || !plan.Budgets[0].Amount.IsZero() || plan.Budgets[0].Limit != nil || len(plan.Counters) != 1 {
		t.Fatalf("count-only budget: %+v %+v", plan, f)
	}
}

func TestLimitsValidation(t *testing.T) {
	bad := map[string]struct {
		doc     string
		onGrant bool
	}{
		"principal budget on a grant": {`{"budgets": [{"id": "a", "grouping": "principal", "operations": ["a.b"], "max_count": "1", "period": "day"}]}`, true},
		"task budget on an envelope":  {`{"budgets": [{"id": "a", "grouping": "task", "operations": ["a.b"], "max_count": "1", "period": "day"}]}`, false},
		"no limit at all":             {`{"budgets": [{"id": "a", "grouping": "task", "operations": ["a.b"], "period": "day"}]}`, true},
		"limit without currency":      {`{"budgets": [{"id": "a", "grouping": "task", "operations": ["a.b"], "limit": "5", "period": "day"}]}`, true},
		"negative limit":              {`{"budgets": [{"id": "a", "grouping": "task", "operations": ["a.b"], "currency": "USD", "limit": "-5", "period": "day"}]}`, true},
		"zero count":                  {`{"budgets": [{"id": "a", "grouping": "task", "operations": ["a.b"], "max_count": "0", "period": "day"}]}`, true},
		"count with a sign":           {`{"counters": [{"id": "a", "operations": ["a.b"], "key": "run", "window": "day", "max": "+3"}]}`, true},
		"unknown period":              {`{"budgets": [{"id": "a", "grouping": "task", "operations": ["a.b"], "max_count": "1", "period": "year"}]}`, true},
		"unknown key":                 {`{"counters": [{"id": "a", "operations": ["a.b"], "key": "agent_name", "window": "day", "max": "3"}]}`, true},
		"duplicate rule ids":          {`{"counters": [{"id": "a", "operations": ["a.b"], "key": "run", "window": "day", "max": "3"}, {"id": "a", "operations": ["a.b"], "key": "run", "window": "day", "max": "3"}]}`, true},
		"no operations":               {`{"counters": [{"id": "a", "operations": [], "key": "run", "window": "day", "max": "3"}]}`, true},
	}
	for name, tt := range bad {
		t.Run(name, func(t *testing.T) {
			if err := mustLimits(t, tt.doc).validate(tt.onGrant); !errors.Is(err, ErrInvalid) {
				t.Fatalf("validate = %v", err)
			}
		})
	}
	if _, err := DecodeLimits([]byte(`{"budgets": [{"id": "a", "max_count": 3}]}`)); !errors.Is(err, ErrInvalid) {
		t.Fatal("a JSON number was accepted")
	}
}

func TestRemovingALimitWidens(t *testing.T) {
	cur := rootGrant(t, refundBounds)
	cur.Limits = mustLimits(t, taskBudget)
	next := cur
	next.Revision = 2
	next.Limits = Limits{}
	if r, err := CompareRevision(cur, next); err != nil || !r.Widens {
		t.Fatalf("removing a budget: %+v %v", r, err)
	}
	next.Limits = mustLimits(t, taskBudget)
	next.Limits.Counters = []CountRule{{ID: "one_merge", Operations: Ops{"git.merge"}, Key: "task", Window: bdomain.WindowNone, Max: "1"}}
	if r, err := CompareRevision(cur, next); err != nil || r.Widens {
		t.Fatalf("adding a counter narrows: %+v %v", r, err)
	}
}

// TestHR206_GrantLimitsOnAConsequenceAreRefused: a budget or counter that
// names an operation which is only ever a consequence (a write without
// mappings, such as a payout or a deployment) would never count: the
// pipeline decides a consequence with the action that may cause it but
// never dispatches it. Such a limit is refused at issue. A limit on the
// action that causes it stands, and so does a prefix, which limits the
// dispatched operations it covers.
func TestHR206_GrantLimitsOnAConsequenceAreRefused(t *testing.T) {
	payout := &defs.Definition{Operation: "payments.payout.trigger", Access: defs.AccessWrite}
	lookup := func(op string) *defs.Definition {
		if op == payout.Operation {
			return payout
		}
		return lookupRefund(op)
	}
	g := rootGrant(t, refundBounds)
	for name, limits := range map[string]string{
		"a counter": `{"counters": [{"id": "payouts", "operations": ["payments.payout.trigger"], "key": "run", "window": "day", "max": "1"}]}`,
		"a budget": `{"budgets": [{"id": "payouts", "grouping": "task", "operations": ["payments.refund.create", "payments.payout.trigger"],
		  "max_count": "3", "period": "day"}]}`,
	} {
		g.Limits = mustLimits(t, limits)
		err := g.ValidateIssue(IssueContext{Now: issueTime, Lookup: lookup})
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "payments.payout.trigger is a consequence") {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, limits := range map[string]string{
		"the action": `{"counters": [{"id": "refunds", "operations": ["payments.refund.create"], "key": "run", "window": "day", "max": "1"}]}`,
		"a prefix":   `{"counters": [{"id": "payments", "operations": ["payments.*"], "key": "run", "window": "day", "max": "1"}]}`,
	} {
		g.Limits = mustLimits(t, limits)
		if err := g.ValidateIssue(IssueContext{Now: issueTime, Lookup: lookup}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestHR222_RangeRunsLeaveEnvelopeBudgetsUntouched (D6): for a simulated run
// the lines owned by guardrails are dropped; the grants' own still apply.
func TestHR222_RangeRunsLeaveEnvelopeBudgetsUntouched(t *testing.T) {
	root := rootGrant(t, refundBounds)
	root.Limits = mustLimits(t, taskBudget)
	env := orgEnvelope(t, `{}`)
	env.Limits = mustLimits(t, `{
	  "budgets": [{"id": "per_person", "grouping": "principal", "operations": ["payments.refund.create"], "currency": "USD", "limit": "500", "period": "day"}],
	  "counters": [{"id": "per_charge", "operations": ["payments.refund.create"], "key": "target", "window": "day", "max": "3"}]}`)
	chain := Chain{Envelopes: []Envelope{env}, Grants: []Grant{root}}
	a := refund("12.50", "USD", "duplicate", mondayNoon)
	realPlan, f := chain.Debits(a, DebitContext{Now: mondayNoon, RunID: ids.NewV7(), Principal: alice})
	if f != nil || len(realPlan.Budgets) != 2 || len(realPlan.Counters) != 1 {
		t.Fatalf("real run: %+v, %+v", realPlan, f)
	}
	sim, f := chain.Debits(a, DebitContext{Now: mondayNoon, RunID: ids.NewV7(), Principal: alice, Simulated: true})
	if f != nil || len(sim.Budgets) != 1 || len(sim.Counters) != 0 {
		t.Fatalf("simulated run: %+v, %+v, want only the grant's budget", sim, f)
	}
	if sim.Budgets[0].Ref != realPlan.Budgets[1].Ref {
		t.Fatalf("the grant's own line changed: %+v vs %+v", sim.Budgets[0].Ref, realPlan.Budgets[1].Ref)
	}
}
