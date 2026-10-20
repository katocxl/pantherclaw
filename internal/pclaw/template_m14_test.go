// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"flag"
	"io"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
	polapp "github.com/katocxl/pantherclaw/internal/policy/app"
	"github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/policy/packs/render"
	pcpostgres "github.com/katocxl/pantherclaw/packages/pc-postgres"
	pcslack "github.com/katocxl/pantherclaw/packages/pc-slack"
	pcstripe "github.com/katocxl/pantherclaw/packages/pc-stripe"
)

// The M14 templates (G0 M14 D40, F172): support and internal analysis,
// and the treasury, aggregate-reporting and research-disclosure templates
// the reference packs apply. They go through the same checks as the M11.1
// templates (template_m11_test.go): a complete disclosure, a policy that
// compiles against its packages, scenario tests in the D7 format, and the
// publish gate's mutation run with no survivors (HR-044).

// m14Templates are the M14 templates that carry scenario tests.
var m14Templates = []string{"aggregate-reporting", "customer-support", "internal-analysis", "research-disclosure", "treasury-payments"}

// m14Manifests are the business-connector packages the templates require.
var m14Manifests = [][]byte{pcstripe.Package, pcpostgres.Package, pcslack.Package}

// m14Facts are the facts the business-connector packages' gateway reads
// provide (the stripe.* facts of internal/gateway/stripefacts).
var m14Facts = map[string]fdomain.Type{
	"stripe.payment.refundable":             fdomain.TypeObject,
	"stripe.account.payout_details_changed": fdomain.TypeObject,
	"slack.channel.external":                fdomain.TypeObject,
}

func init() { maps.Copy(m11Facts, m14Facts) }

// examplePayees are the connected accounts {{payee}} is rendered with.
var examplePayees = []string{"acct_ExamplePayee01", "acct_ExamplePayee02"}

// Example customers and Slack channels the list kinds are rendered with.
var (
	exampleCustomers     = []string{"cus-1001", "cus-1002"}
	exampleSlackChannels = []string{"C0EXAMPLE01", "C0EXAMPLE02"}
)

// exampleLists are the list kinds' example values.
func exampleLists() map[string][]string {
	return map[string][]string{
		render.KindPayee: examplePayees, render.KindCustomer: exampleCustomers, render.KindSlackChannel: exampleSlackChannels,
	}
}

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
		if err := fs.Parse(append([]string{"--team", exampleTeam}, args...)); err != nil {
			return o, err
		}
		return o, check()
	}
	o, err := parse("treasury-payments", "--payee", "acct_ExamplePayee02", "--payee", "acct_ExamplePayee01", "--payee", "acct_ExamplePayee02")
	if err != nil || !slices.Equal(o.lists[render.KindPayee], examplePayees) {
		t.Fatalf("payees %v, %v", o.lists, err)
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
	// D119 L5: outside tests, {{payee}} is a list item only, never the first value.
	for _, s := range []string{"action.target.id == {{payee}}", "{{payee}}"} {
		if _, err := r.fill(s, true); err == nil {
			t.Errorf("%s filled in a rule", s)
		}
		if _, err := r.fill(s, false); err == nil {
			t.Errorf("%s filled outside a list item", s)
		}
	}
}

// TestM14CustomersAreChecked (D106): customer-support needs --customer,
// refuses values that are not customer ids, and renders them into the
// grant's record scope for postgres.rows.read with the classes public and
// internal.
func TestM14CustomersAreChecked(t *testing.T) {
	parse := func(args ...string) (templateOptions, error) {
		t.Helper()
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		o := templateOptions{name: "customer-support", agent: templateAgent}
		check := templateFlags(fs, &o)
		if err := fs.Parse(append([]string{"--team", exampleTeam}, args...)); err != nil {
			return o, err
		}
		return o, check()
	}
	for _, args := range [][]string{{}, {"--customer", "cus 1"}, {"--customer", "cus'1"}, {"--customer", render.OtherCustomer}} {
		if _, err := parse(args...); err == nil {
			t.Errorf("customer-support %v: accepted", args)
		}
	}
	if _, err := parse("--customer", "cus-1", "--payee", "acct_ExamplePayee01"); err == nil {
		t.Error("customer-support took --payee")
	}
	o, err := parse("--customer", "cus-1002", "--customer", "cus-1001")
	if err != nil {
		t.Fatal(err)
	}
	o.environment, o.timeZone, o.agent = "production", "UTC", templateAgent
	d, err := renderTemplate(o)
	if err != nil {
		t.Fatal(err)
	}
	var bounds struct {
		Scope map[string]struct {
			Records struct {
				Key    string   `json:"key"`
				Values []string `json:"values"`
			} `json:"records"`
			Classes struct {
				IDs []string `json:"ids"`
			} `json:"classes"`
		} `json:"scope"`
	}
	if err := json.Unmarshal(d.Grant.Bounds, &bounds); err != nil {
		t.Fatal(err)
	}
	s := bounds.Scope["postgres.rows.read"]
	if s.Records.Key != "customer" || !slices.Equal(s.Records.Values, exampleCustomers) || !slices.Equal(s.Classes.IDs, []string{"public", "internal"}) {
		t.Errorf("grant scope %s", d.Grant.Bounds)
	}
}

// TestM14AgentTemplatesNeedAgent (D114): a template whose rules are per
// agent is refused without --agent, by apply and by the renderer, and
// renders with one; its rules name only that agent (each such template's
// scenario tests also show another agent unaffected).
func TestM14AgentTemplatesNeedAgent(t *testing.T) {
	args := map[string][]string{
		"aggregate-reporting": nil,
		"customer-support":    {"--customer", "cus-1001"},
		"internal-analysis":   {"--slack-channel", "C0EXAMPLE01"},
		"research-disclosure": {"--repos", "acme/research", "--slack-channel", "C0EXAMPLE01"},
	}
	for name, extra := range args {
		info, err := readTemplateInfo(name)
		if err != nil || !info.RequiresAgent {
			t.Fatalf("%s: requires_agent %v, %v", name, info.RequiresAgent, err)
		}
		parse := func(more ...string) (templateOptions, error) {
			fs := flag.NewFlagSet("t", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			o := templateOptions{name: name}
			check := templateFlags(fs, &o)
			fs.StringVar(&o.agent, "agent", "", "")
			if err := fs.Parse(append([]string{"--team", exampleTeam}, append(slices.Clone(extra), more...)...)); err != nil {
				return o, err
			}
			return o, check()
		}
		if _, err := parse(); err == nil || !strings.Contains(err.Error(), "needs --agent") {
			t.Errorf("%s without --agent: %v", name, err)
		}
		o, err := parse("--agent", templateAgent)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		o.environment, o.timeZone = "production", "UTC"
		d, err := renderTemplate(o)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, r := range d.Rules {
			if when, _ := r["when"].(string); strings.Contains(when, "run.agent_id") && !strings.Contains(when, "run.agent_id == '"+templateAgent+"'") {
				t.Errorf("%s %v: %s", name, r["id"], when)
			}
		}
		o.agent = ""
		if _, err := renderTemplate(o); err == nil {
			t.Errorf("%s rendered without an agent", name)
		}
	}
}

// m14Render renders an M14 template with the example values and the
// template agent, and its policy as a bundle.
func m14Render(t *testing.T, name string) (templateData, *domain.Bundle) {
	t.Helper()
	o := templateOptions{
		name: name, environment: "production", timeZone: "UTC", agent: templateAgent, lists: exampleLists(),
		repos: []string{"acme/research"}, defaults: map[string]string{"acme/research": "main"},
	}
	info, err := readTemplateInfo(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := info.Placeholders[kindRepository]; !ok {
		o.repos, o.defaults = nil, map[string]string{}
	}
	d, err := renderTemplate(o)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return d, m11Rendered{rules: d.Rules}.bundle(t)
}

// TestM14GrantsCoverConsequences (D119 M1): every consequence operation an
// M14 template's rules decide is in the template's grant, so a predicted
// or unknown consequence is decided by those rules and not refused by the
// grant (the scenario fixture's root grant adds them by itself).
func TestM14GrantsCoverConsequences(t *testing.T) {
	pkgs := m11Packages(t)
	for _, name := range m14Templates {
		d, b := m14Render(t, name)
		info, err := readTemplateInfo(name)
		if err != nil {
			t.Fatal(err)
		}
		consequences := map[string]bool{}
		for _, p := range info.Requires.Packages {
			for _, c := range pkgs[p].Consequences {
				consequences[c.Consequence.Operation] = true
			}
		}
		var bounds struct {
			Operations []string `json:"operations"`
		}
		if err := json.Unmarshal(d.Grant.Bounds, &bounds); err != nil {
			t.Fatal(err)
		}
		for _, r := range b.Rules {
			for _, op := range r.Operations {
				if consequences[op] && !slices.Contains(bounds.Operations, op) {
					t.Errorf("%s: rule %s decides the consequence %s, which the grant does not cover", name, r.ID, op)
				}
			}
		}
	}
}

// m14Evaluate evaluates one operation of a template's policy with the
// policy engine, for the template agent's run.
func m14Evaluate(t *testing.T, b *domain.Bundle, pkg, op string, target actionir.Target, params string, c *polapp.Consequence) domain.Outcome {
	t.Helper()
	d := m11Definition(m11Packages(t), []string{pkg}, op)
	compiled, err := (&polapp.Engine{Limits: celenv.DefaultLimits, Facts: m11Facts}).Compile(b, []*defs.Definition{d})
	if err != nil {
		t.Fatal(err)
	}
	a := actionir.ActionIR{Operation: op, Definition: actionir.Definition{Digest: d.Digest}, Target: target, Params: jsontext.Value(params)}
	out, err := compiled.Evaluate(context.Background(), d, a, polapp.Input{
		Budget: polapp.DefaultBudget, Consequence: c, Run: &polapp.Run{ID: "run-1", AgentID: templateAgent},
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestM14TreasuryRequirements (D99, D119 L3/L4): every transfer asks for
// two independent approvers; a predicted payee_changed_recently
// consequence asks for the principal's security-key step-up and no other
// approval; an unknown one is refused outright.
func TestM14TreasuryRequirements(t *testing.T) {
	_, b := m14Render(t, "treasury-payments")
	payee := actionir.Target{Type: "stripe.account", ID: examplePayees[0]}
	out := m14Evaluate(t, b, "pc.stripe", "stripe.transfer.create", payee, `{"amount":{"value":"100.00","currency":"USD"}}`, nil)
	if out.Verdict != domain.VerdictRequireApproval || len(out.Required) != 1 || out.Required[0].Rule != "tr-transfer-approve" ||
		out.Required[0].Approval == nil || out.Required[0].Approval.Count != 2 || !out.Required[0].Approval.Independent || out.Required[0].Approval.Role != "approver" {
		t.Errorf("transfer: %v %+v", out.Verdict, out.Required)
	}
	out = m14Evaluate(t, b, "pc.stripe", "stripe.payee.changed_recently", payee, `{}`, &polapp.Consequence{Rule: "payee-changed-recently", State: "PREDICTED"})
	if out.Verdict != domain.VerdictRequireStepUp || len(out.Required) != 1 || out.Required[0].Rule != "tr-payee-changed" ||
		out.Required[0].StepUp == nil || out.Required[0].StepUp.Subject != "principal" || out.Required[0].StepUp.Method != "webauthn" {
		t.Errorf("changed payee: %v %+v", out.Verdict, out.Required)
	}
	out = m14Evaluate(t, b, "pc.stripe", "stripe.payee.changed_recently", payee, `{}`, &polapp.Consequence{Rule: "payee-changed-recently", State: "UNKNOWN"})
	if item, _ := out.Decisive(); out.Verdict != domain.VerdictDeny || item.Reason != "PAYEE_CHANGES_UNREAD" {
		t.Errorf("unread payee: %v %+v", out.Verdict, item)
	}
}

// TestM14SupportRecordScope (D106, D119 L1, D129 M1): customer-support's
// read of a support table carries a record_scope obligation on key
// customer with exactly the --customer values, never another customer, and
// a data_classes obligation of public and internal only.
func TestM14SupportRecordScope(t *testing.T) {
	_, b := m14Render(t, "customer-support")
	out := m14Evaluate(t, b, "pc.postgres", "postgres.rows.read", actionir.Target{Type: "pg_table", ID: "shop.orders"}, `{"columns":["id"],"limit":"10"}`, nil)
	var found bool
	for _, o := range out.Obligations {
		if o.Kind == domain.RecordScope {
			found = true
			if o.Param != "customer" || !slices.Equal(o.Values, exampleCustomers) || slices.Contains(o.Values, render.OtherCustomer) {
				t.Errorf("record scope %+v, want customer %v", o, exampleCustomers)
			}
		}
	}
	if !found {
		t.Errorf("no record_scope obligation: %+v", out.Obligations)
	}
	var classes []string
	for _, o := range out.Obligations {
		if o.Kind == domain.DataClasses {
			classes = o.Values
		}
	}
	if !slices.Equal(classes, []string{"public", "internal"}) {
		t.Errorf("data_classes obligation %v, want public and internal: %+v", classes, out.Obligations)
	}
}

// TestM14SlackGrantsNameTheChannels (D107, D123): the Slack templates'
// grants bind pc.slack's destination set and targets to exactly the
// --slack-channel values.
func TestM14SlackGrantsNameTheChannels(t *testing.T) {
	for _, name := range []string{"internal-analysis", "research-disclosure"} {
		d, _ := m14Render(t, name)
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
		if !slices.Equal(bounds.Destinations.IDs, exampleSlackChannels) || !slices.Equal(bounds.Targets["slack_channel"].IDs, exampleSlackChannels) {
			t.Errorf("%s: grant bounds %s", name, d.Grant.Bounds)
		}
	}
}

// exampleTeam is the team the scoped templates are applied for.
const exampleTeam = "01890000-0000-7000-8000-0000000000b1"

// TestM14WeeklyCapsAreEnvelopes (D120): customer-support and
// treasury-payments need --team or --bu, and their envelope carries the
// weekly cap (500.00 USD per team; 50000.00 USD for the scope, grouped by
// org). The cap is one account for every task: a second task's grant
// debits the same envelope account as the first, while each task grant's
// own budget is a separate account, so no number of task grants exceeds
// the envelope's cap.
func TestM14WeeklyCapsAreEnvelopes(t *testing.T) {
	teamID, err := ids.ParseUUID(exampleTeam)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]struct {
		grouping, limit, op string
		args                []string
		action              gdomain.Action
	}{
		"customer-support": {
			"team", "500.00", "stripe.refund.create",
			[]string{"--customer", "cus-1001", "--agent", templateAgent},
			gdomain.Action{Operation: "stripe.refund.create", TargetType: "stripe.payment", TargetID: "pi_Support0001"},
		},
		"treasury-payments": {
			"org", "50000.00", "stripe.transfer.create",
			[]string{"--payee", examplePayees[0]},
			gdomain.Action{Operation: "stripe.transfer.create", TargetType: "stripe.account", TargetID: examplePayees[0]},
		},
	} {
		parse := func(more ...string) (templateOptions, error) {
			fs := flag.NewFlagSet("t", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			o := templateOptions{name: name}
			check := templateFlags(fs, &o)
			fs.StringVar(&o.agent, "agent", "", "")
			if err := fs.Parse(append(slices.Clone(want.args), more...)); err != nil {
				return o, err
			}
			return o, check()
		}
		if _, err := parse(); err == nil || !strings.Contains(err.Error(), "needs --team or --bu") {
			t.Errorf("%s without --team or --bu: %v", name, err)
		}
		if _, err := parse("--bu", exampleTeam); err != nil {
			t.Errorf("%s with --bu: %v", name, err)
		}
		o, err := parse("--team", exampleTeam)
		if err != nil {
			t.Fatal(err)
		}
		o.environment, o.timeZone = "production", "UTC"
		d, err := renderTemplate(o)
		if err != nil {
			t.Fatal(err)
		}
		if !d.Envelope.Present || !sameJSON(d.Envelope.Bounds, []byte("{}")) {
			t.Fatalf("%s: envelope %+v", name, d.Envelope)
		}
		envLimits, err := gdomain.DecodeLimits(d.Envelope.Limits)
		if err != nil {
			t.Fatal(err)
		}
		if len(envLimits.Budgets) != 1 || string(envLimits.Budgets[0].Grouping) != want.grouping || envLimits.Budgets[0].Limit != want.limit ||
			envLimits.Budgets[0].Period != bdomain.PeriodWeek || !envLimits.Budgets[0].Operations.Matches(want.op) {
			t.Fatalf("%s: envelope limits %+v", name, envLimits)
		}
		env := gdomain.Envelope{ID: gdomain.NewEnvelopeID(), Revision: 1, Scope: gdomain.Scope{Kind: gdomain.ScopeTeam, ID: teamID}, Name: name, Limits: envLimits}
		grantLimits, err := gdomain.DecodeLimits(d.Grant.Limits)
		if err != nil {
			t.Fatal(err)
		}
		a := want.action
		a.Access = defs.AccessWrite
		a.Params = defs.Values{"amount": {Type: defs.TypeMoney, Money: money.Money{Amount: money.MustParse("10.00"), Currency: "USD"}}}
		monday := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
		a.Time = monday
		dc := gdomain.DebitContext{Now: monday, RunID: ids.NewV7(), TeamID: teamID}
		var envRefs, taskRefs []bdomain.Ref
		for range 2 {
			g := gdomain.Grant{ID: gdomain.NewGrantID(), Limits: grantLimits}
			plan, f := (gdomain.Chain{Envelopes: []gdomain.Envelope{env}, Grants: []gdomain.Grant{g}}).Debits(a, dc)
			if f != nil {
				t.Fatalf("%s: %+v", name, f)
			}
			if len(plan.Budgets) != 2 {
				t.Fatalf("%s: debits %+v, want the envelope's and the task's", name, plan.Budgets)
			}
			envRefs, taskRefs = append(envRefs, plan.Budgets[0].Ref), append(taskRefs, plan.Budgets[1].Ref)
		}
		if envRefs[0] != envRefs[1] {
			t.Errorf("%s: two task grants debit different envelope accounts %v", name, envRefs)
		}
		if taskRefs[0] == taskRefs[1] {
			t.Errorf("%s: two task grants share a task account", name)
		}
	}
}

// TestM14MergeBudgets (D120): a limits-only envelope adds its budget to a
// scope's existing limits, replacing one of the same id and keeping the
// others and the counters.
func TestM14MergeBudgets(t *testing.T) {
	cur := []byte(`{"budgets":[{"id":"other","grouping":"team","operations":["github.*"],"max_count":"9","period":"day"},{"id":"support_weekly_refunds","grouping":"team","operations":["stripe.refund.create"],"currency":"USD","limit":"900.00","period":"week"}],"counters":[{"id":"c","operations":["github.*"],"key":"run","window":"none","max":"1"}]}`)
	tpl := []byte(`{"budgets":[{"id":"support_weekly_refunds","grouping":"team","operations":["stripe.refund.create"],"currency":"USD","limit":"500.00","period":"week"}]}`)
	got, err := mergeBudgets(cur, tpl)
	if err != nil {
		t.Fatal(err)
	}
	l, err := gdomain.DecodeLimits(got)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Budgets) != 2 || l.Budgets[0].ID != "other" || l.Budgets[1].Limit != "500.00" || len(l.Counters) != 1 {
		t.Errorf("merged %s", got)
	}
	if got, err := mergeBudgets(nil, tpl); err != nil || !sameJSON(got, tpl) {
		t.Errorf("into none: %s %v", got, err)
	}
}
