// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	polapp "github.com/katocxl/pantherclaw/internal/policy/app"
	"github.com/katocxl/pantherclaw/internal/policy/domain"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
	pcgithub "github.com/katocxl/pantherclaw/packages/pc-github"
	pcshell "github.com/katocxl/pantherclaw/packages/pc-shell"
	"github.com/katocxl/pantherclaw/templates"
)

// The M11.1 templates (G0 M11.1 D16, F172–F178): refunds, release
// deployment and production diagnostics, each with a disclosure and
// baseline scenario tests in the D7 format. These tests check the files as
// data: the disclosure is complete, the policy compiles against its
// packages, the scenario tests parse strictly, and, evaluated with the
// policy engine alone, every case holds and every comparison flip and
// every rule removal fails at least one case (HR-044). The publish gate
// runs the same cases through the whole decision pipeline.

// m11Templates are the templates that carry scenario tests.
var m11Templates = []string{"production-diagnostics", "refunds", "release-deployment"}

// Example values the placeholders are rendered with.
const (
	exampleEnvironmentID = "01890000-0000-7000-8000-0000000000e1"
	exampleOtherEnvID    = "01890000-0000-7000-8000-0000000000e2"
	exampleWorkspace     = "/srv/app"
)

// m11Case is one scenario test in the D7 format, decoded strictly.
type m11Case struct {
	ID      string `json:"id"`
	Per     string `json:"per"`
	Summary string `json:"summary"`
	Action  struct {
		Operation   string         `json:"operation"`
		Environment string         `json:"environment,omitzero"`
		Target      string         `json:"target,omitzero"`
		Params      jsontext.Value `json:"params"`
	} `json:"action"`
	Given struct {
		Grant *struct {
			Constraints []domain.Constraint `json:"constraints"`
		} `json:"grant,omitzero"`
		Budget *struct {
			Param    string `json:"param"`
			Currency string `json:"currency,omitzero"`
			Limit    string `json:"limit"`
			Used     string `json:"used"`
		} `json:"budget,omitzero"`
		Facts map[string]struct {
			Value      jsontext.Value `json:"value"`
			AgeSeconds int            `json:"age_seconds"`
		} `json:"facts,omitzero"`
		Approval         string `json:"approval,omitzero"`
		StepUp           string `json:"step_up,omitzero"`
		DestinationClass string `json:"destination_class,omitzero"`
	} `json:"given,omitzero"`
	Expect struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
		Rule     string `json:"rule,omitzero"`
	} `json:"expect"`
}

// m11Rendered is a template's policy and tests rendered for repositories.
type m11Rendered struct {
	rules []map[string]any
	cases []m11Case
}

// renderM11 renders a template's policy.json and tests.json the way apply
// fills placeholders: a "per": "repo" item once per repository (its id
// made per repository, {{repo}} and {{repository}} filled), a "per": "org"
// item once with {{repos}} as a CEL list.
func renderM11(t *testing.T, name string, repos []string) m11Rendered {
	t.Helper()
	quoted := make([]string, len(repos))
	for i, r := range repos {
		quoted[i] = "'" + r + "'"
	}
	common := []string{
		"{{environment_id}}", exampleEnvironmentID, "{{other_environment_id}}", exampleOtherEnvID,
		"{{environment}}", "production", "{{workspace}}", exampleWorkspace,
		"{{repos}}", "[" + strings.Join(quoted, ", ") + "]",
	}
	expand := func(file, key string) []map[string]any {
		raw, err := fs.ReadFile(templates.FS, name+"/"+file)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string][]map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s/%s: %v", name, file, err)
		}
		var out []map[string]any
		fill := func(item map[string]any, id string, pairs ...string) {
			b, err := json.Marshal(item, json.Deterministic(true))
			if err != nil {
				t.Fatal(err)
			}
			s := strings.NewReplacer(append(pairs, common...)...).Replace(string(b))
			var m map[string]any
			if err := json.Unmarshal([]byte(s), &m); err != nil {
				t.Fatalf("%s/%s %s: %v", name, file, id, err)
			}
			m["id"] = id
			out = append(out, m)
		}
		for _, item := range doc[key] {
			base, _ := item["id"].(string)
			switch item["per"] {
			case "org":
				fill(item, base)
			case "repo":
				for _, r := range repos {
					fill(item, repoRuleID(base, r), "{{repository}}", "action.target.id == '"+r+"'", "{{repo}}", r)
				}
			default:
				t.Fatalf("%s/%s %s: per %v must be org or repo", name, file, base, item["per"])
			}
		}
		return out
	}
	var r m11Rendered
	r.rules = expand("policy.json", "rules")
	for _, rule := range r.rules {
		delete(rule, "per")
	}
	for _, c := range expand("tests.json", "tests") {
		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		var tc m11Case
		if err := json.Unmarshal(raw, &tc, json.RejectUnknownMembers(true)); err != nil {
			t.Fatalf("%s/tests.json %v: not in the D7 format: %v", name, c["id"], err)
		}
		r.cases = append(r.cases, tc)
	}
	return r
}

func (r m11Rendered) bundle(t *testing.T) *domain.Bundle {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"id": "org-policy", "version": 1, "rules": r.rules})
	if err != nil {
		t.Fatal(err)
	}
	var b domain.Bundle
	if err := json.Unmarshal(raw, &b, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	return &b
}

// m11Packages are the packages the templates may require, by name.
func m11Packages(t *testing.T) map[string]*defs.Package {
	t.Helper()
	out := map[string]*defs.Package{}
	for _, raw := range [][]byte{mockpayments.Package, pcgithub.Package, pcshell.Package} {
		p, err := manifest.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		for i := range p.Definitions {
			d := &p.Definitions[i]
			d.Digest = "sha256:" + p.Name + "/" + d.Operation
		}
		out[p.Name] = p
	}
	return out
}

func m11Definitions(pkgs map[string]*defs.Package) []*defs.Definition {
	var out []*defs.Definition
	for _, p := range pkgs {
		for i := range p.Definitions {
			out = append(out, &p.Definitions[i])
		}
	}
	return out
}

// m11Facts is the fact catalog the templates' rules may read: the
// payments package's prerequisite.
var m11Facts = map[string]fdomain.Type{"payments.charge.refundable": fdomain.TypeBoolean}

// TestM11TemplatesDisclose: every template, coding-to-production
// included, says what it protects, what it does not, and which packages
// and connections it needs (F176), and pclaw template show prints all of
// it.
func TestM11TemplatesDisclose(t *testing.T) {
	names, err := templateNames()
	if err != nil {
		t.Fatal(err)
	}
	if want := append([]string{"coding-to-production"}, m11Templates...); !slices.Equal(names, slices.Sorted(slices.Values(want))) {
		t.Fatalf("templates %v, want %v", names, want)
	}
	pkgs := m11Packages(t)
	for _, n := range names {
		info, err := readTemplateInfo(n)
		if err != nil {
			t.Fatal(err)
		}
		if info.Name != n || info.Summary == "" || info.TaskRef != "template:"+n || len(info.Protects) == 0 || len(info.Excludes) == 0 ||
			len(info.Requires.Packages) == 0 || len(info.Requires.Connections) == 0 {
			t.Errorf("%s: incomplete disclosure %+v", n, info)
		}
		for _, p := range info.Requires.Packages {
			if pkgs[p] == nil {
				t.Errorf("%s requires unknown package %s", n, p)
			}
		}
		var out, errs bytes.Buffer
		if code := Run(context.Background(), []string{"template", "show", n}, &out, &errs, envOf(nil), Options{}); code != 0 {
			t.Fatalf("show %s: %d %s", n, code, errs.String())
		}
		for _, line := range slices.Concat(info.Protects, info.Excludes, info.Requires.Packages, info.Requires.Connections) {
			if !strings.Contains(out.String(), "  - "+line+"\n") {
				t.Errorf("show %s leaves out %q", n, line)
			}
		}
	}
	var out, errs bytes.Buffer
	if code := Run(context.Background(), []string{"template", "list"}, &out, &errs, envOf(nil), Options{}); code != 0 {
		t.Fatalf("list: %d %s", code, errs.String())
	}
	for _, n := range names {
		if !strings.Contains(out.String(), n+" ") {
			t.Errorf("list leaves out %s:\n%s", n, out.String())
		}
	}
	for _, bad := range [][]string{{"template", "show", "nope"}, {"template", "show", "../refunds"}, {"template", "show"}, {"template", "list", "x"}} {
		if code := Run(context.Background(), bad, &out, &errs, envOf(nil), Options{}); code == 0 {
			t.Errorf("%v: exit 0", bad)
		}
	}
}

// TestM11TemplatesCompile: each template's rules, rendered for one and for
// two repositories, are a valid bundle whose approval roles exist and that
// compiles against the packages it requires.
func TestM11TemplatesCompile(t *testing.T) {
	pkgs := m11Packages(t)
	for _, n := range m11Templates {
		for _, repos := range [][]string{{"acme/web"}, {"acme/api", "acme/web"}} {
			t.Run(fmt.Sprintf("%s/%d", n, len(repos)), func(t *testing.T) {
				b := renderM11(t, n, repos).bundle(t)
				if err := b.CheckApprovalRoles(); err != nil {
					t.Fatal(err)
				}
				info, err := readTemplateInfo(n)
				if err != nil {
					t.Fatal(err)
				}
				own := map[string]*defs.Package{}
				for _, p := range info.Requires.Packages {
					own[p] = pkgs[p]
				}
				if _, err := (&polapp.Engine{Limits: celenv.DefaultLimits, Facts: m11Facts}).Compile(b, m11Definitions(own)); err != nil {
					t.Fatalf("%s does not compile against %v: %v", n, info.Requires.Packages, err)
				}
				for _, r := range b.Rules {
					if strings.Contains(r.When+r.Summary+strings.Join(r.Environments, ","), "{{") {
						t.Errorf("%s: a placeholder left in %s", n, r.ID)
					}
				}
			})
		}
	}
}

var (
	m11CaseIDRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	m11Outcomes = []string{"ALLOW", "ALLOW_WITH_OBLIGATIONS", "REQUIRE_STEP_UP", "REQUIRE_APPROVAL", "DENY", "CANNOT_AUTHORIZE"}
)

// TestM11TemplateTestsParse: each template's tests.json is in the D7
// format: at most 200 cases with unique ids, each acting on an operation
// of a required package with params its definition decodes, a known
// approval and step-up state, and a decision the pipeline can give with a
// reason code.
func TestM11TemplateTestsParse(t *testing.T) {
	pkgs := m11Packages(t)
	for _, n := range m11Templates {
		r := renderM11(t, n, []string{"acme/api", "acme/web"})
		info, err := readTemplateInfo(n)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.cases) == 0 || len(r.cases) > 200 {
			t.Fatalf("%s: %d cases", n, len(r.cases))
		}
		seen := map[string]bool{}
		for _, c := range r.cases {
			if !m11CaseIDRe.MatchString(c.ID) || seen[c.ID] {
				t.Errorf("%s: case id %q is malformed or repeated", n, c.ID)
			}
			seen[c.ID] = true
			d := m11Definition(pkgs, info.Requires.Packages, c.Action.Operation)
			if d == nil {
				t.Errorf("%s %s: operation %s is not in %v", n, c.ID, c.Action.Operation, info.Requires.Packages)
				continue
			}
			if _, err := d.DecodeParams(c.Action.Params); err != nil {
				t.Errorf("%s %s: params: %v", n, c.ID, err)
			}
			if c.Summary == "" || !slices.Contains(m11Outcomes, c.Expect.Decision) || !regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`).MatchString(c.Expect.Reason) {
				t.Errorf("%s %s: summary, decision or reason %+v", n, c.ID, c.Expect)
			}
			if !slices.Contains([]string{"", "none", "approved", "approved_other_action", "expired"}, c.Given.Approval) ||
				!slices.Contains([]string{"", "none", "done"}, c.Given.StepUp) {
				t.Errorf("%s %s: given %+v", n, c.ID, c.Given)
			}
			for f := range c.Given.Facts {
				if m11Facts[f] == "" {
					t.Errorf("%s %s: unknown fact %s", n, c.ID, f)
				}
			}
		}
	}
}

func m11Definition(pkgs map[string]*defs.Package, names []string, op string) *defs.Definition {
	for _, n := range names {
		if p := pkgs[n]; p != nil {
			if d, ok := p.Definition(op); ok {
				return d
			}
		}
	}
	return nil
}

// m11Decide evaluates one case with the policy engine alone and maps its
// outcome onto the pipeline's decision as the D7 fixture sets it up (a
// root grant covering the action, nothing else in the way): no rule
// deciding is ALLOW for GRANT_COVERS, and an approved hold is ALLOW.
func m11Decide(t *testing.T, c *polapp.Compiled, d *defs.Definition, tc m11Case) (decision, reason, rule string, err error) {
	t.Helper()
	facts := map[string]fdomain.Value{}
	for name, f := range tc.Given.Facts {
		var b bool
		if err := json.Unmarshal(f.Value, &b); err != nil {
			t.Fatalf("%s: fact %s: %v", tc.ID, name, err)
		}
		facts[name] = fdomain.Value{Type: fdomain.TypeBoolean, Bool: b}
	}
	a := actionir.ActionIR{
		Operation: d.Operation, Definition: actionir.Definition{Digest: d.Digest}, Env: tc.Action.Environment,
		Target: actionir.Target{Type: d.Target.Type, ID: tc.Action.Target}, Params: tc.Action.Params,
	}
	out, err := c.Evaluate(context.Background(), d, a, polapp.Input{Budget: polapp.DefaultBudget, Facts: facts})
	if err != nil {
		return "", "", "", err
	}
	item, _ := out.Decisive()
	switch out.Verdict {
	case domain.VerdictPass, domain.VerdictConstrain:
		return "ALLOW", "GRANT_COVERS", "", nil
	case domain.VerdictRequireApproval:
		if tc.Given.Approval == "approved" {
			return "ALLOW", "GRANT_COVERS", "", nil
		}
	case domain.VerdictRequireStepUp:
		if tc.Given.StepUp == "done" {
			return "ALLOW", "GRANT_COVERS", "", nil
		}
	case domain.VerdictDeny, domain.VerdictCannotAuthorize:
	}
	return string(out.Verdict), item.Reason, item.Rule, nil
}

// m11Failures runs every case against a bundle and returns the ids of the
// cases whose decision, reason or rule differ from what they expect.
func m11Failures(t *testing.T, b *domain.Bundle, defsList []*defs.Definition, cases []m11Case, pkgs map[string]*defs.Package, required []string) ([]string, error) {
	t.Helper()
	c, err := (&polapp.Engine{Limits: celenv.DefaultLimits, Facts: m11Facts}).Compile(b, defsList)
	if err != nil {
		return nil, err
	}
	var failed []string
	for _, tc := range cases {
		d := m11Definition(pkgs, required, tc.Action.Operation)
		decision, reason, rule, err := m11Decide(t, c, d, tc)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", tc.ID, err)
		}
		if decision != tc.Expect.Decision || reason != tc.Expect.Reason || (tc.Expect.Rule != "" && rule != tc.Expect.Rule) {
			failed = append(failed, fmt.Sprintf("%s: got %s %s %s, want %+v", tc.ID, decision, reason, rule, tc.Expect))
		}
	}
	return failed, nil
}

// TestHR044_M11TemplateTestsKillEveryMutant: evaluated with the policy
// engine, every case of every template holds, for one repository and for
// two; and every comparison flip in every rule's condition (Mutants) and
// the removal of every rule each make at least one case fail. A threshold
// or equality no case pins would let a weakened rule pass the gate.
func TestHR044_M11TemplateTestsKillEveryMutant(t *testing.T) {
	pkgs := m11Packages(t)
	for _, n := range m11Templates {
		for _, repos := range [][]string{{"acme/web"}, {"acme/api", "acme/web"}} {
			t.Run(fmt.Sprintf("%s/%d", n, len(repos)), func(t *testing.T) {
				info, err := readTemplateInfo(n)
				if err != nil {
					t.Fatal(err)
				}
				own := map[string]*defs.Package{}
				for _, p := range info.Requires.Packages {
					own[p] = pkgs[p]
				}
				ds := m11Definitions(own)
				r := renderM11(t, n, repos)
				b := r.bundle(t)
				failed, err := m11Failures(t, b, ds, r.cases, pkgs, info.Requires.Packages)
				if err != nil || len(failed) > 0 {
					t.Fatalf("the template's own cases: %v\n%s", err, strings.Join(failed, "\n"))
				}
				killed := func(m *domain.Bundle, what string) {
					t.Helper()
					failed, err := m11Failures(t, m, ds, r.cases, pkgs, info.Requires.Packages)
					if errors.Is(err, domain.ErrInvalid) {
						t.Fatalf("%s does not compile: %v", what, err)
					}
					if err == nil && len(failed) == 0 {
						t.Errorf("mutant survives: %s", what)
					}
				}
				for i, rule := range b.Rules {
					mutants, err := polapp.Mutants(rule.When)
					if err != nil {
						t.Fatal(err)
					}
					for _, m := range mutants {
						mb := *b
						mb.Rules = slices.Clone(b.Rules)
						mb.Rules[i].When = m
						killed(&mb, rule.ID+" when "+m)
					}
					if rule.Kind == domain.Annotate {
						continue
					}
					mb := *b
					mb.Rules = slices.Delete(slices.Clone(b.Rules), i, i+1)
					if len(mb.Rules) == 0 {
						// A bundle has at least one rule: removing the last
						// is a bundle that forbids nothing in its scope.
						mb.Rules = []domain.Rule{{ID: "noop", Kind: domain.Forbid, Summary: "nothing", Operations: rule.Operations, When: "false", Reason: "NOOP"}}
					}
					killed(&mb, "without "+rule.ID)
				}
			})
		}
	}
}

// TestM11DiagnosticsCommands: the production-diagnostics rules, compiled
// and evaluated as the server does, allow single reading commands and
// refuse chaining, substitution, redirection, network and writing
// commands, including spellings that hide them.
func TestM11DiagnosticsCommands(t *testing.T) {
	pkgs := m11Packages(t)
	shell, _ := pkgs["pc.shell"].Definition("shell.command.run")
	c, err := (&polapp.Engine{Limits: celenv.DefaultLimits}).Compile(renderM11(t, "production-diagnostics", nil).bundle(t), []*defs.Definition{shell})
	if err != nil {
		t.Fatal(err)
	}
	decide := func(command string) string {
		t.Helper()
		params, err := json.Marshal(map[string]string{"shell": "bash", "command": command, "cwd": exampleWorkspace, "call": "toolu_1"})
		if err != nil {
			t.Fatal(err)
		}
		tc := m11Case{ID: "x"}
		tc.Action.Environment, tc.Action.Target, tc.Action.Params = exampleEnvironmentID, "local", params
		decision, _, _, err := m11Decide(t, c, shell, tc)
		if err != nil {
			t.Fatalf("%q: %v", command, err)
		}
		return decision
	}
	for _, cmd := range []string{"ls -la", "cat /var/log/app.log", "  tail -n 50 app.log", "grep -rn 'timeout' logs", "ps aux", "df -h", "du -sh .", "uptime", "lsof -i"} {
		if d := decide(cmd); d != "ALLOW" {
			t.Errorf("%q: %s, want ALLOW", cmd, d)
		}
	}
	for _, cmd := range []string{
		"ls; rm -rf /", "ls && reboot", "cat a | sh", "cat $(echo x)", "cat `id`", "ls\nrm x","cat < /etc/passwd",
		"cat x > y", "cat x >> y", "echo hi", "env rm x", "find . -delete", "sed -i s/a/b/ f", "/bin/rm x", "python3 -c 'print(1)'",
		"curl http://x", "wget x", "ssh host", "lsof -i; nc -l 80", "ls \\nrm", "grep x f || touch y", "",
	} {
		if d := decide(cmd); d != "DENY" {
			t.Errorf("%q: %s, want DENY", cmd, d)
		}
	}
}
