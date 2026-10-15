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
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	polapp "github.com/katocxl/pantherclaw/internal/policy/app"
	"github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/policy/scenario"
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
	exampleOtherEnvID    = otherEnvironmentID
	exampleWorkspace     = "/srv/app"
)

// m11Case is one scenario test in the D7 format, decoded strictly.
type m11Case struct {
	ID      string `json:"id"`
	Per     string `json:"per"`
	Summary string `json:"summary"`
	Action  struct {
		Operation   string           `json:"operation"`
		Environment string           `json:"environment,omitzero"`
		Target      *actionir.Target `json:"target,omitzero"`
		Params      jsontext.Value   `json:"params"`
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
		// Agent sets the fixture agent and its run (D20).
		Agent string `json:"agent,omitzero"`
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
	// raw are the rendered cases as JSON objects.
	raw []map[string]any
}

// renderM11 renders a template with the product renderer (renderTemplate)
// for repositories and example values, as apply does once the environment's
// id is read.
func renderM11(t *testing.T, name string, repos []string) m11Rendered {
	t.Helper()
	return renderM11Env(t, name, repos, "production")
}

func renderM11Env(t *testing.T, name string, repos []string, environment string) m11Rendered {
	t.Helper()
	o := templateOptions{
		name: name, environment: environment, timeZone: "UTC", defaults: map[string]string{}, agent: templateAgent,
		environmentID: exampleEnvironmentID, workspace: exampleWorkspace,
	}
	info, err := readTemplateInfo(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := info.Placeholders[kindRepository]; ok {
		o.repos = repos
		for _, r := range repos {
			o.defaults[r] = "main"
		}
	}
	for _, k := range []string{kindEnvironmentID, kindWorkspace, kindAgent} {
		if _, ok := info.Placeholders[k]; !ok {
			switch k {
			case kindEnvironmentID:
				o.environmentID = ""
			case kindWorkspace:
				o.workspace = ""
			case kindAgent:
				o.agent = ""
			}
		}
	}
	d, err := renderTemplate(o)
	if err != nil {
		t.Fatalf("render %s: %v", name, err)
	}
	r := m11Rendered{rules: d.Rules, raw: d.Tests}
	for _, c := range d.Tests {
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
// it. Traversal out of production-diagnostics' workspace is not a D7 case:
// a non-normalized cwd is refused before the rules (HR-187), and through
// the shell hook it is normalized and denied (TestM11DiagnosticsTraversal).
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
		var b struct {
			Bool bool `json:"bool"`
		}
		if err := json.Unmarshal(f.Value, &b); err != nil {
			t.Fatalf("%s: fact %s: %v", tc.ID, name, err)
		}
		facts[name] = fdomain.Value{Type: fdomain.TypeBoolean, Bool: b.Bool}
	}
	a := actionir.ActionIR{
		Operation: d.Operation, Definition: actionir.Definition{Digest: d.Digest}, Env: tc.Action.Environment,
		Target: *tc.Action.Target, Params: tc.Action.Params,
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
		for _, rc := range []struct {
			repos []string
			env   string
		}{{[]string{"acme/web"}, "production"}, {[]string{"acme/api", "acme/web"}, "production"}, {[]string{"acme/web"}, "staging"}} {
			repos := rc.repos
			t.Run(fmt.Sprintf("%s/%d/%s", n, len(repos), rc.env), func(t *testing.T) {
				info, err := readTemplateInfo(n)
				if err != nil {
					t.Fatal(err)
				}
				own := map[string]*defs.Package{}
				for _, p := range info.Requires.Packages {
					own[p] = pkgs[p]
				}
				ds := m11Definitions(own)
				r := renderM11Env(t, n, repos, rc.env)
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
		tc.Action.Environment, tc.Action.Target, tc.Action.Params = exampleEnvironmentID, &actionir.Target{Type: "shell.workspace", ID: "local"}, params
		decision, _, _, err := m11Decide(t, c, shell, tc)
		if err != nil {
			t.Fatalf("%q: %v", command, err)
		}
		return decision
	}
	for _, cmd := range []string{"ls -la", "cat /var/log/app.log", "  tail -n 50 app.log", "grep -rn 'timeout' logs", "ps aux", "df -h", "du -sh .", "uptime", "lsof -i", "ls\t-la", "grep\t-c\tERROR app.log"} {
		if d := decide(cmd); d != "ALLOW" {
			t.Errorf("%q: %s, want ALLOW", cmd, d)
		}
	}
	for _, cmd := range []string{
		"ls; rm -rf /", "ls && reboot", "cat a | sh", "cat $(echo x)", "cat `id`", "ls\nrm x", "ls\npython3 fix.py", "ls\nsh evil.sh", "cat \n bash x.sh", "cat < /etc/passwd",
		"cat x > y", "cat x >> y", "echo hi", "env rm x", "find . -delete", "sed -i s/a/b/ f", "/bin/rm x", "python3 -c 'print(1)'",
		"curl http://x", "wget x", "ssh host", "lsof -i; nc -l 80", "ls \\nrm", "grep x f || touch y", "",
	} {
		if d := decide(cmd); d != "DENY" {
			t.Errorf("%q: %s, want DENY", cmd, d)
		}
	}
	// Other control characters never reach the rules: the command param
	// refuses them (HR-102). pd-control-character also forbids them, in
	// case that check ever loosens.
	for _, cmd := range []string{"ls\x0bpython3 x", "ls\x1b[2Jid", "ls\x7f", "ls\rpython3 x"} {
		params, err := json.Marshal(map[string]string{"shell": "bash", "command": cmd, "cwd": exampleWorkspace, "call": "toolu_1"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := shell.DecodeParams(params); !errors.Is(err, actionir.ErrAmbiguous) {
			t.Errorf("%q: %v, want ambiguous", cmd, err)
		}
	}
	for _, cmd := range []string{"ls\x0bpython3 x", "ls\x1b[2Jid", "ls\x7f", "ls\rpython3 x", "ls\npython3 x"} {
		if !regexp.MustCompile(`[\x00-\x08\x0a-\x1f\x7f]`).MatchString(cmd) {
			t.Errorf("%q: the control-character pattern misses it", cmd)
		}
	}
}

// TestM11DiagnosticsTraversal: a working directory that climbs out of the
// workspace (/srv/app/../etc) is refused. Through the shell hook the
// mapping normalizes it (normpath) to /etc, which pd-workspace denies; as
// a raw action it is not a normalized path, so it is ambiguous and never
// reaches the rules (HR-187, CANNOT_AUTHORIZE upstream).
func TestM11DiagnosticsTraversal(t *testing.T) {
	pkg, err := manifest.Decode(pcshell.Package)
	if err != nil {
		t.Fatal(err)
	}
	shell, _ := pkg.Definition("shell.command.run")
	c, err := (&polapp.Engine{Limits: celenv.DefaultLimits}).Compile(renderM11(t, "production-diagnostics", nil).bundle(t), []*defs.Definition{shell})
	if err != nil {
		t.Fatal(err)
	}
	m, err := mapping.New(pkg, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	for _, cwd := range []string{exampleWorkspace + "/../etc", exampleWorkspace + "/logs/../../etc", exampleWorkspace + "/./../app-other"} {
		input, err := json.Marshal(map[string]string{"shell": "bash", "command": "ls", "cwd": cwd, "call": "toolu_1"})
		if err != nil {
			t.Fatal(err)
		}
		p, err := m.Hook(context.Background(), mapping.Context{
			Org: "01890000-0000-7000-8000-000000000001", Env: exampleEnvironmentID, RunID: "01890000-0000-7000-8000-000000000003",
			ActionID: "01890000-0000-7000-8000-000000000004", AgentInstance: "01890000-0000-7000-8000-000000000005",
		}, "shell", input)
		if err != nil {
			t.Fatalf("%s: %v", cwd, err)
		}
		out, err := c.Evaluate(context.Background(), shell, p.Action, polapp.Input{Budget: polapp.DefaultBudget})
		if err != nil {
			t.Fatal(err)
		}
		if item, _ := out.Decisive(); out.Verdict != domain.VerdictDeny || item.Rule != "pd-workspace" {
			t.Errorf("%s: %s by %s, want DENY by pd-workspace", cwd, out.Verdict, item.Rule)
		}
		raw, err := json.Marshal(map[string]string{"shell": "bash", "command": "ls", "cwd": cwd, "call": "toolu_1"})
		if err != nil {
			t.Fatal(err)
		}
		a := actionir.ActionIR{
			Operation: shell.Operation, Definition: actionir.Definition{Digest: shell.Digest}, Env: exampleEnvironmentID,
			Target: actionir.Target{Type: "shell.workspace", ID: "local"}, Params: raw,
		}
		if _, err := c.Evaluate(context.Background(), shell, a, polapp.Input{Budget: polapp.DefaultBudget}); !errors.Is(err, actionir.ErrAmbiguous) {
			t.Errorf("raw %s: %v, want ambiguous", cwd, err)
		}
	}
}

// TestM11ReleaseConsequenceHeld: a deployment that is a consequence of a
// merge names no environment when the merge is decided; rd-environment
// leaves it to rd-release, which holds it for a release approver, whatever
// environment the template was applied for (D21). The D7 format has no
// consequence, so this case lives here.
func TestM11ReleaseConsequenceHeld(t *testing.T) {
	pkgs := m11Packages(t)
	deploy, _ := pkgs["pc.github"].Definition("github.deployment.trigger")
	for _, env := range []string{"production", "staging"} {
		c, err := (&polapp.Engine{Limits: celenv.DefaultLimits}).Compile(renderM11Env(t, "release-deployment", []string{"acme/web"}, env).bundle(t), []*defs.Definition{deploy})
		if err != nil {
			t.Fatal(err)
		}
		a := actionir.ActionIR{
			Operation: deploy.Operation, Definition: actionir.Definition{Digest: deploy.Digest},
			Target: actionir.Target{Type: "github.repository", ID: "acme/web"}, Params: jsontext.Value(`{}`),
		}
		for _, state := range []string{"PREDICTED", "UNKNOWN"} {
			out, err := c.Evaluate(context.Background(), deploy, a, polapp.Input{Budget: polapp.DefaultBudget, Consequence: &polapp.Consequence{Rule: "r", State: state}})
			if err != nil {
				t.Fatal(err)
			}
			if item, _ := out.Decisive(); out.Verdict != domain.VerdictRequireApproval || item.Reason != "DEPLOYMENT_NEEDS_RELEASE" {
				t.Errorf("%s, %s consequence: %s %s, want REQUIRE_APPROVAL DEPLOYMENT_NEEDS_RELEASE", env, state, out.Verdict, item.Reason)
			}
		}
	}
}

// m11World is the read side of the scenario runner: the templates'
// packages, with their own digests, and the fact catalog.
type m11World struct{ defs []*defs.Definition }

func (w m11World) ActiveDefinitions(context.Context, ids.OrgID) ([]*defs.Definition, error) {
	return w.defs, nil
}

func (m11World) Catalog(context.Context, ids.OrgID) (map[string]fdomain.Type, error) {
	return maps.Clone(m11Facts), nil
}

// TestM11TemplatesPassTheGate: each template's rules and tests, rendered,
// pass the publish gate's test runner (M11.1 D7, HR-044): every case
// decided by the real pipeline as it expects, and every comparison mutant
// and rule removal killed.
func TestM11TemplatesPassTheGate(t *testing.T) {
	var ds []*defs.Definition
	for _, raw := range [][]byte{mockpayments.Package, pcgithub.Package, pcshell.Package} {
		p, err := manifest.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		for i := range p.Definitions {
			ds = append(ds, &p.Definitions[i])
		}
	}
	org := ids.MustParse[ids.Org]("01890000-0000-7000-8000-000000000001")
	for _, n := range []string{"production-diagnostics", "refunds"} {
		for _, env := range []string{"production", "staging"} {
			t.Run(n+"/"+env, func(t *testing.T) {
				r := renderM11Env(t, n, []string{"acme/api", "acme/web"}, env)
				b := r.bundle(t)
				for _, c := range r.raw {
					delete(c, "per")
				}
				raw, err := json.Marshal(r.raw)
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(raw, &b.Tests, json.RejectUnknownMembers(true)); err != nil {
					t.Fatal(err)
				}
				res, err := scenario.New(m11World{ds}, m11World{ds}, celenv.DefaultLimits, polapp.DefaultBudget).Run(context.Background(), org, b)
				if err != nil {
					t.Fatal(err)
				}
				for _, c := range res.Cases {
					if !c.Passed {
						t.Errorf("case %s: %s", c.ID, c.Detail)
					}
				}
				for _, m := range res.Surviving {
					t.Errorf("mutant survives: %s %s", m.Rule, m.Mutation)
				}
				t.Logf("%d cases, %d mutants, %d survivors", len(res.Cases), res.Mutants, res.Survivors)
				if !res.Passed || res.Error != "" {
					t.Errorf("gate: passed %v, error %q, %d mutants", res.Passed, res.Error, res.Mutants)
				}
			})
		}
	}
}

// TestM11PlaceholdersAreChecked: a value that breaks its placeholder's
// declared pattern or kind is refused before anything is rendered, and
// every value that reaches a condition is a quoted CEL literal (M11.1
// D27): a quote in a value can never end the literal.
func TestM11PlaceholdersAreChecked(t *testing.T) {
	base := templateOptions{
		name: "production-diagnostics", environment: "production", environmentID: exampleEnvironmentID, workspace: exampleWorkspace, timeZone: "UTC",
	}
	if _, err := renderTemplate(base); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*templateOptions){
		"environment with a quote": func(o *templateOptions) { o.environment = "prod'uction" },
		"environment upper case":   func(o *templateOptions) { o.environment = "Production" },
		"environment id":           func(o *templateOptions) { o.environmentID = "production" },
		"relative workspace":       func(o *templateOptions) { o.workspace = "srv/app" },
		"workspace not normalized": func(o *templateOptions) { o.workspace = "/srv/app/../etc" },
		"workspace with a quote":   func(o *templateOptions) { o.workspace = "/srv/a'pp" },
		"workspace with a newline": func(o *templateOptions) { o.workspace = "/srv/a\npp" },
		"workspace trailing slash": func(o *templateOptions) { o.workspace = "/srv/app/" },
	} {
		o := base
		edit(&o)
		if _, err := renderTemplate(o); err == nil {
			t.Errorf("%s: rendered", name)
		}
	}
	rd := templateOptions{name: "release-deployment", environment: "production", timeZone: "UTC", repos: []string{"acme/web"}, defaults: map[string]string{"acme/web": "main"}}
	if _, err := renderTemplate(rd); err != nil {
		t.Fatal(err)
	}
	rd.repos = []string{"acme/we'b"}
	if _, err := renderTemplate(rd); err == nil {
		t.Error("a repository with a quote rendered")
	}
	for in, want := range map[string]string{`a'b`: `'a\'b'`, `a\b`: `'a` + `\\` + `b'`, "a\nb": `'a\x0ab'`, "plain/x": `'plain/x'`} {
		if got := celQuote(in); got != want {
			t.Errorf("celQuote(%q) = %s, want %s", in, got, want)
		}
	}
	// A placeholder the template does not declare is an error, in a
	// condition or not, and a condition-only placeholder stays in one.
	r := renderer{o: base, spec: map[string]placeholderSpec{kindEnvironment: {Kind: kindEnvironment, Pattern: "^[a-z]+$"}}}
	for _, s := range []string{"{{workspace}}", "{{agent}}", "{{nope}}", "{{repository}}"} {
		if _, err := r.fill(s, "", true); err == nil {
			t.Errorf("%s filled without a declaration", s)
		}
	}
	if got, err := r.fill("env == {{environment}}", "", true); err != nil || got != "env == 'production'" {
		t.Errorf("condition: %q %v", got, err)
	}
	if got, err := r.fill("for {{environment}}", "", false); err != nil || got != "for production" {
		t.Errorf("text: %q %v", got, err)
	}
}

// TestM11NoQuotedPlaceholders: no template writes a placeholder inside a
// string literal of a condition, where it would bypass celQuote.
func TestM11NoQuotedPlaceholders(t *testing.T) {
	names, err := templateNames()
	if err != nil {
		t.Fatal(err)
	}
	quoted := regexp.MustCompile(`'[^']*\{\{[a-z_]+\}\}[^']*'`)
	for _, n := range names {
		raw, err := fs.ReadFile(templates.FS, n+"/policy.json")
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Rules []struct {
				ID   string `json:"id"`
				When string `json:"when"`
			} `json:"rules"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		for _, r := range doc.Rules {
			if m := quoted.FindString(r.When); m != "" {
				t.Errorf("%s rule %s: placeholder inside a literal: %s", n, r.ID, m)
			}
		}
	}
}
