// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"encoding/json/v2"
	"errors"
	"flag"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"
)

func templateOpts(t *testing.T, args ...string) (templateOptions, error) {
	t.Helper()
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	o := templateOptions{name: "coding-to-production"}
	check := templateFlags(fs, &o)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return o, check()
}

func TestTemplateFlags(t *testing.T) {
	o, err := templateOpts(t, "--repos", "acme/web, acme/api,acme/web", "--default-branch", "trunk", "--default-branch", "acme/api=develop")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(o.repos, ",") != "acme/api,acme/web" || o.defaults["acme/api"] != "develop" || o.defaults["acme/web"] != "trunk" {
		t.Fatalf("repos %v, defaults %v", o.repos, o.defaults)
	}
	if o.environment != "production" || o.timeZone != "UTC" || o.expires.Hours() != 720 {
		t.Fatalf("defaults: %+v", o)
	}
	for _, bad := range [][]string{
		{},
		{"--repos", "Acme/Web"},
		{"--repos", "acme/web", "--default-branch", "acme/other=main"},
		{"--repos", "acme/web", "--default-branch", "../x"},
		{"--repos", "acme/web", "--team", "not-an-id"},
		{"--repos", "acme/web", "--team", "01890000-0000-7000-8000-000000000001", "--bu", "01890000-0000-7000-8000-000000000002"},
		{"--repos", "acme/web", "--expires", "-1h"},
	} {
		if _, err := templateOpts(t, bad...); err == nil {
			t.Errorf("%v: accepted", bad)
		}
	}
}

func TestTemplateRender(t *testing.T) {
	o, err := templateOpts(t, "--repos", "acme/web,acme/api", "--default-branch", "acme/api=develop", "--time-zone", "Europe/London")
	if err != nil {
		t.Fatal(err)
	}
	d, err := renderTemplate(o)
	if err != nil {
		t.Fatal(err)
	}
	rules := map[string]map[string]any{}
	for _, r := range d.Rules {
		rules[r["id"].(string)] = r
	}
	if len(rules) != 6 || len(d.Skipped) != 1 {
		t.Fatalf("rules without an agent: %v, skipped %v", ruleIDs(d.Rules), d.Skipped)
	}
	for id, want := range map[string]string{
		repoRuleID("c2p-merge-review", "acme/api"):            `action.target.id.startsWith('acme/api#')`,
		repoRuleID("c2p-merge-review", "acme/web"):            `action.target.id.startsWith('acme/web#')`,
		repoRuleID("c2p-release", "acme/api"):                 `action.target.id == 'acme/api'`,
		repoRuleID("c2p-no-default-branch-write", "acme/api"): `action.target.id == 'acme/api@refs/heads/develop'`,
		repoRuleID("c2p-no-default-branch-write", "acme/web"): `action.target.id == 'acme/web@refs/heads/main'`,
	} {
		if rules[id]["when"] != want {
			t.Errorf("%s when %q, want %q", id, rules[id]["when"], want)
		}
		if _, ok := rules[id]["per"]; ok {
			t.Errorf("%s keeps the template's per", id)
		}
	}
	bounds := string(d.Envelope.Bounds)
	for _, want := range []string{`"acme/api"`, `"acme/web"`, `"acme/api#"`, `"acme/web@"`} {
		if !strings.Contains(bounds, want) || !strings.Contains(string(d.Grant.Bounds), want) {
			t.Errorf("bounds lack %s: %s / %s", want, bounds, d.Grant.Bounds)
		}
	}
	if strings.Contains(bounds+string(d.Grant.Bounds), "{{") {
		t.Fatalf("a placeholder left: %s %s", bounds, d.Grant.Bounds)
	}
	var limits struct {
		Counters []struct {
			Key string `json:"key"`
			Max string `json:"max"`
		} `json:"counters"`
	}
	if err := json.Unmarshal(d.Grant.Limits, &limits); err != nil || len(limits.Counters) != 1 || limits.Counters[0].Max != "1" || limits.Counters[0].Key != "run" {
		t.Fatalf("limits %s: %v", d.Grant.Limits, err)
	}
	if d.Window.GetEnvironment() != "production" || d.Window.GetTimeZone() != "Europe/London" || len(d.Window.GetWeekly()) != 5 {
		t.Fatalf("window %+v", d.Window)
	}
	if d.TaskRef != "template:coding-to-production" {
		t.Fatalf("task_ref %q", d.TaskRef)
	}
	if _, err := renderTemplate(templateOptions{name: "nope"}); err == nil {
		t.Fatal("rendered a template that does not exist")
	}
}

// TestTemplateShellRule checks the shell rule's pattern (RE2, as CEL's
// matches) against commands it must and must not forbid.
func TestTemplateShellRule(t *testing.T) {
	o, err := templateOpts(t, "--repos", "acme/web")
	if err != nil {
		t.Fatal(err)
	}
	const agent = "01890000-0000-7000-8000-00000000000a"
	o.agent = agent
	d, err := renderTemplate(o)
	if err != nil {
		t.Fatal(err)
	}
	var when string
	for _, r := range d.Rules {
		if r["id"] == "c2p-no-shell-merge--"+agent {
			when, _ = r["when"].(string)
		}
	}
	if !strings.HasPrefix(when, "run.agent_id == '"+agent+"' && ") {
		t.Fatalf("the shell rule is not the agent's: %q", when)
	}
	m := regexp.MustCompile(`matches\(r'(.*)'\)$`).FindStringSubmatch(when)
	if m == nil {
		t.Fatalf("shell rule when %q", when)
	}
	re := regexp.MustCompile(m[1]) // a CEL raw string: the pattern as RE2 reads it
	for _, c := range []string{
		"git push", "git push origin main", "cd x && git  push", "gh pr merge 1", "true; gh pr merge --squash",
		"gh api -X PUT repos/acme/web/pulls/1/merge", "(git push)",
		"git -C dir push", "git -c k=v push", "git --no-pager push", "/usr/bin/git push", "env git push", "gh -R acme/web pr merge 1",
	} {
		if !re.MatchString(c) {
			t.Errorf("%q is not forbidden", c)
		}
	}
	for _, c := range []string{"git status", "gh pr view 1", "gh api repos/acme/web/pulls", "git pushd", "echo legit-push", "git log --grep push", "legit push"} {
		if re.MatchString(c) {
			t.Errorf("%q is forbidden", c)
		}
	}
}

func TestAgentOfIdentifier(t *testing.T) {
	const id = "01890000-0000-7000-8000-00000000000a"
	if got := agentOfIdentifier("pc:org/01890000-0000-7000-8000-000000000001/agent/" + id + "/inst/01890000-0000-7000-8000-000000000002"); got != id {
		t.Fatalf("agent %q", got)
	}
	if got := agentOfIdentifier("pc:org/x"); got != "" {
		t.Fatalf("agent of a bad identifier %q", got)
	}
}

// TestTemplateInitChecksFirst: init --template checks the template's options
// before it writes anything.
func TestTemplateInitChecksFirst(t *testing.T) {
	for _, bad := range [][]string{
		{"--template", "coding-to-production"},
		{"--template", "coding-to-production", "--repos", "Acme/Web"},
		{"--template", "coding-to-production", "--repos", "acme/web", "--default-branch", "acme/api=main"},
	} {
		f := newInitFixture(t)
		if code, out, errs := f.run(t, append(bad, "--yes")...); code == 0 {
			t.Fatalf("%v: %d %s %s", bad, code, out, errs)
		}
		if _, err := os.Stat(f.local()); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%v: init wrote %s (%v)", bad, f.local(), err)
		}
	}
}

// TestRepoRuleID: repositories that differ only in case or punctuation get
// different rule ids, every id is a valid policy rule id, and a long name
// is cut with its hash kept.
func TestRepoRuleID(t *testing.T) {
	valid := regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	seen := map[string]string{}
	long := "acme/" + strings.Repeat("r", 100)
	for _, repo := range []string{"acme/web", "Acme/Web", "acme/we-b", "acme/we.b", "acme/we_b", "acme-we/b", long, long + "x"} {
		id := repoRuleID("c2p-no-default-branch-write", repo)
		if !valid.MatchString(id) {
			t.Errorf("%s: id %q is not a rule id", repo, id)
		}
		if other, ok := seen[id]; ok {
			t.Errorf("%s and %s share the id %s", repo, other, id)
		}
		seen[id] = repo
	}
	if id := repoRuleID("c2p-release", "acme/web"); !strings.HasPrefix(id, "c2p-release--acme-web-") || len(id) != len("c2p-release--acme-web-")+6 {
		t.Errorf("id %q", id)
	}
}
