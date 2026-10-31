// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package offline_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/policy/offline"
	"github.com/katocxl/pantherclaw/internal/policy/scenario"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
)

// bundle is a policy that passes the publish gate: a hard cap on refunds,
// and cases that kill every mutant.
func bundle(limit string) map[string]any {
	refund := func(id, amount, decision, reason, rule string) map[string]any {
		c := map[string]any{
			"id": id, "summary": "a refund of " + amount,
			"action": map[string]any{
				"operation": "payments.refund.create", "target": map[string]any{"type": "payments.charge", "id": "ch_1"},
				"params": map[string]any{"amount": map[string]any{"value": amount, "currency": "USD"}, "reason": "duplicate"},
			},
			"given":  map[string]any{"facts": map[string]any{"payments.charge.refundable": map[string]any{"value": map[string]any{"bool": true}, "age_seconds": 10}}},
			"expect": map[string]any{"decision": decision, "reason": reason},
		}
		if rule != "" {
			c["expect"].(map[string]any)["rule"] = rule
		}
		return c
	}
	return map[string]any{
		"id": "refunds",
		"rules": []map[string]any{{
			"id": "cap", "kind": "CONSTRAIN", "summary": "no refund above the cap",
			"operations": []string{"payments.refund.create"}, "when": "true", "reason": "REFUND_OVER_CAP",
			"constraint": map[string]any{"kind": "amount_max", "param": "amount", "max": limit, "currency": "USD"},
		}},
		"tests": []map[string]any{
			refund("under", "10.00", "ALLOW", "GRANT_COVERS", ""),
			refund("over", "9999.00", "DENY", "REFUND_OVER_CAP", "cap"),
		},
	}
}

func write(t *testing.T, doc any) string {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func check(t *testing.T, o offline.Options) *offline.Report {
	t.Helper()
	r, err := offline.Check(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestD120_ABundleThroughTheGateFromFiles: the real validator, scenario
// runner and mutation gate, with no server (D120), over built-in packages
// and over a directory of them, with the fixture's fact typed by its value.
func TestD120_ABundleThroughTheGateFromFiles(t *testing.T) {
	policy := write(t, bundle("500.00"))
	r := check(t, offline.Options{PolicyFile: policy})
	if !r.Passed {
		t.Fatalf("failed: %s", r.Text())
	}
	if len(r.Scenarios.Cases) != 2 || r.Scenarios.Mutants == 0 {
		t.Fatalf("scenarios: %+v", r.Scenarios)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "payments.package.yaml"), mockpayments.Package, 0o600); err != nil {
		t.Fatal(err)
	}
	if r := check(t, offline.Options{PolicyFile: policy, PackagesDir: dir}); !r.Passed {
		t.Fatalf("with --packages: %s", r.Text())
	}

	// A directory replaces the built-in packages.
	gh := bundle("500.00")
	gh["rules"].([]map[string]any)[0]["operations"] = []string{"github.pull.merge"}
	if r := check(t, offline.Options{PolicyFile: write(t, gh), PackagesDir: dir}); r.Passed || r.Validation.Passed {
		t.Fatalf("an operation outside the directory passed: %s", r.Text())
	}
}

// TestD120_BuiltInPackagesNeverCollide: a case can always tell which
// definition decides.
func TestD120_BuiltInPackagesNeverCollide(t *testing.T) {
	seen := map[string]string{}
	for _, raw := range offline.Builtin() {
		p, err := manifest.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		for i := range p.Definitions {
			op := p.Definitions[i].Operation
			if other, dup := seen[op]; dup {
				t.Errorf("%s is in %s and %s", op, other, p.Name)
			}
			seen[op] = p.Name
		}
	}
}

// TestD120_FactsFileDeclaresWhatRulesRead: a rule's fact needs a
// declaration; facts.json gives it, and without it validation fails.
func TestD120_FactsFileDeclaresWhatRulesRead(t *testing.T) {
	b := bundle("500.00")
	rule := b["rules"].([]map[string]any)[0]
	rule["facts"] = []map[string]any{{"name": "risk.score", "max_age_seconds": 60}}
	policy := write(t, b)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.yaml"), mockpayments.Package, 0o600); err != nil {
		t.Fatal(err)
	}
	r := check(t, offline.Options{PolicyFile: policy, PackagesDir: dir})
	if !slices.ContainsFunc(r.Validation.Findings, func(f pdomain.Finding) bool { return f.Code == "FACT_UNKNOWN" }) {
		t.Fatalf("no FACT_UNKNOWN: %s", r.Text())
	}
	if err := os.WriteFile(filepath.Join(dir, offline.FactsFile), []byte(`{"facts":[{"name":"risk.score","type":"integer"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r = check(t, offline.Options{PolicyFile: policy, PackagesDir: dir})
	if slices.ContainsFunc(r.Validation.Findings, func(f pdomain.Finding) bool { return f.Code == "FACT_UNKNOWN" }) {
		t.Fatalf("still FACT_UNKNOWN: %s", r.Text())
	}
}

// TestD121_ScenariosAddToTheBundlesTests: fixtures run with the bundle's
// own tests, and a failing one fails the check.
func TestD121_ScenariosAddToTheBundlesTests(t *testing.T) {
	b := bundle("500.00")
	tests := b["tests"]
	delete(b, "tests")
	dir := t.TempDir()
	fixture := write(t, map[string]any{"tests": tests})
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "refunds.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	policy := write(t, b)
	if r := check(t, offline.Options{PolicyFile: policy, ScenariosDir: dir}); !r.Passed || len(r.Scenarios.Cases) != 2 {
		t.Fatalf("with fixtures: %s", r.Text())
	}

	// No case at all is what the publish gate refuses, too.
	r := check(t, offline.Options{PolicyFile: policy})
	if r.Passed || r.Scenarios.Error != pdomain.ErrNoCases {
		t.Fatalf("no cases passed: %s", r.Text())
	}

	// A case that decides otherwise fails it.
	bad := bundle("500.00")
	bad["tests"].([]map[string]any)[0]["expect"] = map[string]any{"decision": "DENY", "reason": "NOPE"}
	r = check(t, offline.Options{PolicyFile: write(t, bad)})
	if r.Passed || !slices.Contains(r.Failures, offline.FailureScenarios) {
		t.Fatalf("failing case passed: %s", r.Text())
	}
}

// TestD121_AnInvalidBundleIsAFailureNotAnError: a bad policy file is the
// check's own answer, exit 1; a missing one is a check that cannot run.
func TestD121_AnInvalidBundleIsAFailureNotAnError(t *testing.T) {
	bad := bundle("500.00")
	bad["surprise"] = true
	r := check(t, offline.Options{PolicyFile: write(t, bad)})
	if r.Passed || r.Scenarios.Error != scenario.ErrBundleInvalid || len(r.Validation.Findings) != 1 {
		t.Fatalf("report: %s", r.Text())
	}

	for name, o := range map[string]offline.Options{
		"no file":    {PolicyFile: filepath.Join(t.TempDir(), "gone.json")},
		"bad mode":   {PolicyFile: write(t, bundle("1.00")), FailOn: "sometimes"},
		"no base":    {PolicyFile: write(t, bundle("1.00")), BaseFile: filepath.Join(t.TempDir(), "gone.json")},
		"empty dir":  {PolicyFile: write(t, bundle("1.00")), PackagesDir: t.TempDir()},
		"not a dir":  {PolicyFile: write(t, bundle("1.00")), ScenariosDir: write(t, bundle("1.00"))},
		"base junk":  {PolicyFile: write(t, bundle("1.00")), BaseFile: writeRaw(t, "not json")},
		"facts junk": {PolicyFile: write(t, bundle("1.00")), PackagesDir: dirWith(t, map[string]string{"package.yaml": string(mockpayments.Package), "facts.json": `{"facts":[{"name":"x","type":"blob"}]}`})},
		"scenario":   {PolicyFile: write(t, bundle("1.00")), ScenariosDir: dirWith(t, map[string]string{"x.json": `{"other":1}`})},
	} {
		if _, err := offline.Check(context.Background(), o); !errors.Is(err, offline.ErrInput) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func writeRaw(t *testing.T, s string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "raw.json")
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func dirWith(t *testing.T, files map[string]string) string {
	t.Helper()
	d := t.TempDir()
	for n, s := range files {
		if err := os.WriteFile(filepath.Join(d, n), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

// TestD121_AWideningFailsAndATighteningDoesNot: rule changes by direction,
// the fail-on modes, and outcome samples that say what they cannot prove.
func TestD121_AWideningFailsAndATighteningDoesNot(t *testing.T) {
	base := write(t, bundle("500.00"))

	r := check(t, offline.Options{PolicyFile: write(t, bundle("900.00")), BaseFile: base})
	if r.Passed || !slices.Contains(r.Failures, offline.FailureWidened) || len(r.Changes.Looser) != 1 || r.Changes.Direction != pdomain.Looser {
		t.Fatalf("widening: %s", r.Text())
	}
	if r.Outcomes.Sampled == 0 || len(r.Outcomes.Changes) == 0 {
		t.Fatalf("outcomes: %+v", r.Outcomes)
	}

	tighter := write(t, bundle("100.00"))
	r = check(t, offline.Options{PolicyFile: tighter, BaseFile: base})
	if !r.Passed || r.Changes.Direction != pdomain.Tighter {
		t.Fatalf("tightening: %s", r.Text())
	}
	r = check(t, offline.Options{PolicyFile: tighter, BaseFile: base, FailOn: offline.FailAny})
	if r.Passed || !slices.Contains(r.Failures, offline.FailureChanged) {
		t.Fatalf("--fail-on any: %s", r.Text())
	}

	// The same file: no change, and an empty sample still says it proves
	// nothing, in every format.
	same := write(t, bundle("500.00"))
	r = check(t, offline.Options{PolicyFile: same, BaseFile: base, FailOn: offline.FailAny})
	if !r.Passed || len(r.Outcomes.Changes) != 0 {
		t.Fatalf("same: %s", r.Text())
	}
	raw, err := r.JSON()
	if err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string][]byte{"text": r.Text(), "markdown": r.Markdown(), "json": raw} {
		if !strings.Contains(string(out), "an empty sample proves nothing") {
			t.Errorf("%s does not say what a sample cannot prove:\n%s", name, out)
		}
	}
	if want := fmt.Sprintf("%d sampled, 0 changed", r.Outcomes.Sampled); !strings.Contains(string(r.Text()), want) {
		t.Errorf("text lacks %q:\n%s", want, r.Text())
	}

	// With no base nothing is compared, and the report says so.
	r = check(t, offline.Options{PolicyFile: same})
	if r.Changes != nil || !strings.Contains(string(r.Text()), "no base given") || !strings.Contains(string(r.Text()), "an empty sample proves nothing") {
		t.Fatalf("no base: %s", r.Text())
	}
}

// TestD121_ChecksThatNeedTheServerAreNamed: the report says what it did
// not check.
func TestD121_ChecksThatNeedTheServerAreNamed(t *testing.T) {
	r := check(t, offline.Options{PolicyFile: write(t, bundle("500.00"))})
	for _, want := range []string{"APPROVER_NONE", "FACT_NO_SOURCE"} {
		if !strings.Contains(string(r.Text()), want) {
			t.Errorf("text does not name %s", want)
		}
	}
}

// automationDoc is an automation with one launch and one wait, as JSON.
const automationDoc = `{
  "apiVersion": "automations.pantherclaw.dev/v1", "kind": "Automation", "purpose": "Refund small tickets from Support.",
  "work_kind": "AGENT_WORK", "review_by": "2026-12-01",
  "when": {"inbound": {"source": "0192f000-0000-7000-8000-000000000002", "type": "ticket.created",
    "params": {"ticket": {"from": "/ticket/id", "type": "string", "pattern": "T-[0-9]{1,10}"}}}},
  "authority": {"principal": "self", "ceiling": {"agents": ["0192f000-0000-7000-8000-000000000003"],
    "bounds": {"operations": ["payments.refund.create"]}, "per_grant": {"ttl": "1h"}, "per_day": {"grants": 5, "runs": 5}}},
  "do": [
    {"id": "launch", "step": "launch_run", "with": {"agent": "0192f000-0000-7000-8000-000000000003", "task_ref": "ticket {{params.ticket}}"}},
    {"id": "wait", "step": "wait_run", "with": {"step": "launch"}, "timeout": "2h"}
  ],
  "finish_when": [{"step": "wait", "condition": "RUN_ENDED"}],
  "limits": {"deadline": "1d"}
}`

// TestD120_AutomationScenariosRunInMemory: an automation file runs through
// engine.Simulate; a required kind no case covers, or a case that decides
// otherwise, fails the check, and a definition that does not parse cannot
// run at all.
func TestD120_AutomationScenariosRunInMemory(t *testing.T) {
	policy := write(t, bundle("500.00"))
	cases := func(state string) string {
		return `[{"name": "normal", "kind": "NORMAL", "trigger": {"params": {"ticket": "T-42"}},
		  "stubs": {"launch": [{"state": "DONE", "effect": "CHANGED"}], "wait": [{"state": "DONE", "effect": "CHANGED", "evidence": true}]},
		  "expect": {"state": "` + state + `"}}]`
	}
	dir := dirWith(t, map[string]string{"auto.json": `{"automation": ` + automationDoc + `, "cases": ` + cases("SUCCEEDED") + `}`})
	r := check(t, offline.Options{PolicyFile: policy, ScenariosDir: dir})
	if len(r.Scenarios.Automations) != 1 {
		t.Fatalf("automations: %s", r.Text())
	}
	a := r.Scenarios.Automations[0]
	if a.File != "auto.json" || len(a.Cases) != 1 || !a.Cases[0].Passed {
		t.Fatalf("the case did not run: %+v", a)
	}
	if a.Passed || !slices.Contains(a.Missing, "DENIED") || r.Passed {
		t.Fatalf("missing kinds passed: %+v", a)
	}

	dir = dirWith(t, map[string]string{"auto.json": `{"automation": ` + automationDoc + `, "cases": ` + cases("FAILED") + `}`})
	r = check(t, offline.Options{PolicyFile: policy, ScenariosDir: dir})
	if r.Scenarios.Automations[0].Cases[0].Passed || !strings.Contains(string(r.Text()), "case normal failed") {
		t.Fatalf("a wrong expectation passed: %s", r.Text())
	}

	dir = dirWith(t, map[string]string{"x.json": `{"automation": {"kind": "bad"}, "cases": []}`})
	if _, err := offline.Check(context.Background(), offline.Options{PolicyFile: policy, ScenariosDir: dir}); !errors.Is(err, offline.ErrInput) {
		t.Fatalf("a bad definition: %v", err)
	}
}

// markup is what no rendered policy text may hold raw.
var markup = regexp.MustCompile("[`<>\\[\\]()!*_~|\\\\]|@[a-zA-Z]|#[0-9]|https?://|www\\.")

// hostile carries every way a policy could write into a report.
const hostile = "@octocat cc @org/team <img src=x onerror=alert(1)> [click](https://evil.example) ![p](https://evil.example/p.png) " +
	"`code` ``` **bold** _em_ ~~s~~ | a | b | #1 owner/repo#2 www.evil.example a@b.example :smile: !3 $x$ %4 &amp; <!-- c --> <details> " +
	"deadbeefcafe0123 ## heading\n\n- [ ] task\n::error::owned\n##[error]owned\r\n\x1b[31mred\x1b[0m\u202Ebidi\u200Bzero\u2028line"

// escapedFully strips the escapes the report may hold and returns what is
// left to look at: entities are safe by construction, so only raw text
// counts, and it is what a parser sees.
func rawText(s string) string {
	return regexp.MustCompile(`&#[0-9]+;`).ReplaceAllString(s, " ")
}

// TestHR565_ACheckReportCannotRenderMarkupOrMention: every report field
// that comes from a file, through Escape, holds no raw markup, and each
// sigil stays split from what follows once a renderer decodes entities
// (G0 M23 D122).
func TestHR565_ACheckReportCannotRenderMarkupOrMention(t *testing.T) {
	out := offline.Escape(hostile)
	if m := markup.FindString(rawText(out)); m != "" {
		t.Fatalf("raw markup %q in %s", m, out)
	}
	if strings.ContainsAny(out, "\n\r\x1b") {
		t.Fatalf("a control character survived: %q", out)
	}
	decoded := decode(out)
	for _, bad := range []string{"@octocat", "@org", "#1", "#2", "https://", "www.evil", "a@b", ":smile:", "!3", "deadbeefcafe0123"} {
		if strings.Contains(decoded, bad) {
			t.Errorf("%q still reads whole after decoding", bad)
		}
	}
	if strings.ContainsAny(decoded, "\u202E\u2028\x1b") {
		t.Errorf("a control character survived decoding: %q", decoded)
	}
}

// decode undoes the numeric entities, as a Markdown parser does.
func decode(s string) string {
	return regexp.MustCompile(`&#([0-9]+);`).ReplaceAllStringFunc(s, func(m string) string {
		var n rune
		_, _ = fmt.Sscanf(m, "&#%d;", &n)
		return string(n)
	})
}

// TestT244_APolicyFileCannotInjectIntoACIReport: a whole report of a
// bundle whose every text field is hostile.
func TestT244_APolicyFileCannotInjectIntoACIReport(t *testing.T) {
	// A hostile summary is a format error for a new bundle only when it
	// holds invisible characters, so strip those: the rest reach the report.
	visible := strings.NewReplacer("\u202E", "", "\u200B", "", "\u2028", "", "\x1b", "", "\r", "", "\n", " ").Replace(hostile)
	b := bundle("500.00")
	rule := b["rules"].([]map[string]any)[0]
	rule["summary"] = visible
	base := write(t, b)
	next := bundle("500.00")
	nextRule := next["rules"].([]map[string]any)[0]
	nextRule["summary"] = visible + " changed"
	nextRule["reason"] = "REFUND_OVER_CAP"
	next["tests"].([]map[string]any)[0]["summary"] = visible
	next["tests"].([]map[string]any)[0]["expect"] = map[string]any{"decision": "DENY", "reason": visible}
	r := check(t, offline.Options{PolicyFile: write(t, next), BaseFile: base, FailOn: offline.FailAny})
	if r.Passed {
		t.Fatal("passed")
	}
	md := string(r.Markdown())
	lines := strings.Split(md, "\n")
	for _, l := range lines {
		if strings.HasPrefix(l, "### ") {
			continue
		}
		if m := markup.FindString(rawText(l)); m != "" {
			t.Errorf("raw markup %q in line %q", m, l)
		}
	}
	for _, line := range strings.Split(string(r.Text()), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "::") {
			t.Errorf("a workflow command can start a line: %q", line)
		}
		if strings.Contains(line, "##[") {
			t.Errorf("a legacy runner command survived: %q", line)
		}
	}

	// The invalid-bundle path carries the decoder's words about the file.
	bad := bundle("500.00")
	bad["rules"].([]map[string]any)[0]["summary"] = "a\u202Eb"
	r = check(t, offline.Options{PolicyFile: write(t, bad)})
	if strings.ContainsRune(string(r.Text()), '\u202E') || strings.ContainsRune(string(r.Markdown()), '\u202E') {
		t.Error("bidi text reached a report")
	}
}

// TestHR565_TheMarkdownReportIsCapped: at most 60 KiB, never cut inside an
// escape, and it says it was cut (D122).
func TestHR565_TheMarkdownReportIsCapped(t *testing.T) {
	r := &offline.Report{Validation: offline.Validation{}}
	for i := range 200 {
		r.Validation.Findings = append(r.Validation.Findings, pdomain.Finding{Code: "X", Severity: "ERROR", Detail: strings.Repeat("@", 2000) + fmt.Sprint(i)})
	}
	for i := range 200 {
		r.Scenarios.Surviving = append(r.Scenarios.Surviving, pdomain.MutantResult{Rule: "r", Mutation: strings.Repeat("<", 2000) + fmt.Sprint(i)})
		r.Scenarios.Uncompilable = append(r.Scenarios.Uncompilable, pdomain.MutantResult{Rule: "r", Mutation: strings.Repeat("<", 2000) + fmt.Sprint(i)})
	}
	md := r.Markdown()
	if len(md) > offline.MarkdownCap {
		t.Fatalf("%d bytes", len(md))
	}
	if !strings.Contains(string(md), "Report cut at 60 KiB") {
		t.Fatalf("not marked as cut: %d bytes", len(md))
	}
	if regexp.MustCompile(`&#[0-9]*$`).MatchString(strings.Split(strings.TrimRight(string(md), "\n"), "\n\n")[0]) {
		t.Fatal("cut inside an escape")
	}
}

// TestHR232_ACheckLeavesItsInputsAlone: a check writes nothing beside its
// files.
func TestHR232_ACheckLeavesItsInputsAlone(t *testing.T) {
	policy := write(t, bundle("500.00"))
	dir := filepath.Dir(policy)
	check(t, offline.Options{PolicyFile: policy})
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("%d files after a check", len(entries))
	}
}

// TestT245_ALinkCannotPointACheckElsewhere: a pull request can add a link,
// and the check refuses to read through it.
func TestT245_ALinkCannotPointACheckElsewhere(t *testing.T) {
	target := write(t, bundle("500.00"))
	link := filepath.Join(t.TempDir(), "policy.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	if _, err := offline.Check(context.Background(), offline.Options{PolicyFile: link}); !errors.Is(err, offline.ErrInput) {
		t.Fatalf("read through a link: %v", err)
	}
}
