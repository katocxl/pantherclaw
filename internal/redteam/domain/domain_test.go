// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

const header = `apiVersion: pantherclaw.range/v1
id: RT-009
title: t
category: boundary
suite: coding-agent
tier: community
attacker: A1
threats: [T-080]
rules: [HR-201]
`

func parseSteps(steps string) error {
	_, err := domain.Parse([]byte(header + "steps:\n" + steps))
	return err
}

func TestHR223_ScenarioFilesAreStrictData(t *testing.T) {
	valid, _ := filepath.Glob("../testdata/valid/*.yaml")
	if len(valid) < 3 {
		t.Fatalf("want the valid testdata, found %d files", len(valid))
	}
	for _, f := range valid {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s, err := domain.Parse(raw)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if err := s.CheckFileName(filepath.Base(f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	invalid, _ := filepath.Glob("../testdata/invalid/*.yaml")
	if len(invalid) < 10 {
		t.Fatalf("want the invalid testdata, found %d files", len(invalid))
	}
	for _, f := range invalid {
		raw, _ := os.ReadFile(f)
		if _, err := domain.Parse(raw); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", filepath.Base(f), err)
		}
	}
	for name, doc := range map[string]string{
		"two documents": header + "steps:\n  - {id: a, do: operator.revoke_grant}\n---\nx: 1\n",
		"null":          header + "steps:\n  - {id: a, do: operator.revoke_grant, save: {x: }}\n",
		"float":         header + "steps:\n  - {id: a, do: agent.call, with: {face: mcp, connection: g, tool: t, args: {n: 1.5}}, expect: {outcome: ALLOW}}\n",
		"merge key":     header + "steps:\n  - <<: {id: a}\n    do: operator.revoke_grant\n",
		"BOM":           "\xef\xbb\xbf" + header + "steps:\n  - {id: a, do: operator.revoke_grant}\n",
		"duplicate key": header + "title: again\nsteps:\n  - {id: a, do: operator.revoke_grant}\n",
		"empty":         "",
	} {
		if _, err := domain.Parse([]byte(doc)); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
}

func TestHR223_LimitsAreEnforced(t *testing.T) {
	var many strings.Builder
	for i := 0; i < domain.MaxSteps+1; i++ {
		many.WriteString("  - {id: s" + strings.Repeat("a", i%3) + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ", do: operator.revoke_grant}\n")
	}
	if err := parseSteps(many.String()); err == nil {
		t.Error("41 steps accepted")
	}
	long := strings.Repeat("x", domain.MaxStringLen+1)
	if err := parseSteps("  - {id: a, do: agent.call, with: {face: mcp, connection: g, tool: t, args: {k: " + long + "}}, expect: {outcome: ALLOW}}\n"); err == nil {
		t.Error("a 4 KiB+ string was accepted")
	}
	deep := strings.Repeat("{a: ", 9) + "1" + strings.Repeat("}", 9)
	if err := parseSteps("  - {id: a, do: agent.call, with: {face: mcp, connection: g, tool: t, args: " + deep + "}, expect: {outcome: ALLOW}}\n"); err == nil {
		t.Error("args nested deeper than 8 accepted")
	}
	if _, err := domain.Parse(make([]byte, domain.MaxFileBytes+1)); err == nil {
		t.Error("oversized file accepted")
	}
	if err := parseSteps("  - {id: a, do: wait, with: {for: effect_confirmed, of: a, max_seconds: 11}, expect: {outcome: CONFIRMED}}\n"); err == nil {
		t.Error("wait over 10 s accepted")
	}
}

func TestHR223_UnknownStepKindsAreRejected(t *testing.T) {
	for _, kind := range []string{"shell.run", "agent.exec", "http.get", "agent", "AGENT.CALL", "sandbox.exec", "person.approve ", ""} {
		err := parseSteps("  - {id: a, do: \"" + kind + "\", with: {}}\n")
		if !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("kind %q: want ErrInvalid, got %v", kind, err)
		}
	}
	for _, kind := range domain.StepKinds {
		if kind == "" {
			t.Fatal("empty kind in catalogue")
		}
	}
	// A known kind rejects fields outside its own shape.
	if err := parseSteps("  - {id: a, do: operator.revoke_grant, with: {anything: 1}}\n"); err == nil {
		t.Error("an empty-with kind accepted a field")
	}
	if err := parseSteps("  - {id: a, do: sandbox.probe, with: {probe: not_a_probe}, expect: {outcome: BLOCKED}}\n"); err == nil {
		t.Error("an unknown probe accepted")
	}
}

func TestT092_AHostileScenarioCannotNameAHostOrURL(t *testing.T) {
	for name, with := range map[string]string{
		"url field":        "{face: http, connection: github, method: GET, path: /x, url: \"http://evil.example\"}",
		"host field":       "{face: http, connection: github, method: GET, path: /x, host: evil.example}",
		"url path":         "{face: http, connection: github, method: GET, path: \"https://evil.example/x\"}",
		"scheme-less path": "{face: http, connection: github, method: GET, path: \"//evil.example/x\"}",
		"userinfo path":    "{face: http, connection: github, method: GET, path: \"/@evil.example\"}",
		"address role":     "{face: http, connection: \"evil.example:443\", method: GET, path: /x}",
		"url role":         "{face: mcp, connection: \"http://127.0.0.1\", tool: t}",
		"ip role":          "{face: mcp, connection: \"127.0.0.1\", tool: t}",
		"traversal":        "{face: http, connection: github, method: GET, path: /a/../../etc}",
	} {
		if err := parseSteps("  - {id: a, do: agent.call, with: " + with + ", expect: {outcome: ALLOW}}\n"); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
	if err := parseSteps("  - {id: a, do: agent.direct, with: {connection: github, method: GET, path: \"http://x\"}, expect: {outcome: ALLOW}}\n"); err == nil {
		t.Error("agent.direct accepted a URL")
	}
}

func TestT092_AHostileScenarioCannotRunAShell(t *testing.T) {
	for name, step := range map[string]string{
		"shell kind":     "{id: a, do: shell, with: {cmd: id}}",
		"exec kind":      "{id: a, do: sandbox.exec, with: {cmd: id}}",
		"probe command":  "{id: a, do: sandbox.probe, with: {probe: icmp, command: id}, expect: {outcome: BLOCKED}}",
		"probe argv":     "{id: a, do: sandbox.probe, with: {probe: icmp, argv: [id]}, expect: {outcome: BLOCKED}}",
		"probe as shell": "{id: a, do: sandbox.probe, with: {probe: \"sh -c id\"}, expect: {outcome: BLOCKED}}",
		"call script":    "{id: a, do: agent.call, with: {face: mcp, connection: g, tool: t, script: id}, expect: {outcome: ALLOW}}",
		"tool shell":     "{id: a, do: agent.call, with: {face: mcp, connection: g, tool: \"t; id\"}, expect: {outcome: ALLOW}}",
	} {
		if err := parseSteps("  - " + step + "\n"); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
}

func TestT092_ACannotActAsAPersonWithoutAnOperator(t *testing.T) {
	// Person steps name a held step and a role; they cannot carry a credential,
	// a token or a user, and cannot point at a step that does not precede them.
	for name, step := range map[string]string{
		"no earlier step": "{id: a, do: person.approve, with: {step: b, as: approver}}\n  - {id: b, do: operator.revoke_grant}",
		"self":            "{id: a, do: person.approve, with: {step: a, as: approver}}",
		"unknown role":    "{id: x, do: operator.revoke_grant}\n  - {id: a, do: person.approve, with: {step: x, as: admin}}",
		"token field":     "{id: x, do: operator.revoke_grant}\n  - {id: a, do: person.approve, with: {step: x, as: approver, token: abc}}",
		"user field":      "{id: x, do: operator.revoke_grant}\n  - {id: a, do: person.decline, with: {step: x, as: approver, user: alice}}",
	} {
		if err := parseSteps("  - " + step + "\n"); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
	if err := parseSteps("  - {id: x, do: operator.revoke_grant}\n  - {id: a, do: person.approve, with: {step: x, as: approver}}\n"); err != nil {
		t.Errorf("a well-formed person step: %v", err)
	}
}

func TestT092_ReferencesComeOnlyFromSavesAndFixtures(t *testing.T) {
	good := "  - {id: a, do: agent.call, with: {face: mcp, connection: g, tool: t}, save: {pr: /number}, expect: {outcome: ALLOW}}\n" +
		"  - {id: b, do: agent.call, with: {face: http, connection: g, method: GET, path: \"/pulls/${pr}/${fixture.branch}\"}, expect: {outcome: ALLOW}}\n"
	if err := parseSteps(good); err != nil {
		t.Fatal(err)
	}
	for name, step := range map[string]string{
		"own save":    "{id: a, do: agent.call, with: {face: mcp, connection: g, tool: t, args: {n: \"${n}\"}}, save: {n: /x}, expect: {outcome: ALLOW}}",
		"expression":  "{id: a, do: agent.call, with: {face: mcp, connection: g, tool: t, args: {n: \"${a + b}\"}}, expect: {outcome: ALLOW}}",
		"environment": "{id: a, do: agent.call, with: {face: mcp, connection: g, tool: t, args: {n: \"${env.HOME}\"}}, expect: {outcome: ALLOW}}",
		"in a key":    "{id: a, do: agent.call, with: {face: mcp, connection: g, tool: t, args: {\"${fixture.k}\": 1}}, expect: {outcome: ALLOW}}",
		"bad pointer": "{id: a, do: agent.call, with: {face: mcp, connection: g, tool: t}, save: {n: number}, expect: {outcome: ALLOW}}",
		"bad escape":  "{id: a, do: agent.call, with: {face: mcp, connection: g, tool: t}, save: {n: /a~2}, expect: {outcome: ALLOW}}",
	} {
		if err := parseSteps("  - " + step + "\n"); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
}

func TestSubstitutionIsPlainAndSinglePass(t *testing.T) {
	out, err := domain.Substitute([]byte(`{"a":"x${one}y","n":12345678901234567,"k":["${two}"]}`),
		map[string]string{"one": "${two}", "two": `q"uote`})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(out), `{"a":"x${two}y","n":12345678901234567,"k":["q\"uote"]}`; got != want {
		t.Errorf("got %s want %s", got, want)
	}
	if _, err := domain.Substitute([]byte(`{"a":"${missing}"}`), nil); err == nil {
		t.Error("an unknown name was substituted")
	}
}

func TestDigestIgnoresSpellingAndSetDigestIgnoresOrder(t *testing.T) {
	a := header + "steps:\n  - {id: a, do: operator.revoke_grant}\n"
	b := header + "harness_only: false\nrequires: []\nsteps:\n  - id: a\n    do: operator.revoke_grant\n"
	sa, err := domain.Parse([]byte(a))
	if err != nil {
		t.Fatal(err)
	}
	sb, err := domain.Parse([]byte(b))
	if err != nil {
		t.Fatal(err)
	}
	da, _ := domain.Digest(sa)
	db, _ := domain.Digest(sb)
	if da != db || !strings.HasPrefix(da, "sha256:") {
		t.Errorf("digests differ: %s %s", da, db)
	}
	sc, _ := domain.Parse([]byte(strings.Replace(a, "title: t", "title: u", 1)))
	if dc, _ := domain.Digest(sc); dc == da {
		t.Error("a changed title kept the digest")
	}
	x := domain.SetDigest(map[string]string{"RT-001": "sha256:a", "RT-002": "sha256:b"})
	y := domain.SetDigest(map[string]string{"RT-002": "sha256:b", "RT-001": "sha256:a"})
	if x != y || x == domain.SetDigest(map[string]string{"RT-001": "sha256:a"}) {
		t.Error("set digest wrong")
	}
}

func TestFileNameMustCarryTheID(t *testing.T) {
	s := &domain.Scenario{ID: "RT-002"}
	for name, ok := range map[string]bool{
		"RT-002-merge-held.yaml": true, "RT-002.yaml": false, "RT-003-merge-held.yaml": false,
		"RT-002-Merge.yaml": false, "RT-002-merge.yml": false, "x/RT-002-a.yaml": false,
	} {
		if err := s.CheckFileName(name); (err == nil) != ok {
			t.Errorf("%s: err=%v want ok=%v", name, err, ok)
		}
	}
}

func TestHR226_ARegressionFailsTheGate(t *testing.T) {
	e := func(id, d string, v domain.Verdict) domain.Entry { return domain.Entry{ID: id, Digest: d, Verdict: v} }
	base := []domain.Entry{
		e("RT-001", "d1", domain.VerdictPass), e("RT-002", "d2", domain.VerdictPass), e("RT-003", "d3", domain.VerdictPass),
		e("RT-004", "d4", domain.VerdictPass), e("RT-005", "d5", domain.VerdictFail), e("RT-006", "d6", domain.VerdictSkipped),
	}
	for name, tc := range map[string]struct {
		cur  []domain.Entry
		exit int
		reg  int
	}{
		"all hold": {[]domain.Entry{e("RT-001", "d1", "PASS"), e("RT-002", "d2", "PASS"), e("RT-003", "d3", "PASS"), e("RT-004", "d4", "PASS"), e("RT-005", "d5", "FAIL"), e("RT-006", "d6", "SKIPPED")}, 1, 0}, // RT-005 still FAILs
		"improved": {[]domain.Entry{e("RT-001", "d1", "PASS"), e("RT-002", "d2", "PASS"), e("RT-003", "d3", "PASS"), e("RT-004", "d4", "PASS"), e("RT-005", "d5", "PASS"), e("RT-006", "d6", "PASS")}, 0, 0},
		"fail":     {[]domain.Entry{e("RT-001", "d1", "FAIL"), e("RT-002", "d2", "PASS"), e("RT-003", "d3", "PASS"), e("RT-004", "d4", "PASS")}, 1, 2},
		"error":    {[]domain.Entry{e("RT-001", "d1", "PASS"), e("RT-002", "d2", "ERROR"), e("RT-003", "d3", "PASS"), e("RT-004", "d4", "PASS")}, 1, 2},
		"skipped":  {[]domain.Entry{e("RT-001", "d1", "PASS"), e("RT-002", "d2", "PASS"), e("RT-003", "d3", "SKIPPED"), e("RT-004", "d4", "PASS")}, 1, 2},
		"missing":  {[]domain.Entry{e("RT-001", "d1", "PASS"), e("RT-002", "d2", "PASS"), e("RT-003", "d3", "PASS")}, 1, 1},
	} {
		c := domain.Compare(base, tc.cur)
		if c.ExitCode() != tc.exit {
			t.Errorf("%s: exit %d want %d (%+v)", name, c.ExitCode(), tc.exit, c)
		}
		if name != "all hold" && name != "improved" && len(c.Regressions) == 0 {
			t.Errorf("%s: no regression reported", name)
		}
	}
	// A baseline FAIL that stays FAIL is not a regression, but any current FAIL exits 1.
	c := domain.Compare([]domain.Entry{e("RT-005", "d5", "FAIL")}, []domain.Entry{e("RT-005", "d5", "FAIL")})
	if len(c.Regressions) != 0 || c.ExitCode() != 1 {
		t.Errorf("a standing FAIL: %+v", c)
	}
	// A changed digest is reported and still compared.
	c = domain.Compare([]domain.Entry{e("RT-001", "old", "PASS")}, []domain.Entry{e("RT-001", "new", "FAIL")})
	if len(c.Changed) != 1 || len(c.Regressions) != 1 || c.ExitCode() != 1 {
		t.Errorf("a changed digest: %+v", c)
	}
	c = domain.Compare([]domain.Entry{e("RT-001", "old", "PASS")}, []domain.Entry{e("RT-001", "new", "PASS"), e("RT-099", "n", "PASS")})
	if len(c.Changed) != 1 || c.ExitCode() != 0 {
		t.Errorf("a changed digest that passes: %+v", c)
	}
}

func FuzzParseScenario(f *testing.F) {
	files, _ := filepath.Glob("../testdata/*/*.yaml")
	for _, p := range files {
		if raw, err := os.ReadFile(p); err == nil {
			f.Add(raw)
		}
	}
	f.Add([]byte(header + "steps:\n  - {id: a, do: operator.revoke_grant}\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		s, err := domain.Parse(raw)
		if err != nil {
			if !errors.Is(err, domain.ErrInvalid) {
				t.Fatalf("error outside ErrInvalid: %v", err)
			}
			return
		}
		d1, err := domain.Digest(s)
		if err != nil {
			t.Fatal(err)
		}
		if d2, _ := domain.Digest(s); d1 != d2 {
			t.Fatal("digest is not stable")
		}
		if len(s.Steps) == 0 || len(s.Steps) > domain.MaxSteps {
			t.Fatal("validation let a bad step count through")
		}
	})
}
