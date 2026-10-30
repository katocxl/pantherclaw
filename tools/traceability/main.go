// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Command traceability checks that every hardening rule (HR-###) and threat
// (T-###) scheduled for a completed milestone has a test (HARDENING_RULES
// "Traceability convention", THREAT_MODEL §7).
//
// A rule is due at the first milestone in its MS column. It is covered by a
// test whose name starts with TestHR###_. A threat is covered by a
// TestT###_ test, or by tests for at least one hardening rule its
// mitigations reference. Tests are Go functions in _test.go files, and the
// SDKs' tests with the same names (G0 M8): Python unittest methods
// test_HR###_… in test_*.py files and TypeScript node:test tests named
// "TestHR###_…" in *.test.ts files.
//
//	go -C tools run ./traceability -root .. -through M1
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// milestones in delivery order, which is not numeric order (ADR-0017):
// M12 comes before the v0.1.0 preview, M11.1 (the policy half of M11)
// after it and before M10, and M14 before M13. The UI phase (milestone UI,
// founder decision 2026-10-20) comes after M14 and before M13. M15 to M19
// are post-1.0 and come after M13, in that order (G0 M15, G0 M17, G0 M18,
// G0 M19).
var milestones = []string{"M0", "M1", "M1.5", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "M9", "M12", "M11.1", "M10", "M11", "M14", "UI", "M13", "M15", "M16", "M17", "M18", "M19"}

func milestoneIndex(m string) int { return slices.Index(milestones, strings.TrimSpace(m)) }

var (
	hrRow     = regexp.MustCompile(`^\|\s*(HR-\d{3})\s*\|.*\|\s*([^|]+?)\s*\|\s*$`)
	threatRow = regexp.MustCompile(`^\|\s*(T-\d{3})\s*\|(.*)\|\s*([^|]+?)\s*\|\s*$`)
	hrRef     = regexp.MustCompile(`HR-(\d{3})(?:\.\.(\d{3}))?`)
	testName  = regexp.MustCompile(`func (Test(?:HR|T)\d{3})_`)
	// A Python or TypeScript test counts only where it is declared, at the
	// start of a line, never in a comment, a docstring or a string.
	pyTest = regexp.MustCompile(`(?m)^[ \t]*def test_((?:HR|T)\d{3})_`)
	tsTest = regexp.MustCompile(`(?m)^[ \t]*test\(\s*["'` + "`" + `](Test(?:HR|T)\d{3})_`)
)

// Item is a rule or threat with the milestone it is due.
type Item struct {
	ID       string
	Due      string
	Mitigate []string // threats only: referenced HR ids
}

func run(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("traceability", flag.ContinueOnError)
	fl.SetOutput(stderr)
	root := fl.String("root", ".", "repository root")
	through := fl.String("through", "", "last completed milestone (for example M1)")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if milestoneIndex(*through) < 0 {
		_, _ = fmt.Fprintf(stderr, "traceability: unknown milestone %q\n", *through)
		return 2
	}
	rules, err := parse(filepath.Join(*root, "docs/security/HARDENING_RULES.md"), hrRow, false)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "traceability:", err)
		return 2
	}
	threats, err := parse(filepath.Join(*root, "docs/security/THREAT_MODEL.md"), threatRow, true)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "traceability:", err)
		return 2
	}
	tests, err := collectTests(os.DirFS(*root))
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "traceability:", err)
		return 2
	}
	missing := Missing(rules, threats, tests, *through)
	for _, m := range missing {
		_, _ = fmt.Fprintln(stdout, m)
	}
	if len(missing) > 0 {
		_, _ = fmt.Fprintf(stdout, "traceability: %d item(s) due by %s have no test\n", len(missing), *through)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "traceability: all rules and threats due by %s have tests\n", *through)
	return 0
}

// Missing returns the due items without tests.
func Missing(rules, threats []Item, tests map[string]bool, through string) []string {
	limit := milestoneIndex(through)
	var out []string
	for _, r := range rules {
		if due := milestoneIndex(r.Due); due >= 0 && due <= limit && !tests["Test"+strings.ReplaceAll(r.ID, "-", "")] {
			out = append(out, fmt.Sprintf("%s (due %s): no Test%s_* test", r.ID, r.Due, strings.ReplaceAll(r.ID, "-", "")))
		}
	}
	for _, th := range threats {
		due := milestoneIndex(th.Due)
		if due < 0 || due > limit || tests["Test"+strings.ReplaceAll(th.ID, "-", "")] {
			continue
		}
		covered := slices.ContainsFunc(th.Mitigate, func(hr string) bool { return tests["Test"+strings.ReplaceAll(hr, "-", "")] })
		if !covered {
			out = append(out, fmt.Sprintf("%s (due %s): no Test%s_* test and no test for its mitigations %v",
				th.ID, th.Due, strings.ReplaceAll(th.ID, "-", ""), th.Mitigate))
		}
	}
	return out
}

func parse(path string, row *regexp.Regexp, threat bool) ([]Item, error) {
	f, err := os.Open(path) //nolint:gosec // G304: repository document
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var items []Item
	s := bufio.NewScanner(f)
	for s.Scan() {
		m := row.FindStringSubmatch(s.Text())
		if m == nil {
			continue
		}
		it := Item{ID: m[1]}
		ms := m[len(m)-1]
		it.Due = strings.SplitN(ms, "/", 2)[0]
		if threat {
			it.Mitigate = expandRefs(m[2])
		}
		items = append(items, it)
	}
	return items, s.Err()
}

// expandRefs extracts HR ids, expanding ranges such as HR-050..057.
func expandRefs(s string) []string {
	var out []string
	for _, m := range hrRef.FindAllStringSubmatch(s, -1) {
		lo, _ := strconv.Atoi(m[1])
		hi := lo
		if m[2] != "" {
			hi, _ = strconv.Atoi(m[2])
		}
		for n := lo; n <= hi && n-lo < 100; n++ {
			out = append(out, fmt.Sprintf("HR-%03d", n))
		}
	}
	return out
}

func collectTests(fsys fs.FS) (map[string]bool, error) {
	tests := map[string]bool{}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			// .claude holds session worktrees, whose tests are on unmerged branches.
			case ".git", ".claude", "node_modules", "vendor", "testdata", ".venv", "__pycache__", "dist":
				return fs.SkipDir
			}
			return nil
		}
		var re *regexp.Regexp
		prefix := ""
		switch base := path.Base(p); {
		case strings.HasSuffix(base, "_test.go"):
			re = testName
		case strings.HasPrefix(base, "test_") && strings.HasSuffix(base, ".py"):
			re, prefix = pyTest, "Test"
		case strings.HasSuffix(base, ".test.ts"):
			re = tsTest
		default:
			return nil
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			tests[prefix+m[1]] = true
		}
		return nil
	})
	return tests, err
}
