// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Command licensecheck verifies (and optionally adds) the SPDX licence and
// copyright header that every PantherClaw source file must carry.
//
// Files under the Apache-2.0 directories listed in NOTICE must declare
// Apache-2.0; every other source file must declare BUSL-1.1.
//
//	go -C tools run ./licensecheck -root ..          # check
//	go -C tools run ./licensecheck -root .. -fix     # add missing headers
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

const (
	spdxBUSL   = "BUSL-1.1"
	spdxApache = "Apache-2.0"
	owner      = "Joshua Kato"
	// headerWindow is how many leading lines may precede/contain the header.
	headerWindow = 10
)

// apachePrefixes are repository-relative directories licensed Apache-2.0 (see NOTICE).
var apachePrefixes = []string{"sdk/", "integrations/", "docs/protocol/", "hub/"}

// notBuiltYet are directories NOTICE lists ahead of the code (G0 M23 D123,
// D124): absent is allowed for these, and once one exists it needs a LICENSE
// like any other.
var notBuiltYet = []string{"integrations/github-action/", "integrations/gitlab/"}

// skipDirs are never scanned.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "bin": true, "dist": true, "vendor": true,
	".venv": true, "venv": true, "__pycache__": true, "testdata": true, ".task": true,
	".claude": true, // local agent worktrees and settings, never repository code
}

// thirdPartyDirs hold third-party files vendored unchanged with their own
// LICENSE (see NOTICE), and the code generated from them: they keep their
// upstream headers and get none of ours.
var thirdPartyDirs = []string{"proto/third_party", "internal/gen/opentelemetry"}

// commentPrefix maps source extensions to their line-comment syntax.
var commentPrefix = map[string]string{
	".go": "//", ".proto": "//", ".ts": "//", ".tsx": "//", ".mts": "//", ".cts": "//",
	".js": "//", ".mjs": "//", ".cjs": "//",
	".sql": "--",
	".py":  "#", ".pyi": "#", ".sh": "#", ".bash": "#", ".ps1": "#",
}

// Problem describes one non-compliant file.
type Problem struct {
	Path   string
	Reason string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("licensecheck", flag.ContinueOnError)
	fl.SetOutput(stderr)
	root := fl.String("root", ".", "repository root")
	fix := fl.Bool("fix", false, "add missing headers in place")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	problems, fixed, err := Check(os.DirFS(*root), *root, *fix)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "licensecheck: %v\n", err)
		return 2
	}
	for _, f := range fixed {
		_, _ = fmt.Fprintf(stdout, "added header: %s\n", f)
	}
	listed := CheckListed(os.DirFS(*root))
	for _, p := range append(problems, listed...) {
		_, _ = fmt.Fprintf(stdout, "%s: %s\n", p.Path, p.Reason)
	}
	if len(problems) > 0 {
		_, _ = fmt.Fprintf(stderr, "licensecheck: %d file(s) without a valid licence header (run with -fix)\n", len(problems))
	}
	if len(listed) > 0 {
		_, _ = fmt.Fprintf(stderr, "licensecheck: %d problem(s) with the directories NOTICE lists\n", len(listed))
	}
	if len(problems)+len(listed) > 0 {
		return 1
	}
	return 0
}

// CheckListed checks NOTICE's "Separately Licensed Components" list (G0 M23
// D111, F848): every directory it names has its own LICENSE, and every
// directory under integrations/ is named. A tree without a NOTICE file holds
// no list to check.
func CheckListed(fsys fs.FS) []Problem {
	notice, err := fs.ReadFile(fsys, "NOTICE")
	if err != nil {
		return nil
	}
	listed := ListedDirs(notice)
	if len(listed) == 0 {
		return []Problem{{"NOTICE", "lists no separately licensed directories"}}
	}
	var problems []Problem
	for _, dir := range listed {
		if !isApache(dir) {
			problems = append(problems, Problem{dir, "NOTICE lists it, but this check does not treat it as Apache-2.0"})
		}
		if _, err := fs.Stat(fsys, strings.TrimSuffix(dir, "/")); err != nil && slices.Contains(notBuiltYet, dir) {
			continue
		}
		if _, err := fs.Stat(fsys, dir+"LICENSE"); err != nil {
			problems = append(problems, Problem{dir, "NOTICE lists it, but it has no LICENSE file"})
		}
	}
	entries, err := fs.ReadDir(fsys, "integrations")
	if err != nil {
		return problems
	}
	for _, e := range entries {
		if dir := "integrations/" + e.Name() + "/"; e.IsDir() && !slices.Contains(listed, dir) {
			problems = append(problems, Problem{dir, "not listed in NOTICE"})
		}
	}
	return problems
}

// ListedDirs returns the directories in NOTICE's "Separately Licensed
// Components" list, each with its trailing slash. The list ends at the next
// heading.
func ListedDirs(notice []byte) []string {
	_, rest, ok := strings.Cut(strings.ReplaceAll(string(notice), "\r\n", "\n"), "Separately Licensed Components")
	if !ok {
		return nil
	}
	rest, _, _ = strings.Cut(rest, "Reference documents")
	var dirs []string
	for line := range strings.SplitSeq(rest, "\n") {
		if !strings.HasPrefix(line, "  ") {
			continue
		}
		if fields := strings.Fields(line); len(fields) > 0 && strings.HasSuffix(fields[0], "/") {
			dirs = append(dirs, fields[0])
		}
	}
	return dirs
}

func isApache(p string) bool {
	return slices.ContainsFunc(apachePrefixes, func(pre string) bool { return strings.HasPrefix(p, pre) })
}

// Check scans fsys. When fix is true, files missing a header get one written
// under rootDir; files with a wrong licence identifier are always reported.
func Check(fsys fs.FS, rootDir string, fix bool) (problems []Problem, fixed []string, err error) {
	err = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if p != "." && (skipDirs[d.Name()] || p == "tools/pins" || slices.Contains(thirdPartyDirs, p)) {
				return fs.SkipDir
			}
			return nil
		}
		prefix, ok := commentPrefix[path.Ext(p)]
		if !ok || !d.Type().IsRegular() {
			return nil
		}
		content, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		want := ExpectedLicense(p)
		switch got, hasCopyright := scanHeader(content); {
		case got == want && hasCopyright:
			return nil
		case got != "" && got != want:
			problems = append(problems, Problem{p, fmt.Sprintf("licence %s, want %s", got, want)})
		case fix:
			if err := os.WriteFile(filepath.Join(rootDir, filepath.FromSlash(p)), AddHeader(content, prefix, want), 0o644); err != nil { //nolint:gosec // source files are world-readable by design
				return err
			}
			fixed = append(fixed, p)
		default:
			problems = append(problems, Problem{p, "missing SPDX licence and/or copyright header"})
		}
		return nil
	})
	slices.SortFunc(problems, func(a, b Problem) int { return strings.Compare(a.Path, b.Path) })
	return problems, fixed, err
}

// ExpectedLicense returns the SPDX identifier required for a repository-relative path.
func ExpectedLicense(p string) string {
	if isApache(p) {
		return spdxApache
	}
	return spdxBUSL
}

// scanHeader returns the SPDX identifier and whether a copyright line naming
// the owner appears within the first headerWindow lines.
func scanHeader(content []byte) (spdx string, hasCopyright bool) {
	sc := bufio.NewScanner(bytes.NewReader(content))
	for i := 0; i < headerWindow && sc.Scan(); i++ {
		line := sc.Text()
		if _, after, ok := strings.Cut(line, "SPDX-License-Identifier:"); ok && spdx == "" {
			spdx = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(after), "-->"))
		}
		if strings.Contains(line, "Copyright") && strings.Contains(line, owner) {
			hasCopyright = true
		}
	}
	return spdx, hasCopyright
}

// AddHeader returns content with the licence header inserted, keeping a
// leading shebang line first.
func AddHeader(content []byte, prefix, spdx string) []byte {
	copyright := "Copyright (c) 2026 " + owner + ". See LICENSE and NOTICE."
	if spdx == spdxApache {
		copyright = "Copyright 2026 " + owner
	}
	header := fmt.Sprintf("%s SPDX-License-Identifier: %s\n%s %s\n\n", prefix, spdx, prefix, copyright)

	var out bytes.Buffer
	if bytes.HasPrefix(content, []byte("#!")) {
		line, rest, found := bytes.Cut(content, []byte("\n"))
		out.Write(line)
		out.WriteByte('\n')
		if !found {
			rest = nil
		}
		content = rest
	}
	out.WriteString(header)
	out.Write(content)
	return out.Bytes()
}
