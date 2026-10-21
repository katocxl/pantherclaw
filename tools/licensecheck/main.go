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
var apachePrefixes = []string{"sdk/", "integrations/", "docs/protocol/"}

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
	for _, p := range problems {
		_, _ = fmt.Fprintf(stdout, "%s: %s\n", p.Path, p.Reason)
	}
	if len(problems) > 0 {
		_, _ = fmt.Fprintf(stderr, "licensecheck: %d file(s) without a valid licence header (run with -fix)\n", len(problems))
		return 1
	}
	return 0
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
	for _, pre := range apachePrefixes {
		if strings.HasPrefix(p, pre) {
			return spdxApache
		}
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
