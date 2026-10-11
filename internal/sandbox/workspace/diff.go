// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package workspace

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// Change is one path the agent changed.
type Change struct {
	Path string
	// Kind is "added", "modified", "deleted" or "mode".
	Kind string
	// Flagged marks a dotfile, an editor's or a task runner's file: one
	// that tools run or read as configuration, which the developer reviews
	// before running anything (founder decision 2026-10-11).
	Flagged bool
	// Binary is a file with binary content, old or new: it is not in the
	// patch, and the caller carries its new content another way.
	Binary bool
}

// Change kinds.
const (
	Added    = "added"
	Modified = "modified"
	Deleted  = "deleted"
	ModeOnly = "mode"
)

// taskFiles are file names that build and task tools run.
var taskFiles = []string{
	"makefile", "gnumakefile", "taskfile.yml", "taskfile.yaml", "justfile", "package.json", "pyproject.toml", "setup.py",
	"setup.cfg", "tox.ini", "noxfile.py", "rakefile", "gemfile", "build.gradle", "build.gradle.kts", "pom.xml",
	"cmakelists.txt", "dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
}

// Flagged reports whether a path is a dotfile or in a dot directory
// (.envrc, .vscode/, .idea/, .githooks/, …) or a build or task file.
func Flagged(p string) bool {
	for e := range strings.SplitSeq(p, "/") {
		if strings.HasPrefix(e, ".") {
			return true
		}
	}
	return slices.Contains(taskFiles, strings.ToLower(path.Base(p)))
}

// Diff writes to w a patch in git's format, which git apply applies, from
// the files under oldRoot (empty for none) to those under newRoot, and
// returns what changed. exec names newRoot's executable files, as
// UnpackFiles read them from the sandbox (nil takes the file system's
// bits); oldRoot's come from the file system, as Pack read them. A .git on
// either side is never read and nothing is run. A binary file is left out
// of the patch and marked Binary: git applies a binary patch only with SHA-1
// blob ids, a hash SB-3 keeps out of the code.
func Diff(oldRoot, newRoot string, exec Executables, w io.Writer) ([]Change, error) {
	olds, err := files(oldRoot)
	if err != nil {
		return nil, err
	}
	news, err := files(newRoot)
	if err != nil {
		return nil, err
	}
	if exec != nil {
		for p, f := range news {
			f.exec = exec[p]
			news[p] = f
		}
	}
	names := map[string]bool{}
	for p := range olds {
		names[p] = true
	}
	for p := range news {
		names[p] = true
	}
	bw := bufio.NewWriter(w)
	var out []Change
	for _, p := range slices.Sorted(func(yield func(string) bool) {
		for p := range names {
			if !yield(p) {
				return
			}
		}
	}) {
		o, oOK := olds[p]
		n, nOK := news[p]
		var ob, nb []byte
		if oOK {
			if ob, err = os.ReadFile(o.abs); err != nil {
				return nil, err
			}
		}
		if nOK {
			if nb, err = os.ReadFile(n.abs); err != nil {
				return nil, err
			}
		}
		c := Change{Path: p, Flagged: Flagged(p)}
		switch {
		case !oOK:
			c.Kind = Added
		case !nOK:
			c.Kind = Deleted
		case !bytes.Equal(ob, nb):
			c.Kind = Modified
		case o.exec != n.exec:
			c.Kind = ModeOnly
		default:
			continue
		}
		c.Binary = binary(ob) || binary(nb)
		out = append(out, c)
		if !c.Binary {
			writeFile(bw, p, oOK, nOK, ob, nb, o.exec, n.exec)
		}
	}
	return out, bw.Flush()
}

type file struct {
	abs  string
	exec bool
}

// files are the regular files under root by slash path, outside any .git.
func files(root string) (map[string]file, error) {
	out := map[string]file{}
	if root == "" {
		return out, nil
	}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil || rel == "." {
			return err
		}
		rel = filepath.ToSlash(rel)
		if inGit(rel) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() {
			return err
		}
		out[rel] = file{abs: p, exec: info.Mode()&0o111 != 0}
		return nil
	})
	return out, err
}

func writeFile(w *bufio.Writer, p string, oOK, nOK bool, ob, nb []byte, oExec, nExec bool) {
	a, b := quote("a/"+p), quote("b/"+p)
	fmt.Fprintf(w, "diff --git %s %s\n", a, b)
	om, nm := mode(oExec), mode(nExec)
	switch {
	case !oOK:
		fmt.Fprintf(w, "new file mode %s\n", nm)
	case !nOK:
		fmt.Fprintf(w, "deleted file mode %s\n", om)
	case om != nm:
		fmt.Fprintf(w, "old mode %s\nnew mode %s\n", om, nm)
	}
	if oOK && nOK && bytes.Equal(ob, nb) {
		return
	}
	if len(ob) == 0 && len(nb) == 0 {
		return
	}
	from, to := a, b
	if !oOK {
		from = "/dev/null"
	}
	if !nOK {
		to = "/dev/null"
	}
	fmt.Fprintf(w, "--- %s\n+++ %s\n", from, to)
	hunks(w, diffLines(lines(ob), lines(nb)))
}

func mode(exec bool) string {
	if exec {
		return "100755"
	}
	return "100644"
}

// binary is git's test: a NUL in the first 8000 bytes.
func binary(b []byte) bool {
	return bytes.IndexByte(b[:min(len(b), 8000)], 0) >= 0
}

// quote quotes a path the way git does when it has a control character, a
// quote, a backslash or a byte outside ASCII.
func quote(s string) string {
	if !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == '"' || r == '\\' || r >= 0x7f }) {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	for i := range len(s) {
		switch c := s[i]; c {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if c < 0x20 || c >= 0x7f {
				fmt.Fprintf(&b, `\%03o`, c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// lines splits b into lines, each with its newline but perhaps the last.
func lines(b []byte) []string {
	var out []string
	for l := range strings.Lines(string(b)) {
		out = append(out, l)
	}
	return out
}

// op is one line of an edit script: ' ' kept, '-' removed, '+' added.
type op struct {
	kind byte
	line string
}

// maxEdits bounds the diff's work; beyond it a file is replaced whole,
// which is a valid patch too.
const maxEdits = 2000

// diffLines is the shortest edit script from a to b (Myers' algorithm).
func diffLines(a, b []string) []op {
	n, m := len(a), len(b)
	v := map[int]int{1: 0}
	var trace []map[int]int
	for d := 0; d <= n+m && d <= maxEdits; d++ {
		snapshot := make(map[int]int, len(v))
		for k, x := range v {
			snapshot[k] = x
		}
		trace = append(trace, snapshot)
		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || (k != d && v[k-1] < v[k+1]) {
				x = v[k+1]
			} else {
				x = v[k-1] + 1
			}
			y := x - k
			for x < n && y < m && a[x] == b[y] {
				x++
				y++
			}
			v[k] = x
			if x >= n && y >= m {
				return backtrack(trace, a, b)
			}
		}
	}
	out := make([]op, 0, n+m)
	for _, l := range a {
		out = append(out, op{'-', l})
	}
	for _, l := range b {
		out = append(out, op{'+', l})
	}
	return out
}

func backtrack(trace []map[int]int, a, b []string) []op {
	x, y := len(a), len(b)
	var rev []op
	for d := len(trace) - 1; d >= 0; d-- {
		v := trace[d]
		k := x - y
		var pk int
		if k == -d || (k != d && v[k-1] < v[k+1]) {
			pk = k + 1
		} else {
			pk = k - 1
		}
		px := v[pk]
		py := px - pk
		for x > px && y > py {
			rev = append(rev, op{' ', a[x-1]})
			x--
			y--
		}
		if d > 0 {
			if x == px {
				rev = append(rev, op{'+', b[y-1]})
			} else {
				rev = append(rev, op{'-', a[x-1]})
			}
		}
		x, y = px, py
	}
	slices.Reverse(rev)
	return rev
}

// context is the number of unchanged lines around each change.
const context = 3

// hunks writes the edit script's changes as unified hunks.
func hunks(w *bufio.Writer, ops []op) {
	for i := 0; i < len(ops); {
		if ops[i].kind == ' ' {
			i++
			continue
		}
		start := max(0, i-context)
		end := i
		for j := i; j < len(ops); j++ {
			if ops[j].kind != ' ' {
				end = j + 1
			} else if j-end >= 2*context {
				break
			}
		}
		end = min(len(ops), end+context)
		var oldStart, newStart, oldN, newN int
		for _, o := range ops[:start] {
			if o.kind != '+' {
				oldStart++
			}
			if o.kind != '-' {
				newStart++
			}
		}
		for _, o := range ops[start:end] {
			if o.kind != '+' {
				oldN++
			}
			if o.kind != '-' {
				newN++
			}
		}
		fmt.Fprintf(w, "@@ -%s +%s @@\n", span(oldStart, oldN), span(newStart, newN))
		for _, o := range ops[start:end] {
			_ = w.WriteByte(o.kind)
			_, _ = w.WriteString(o.line)
			if !strings.HasSuffix(o.line, "\n") {
				_, _ = w.WriteString("\n\\ No newline at end of file\n")
			}
		}
		i = end
	}
}

// span is a hunk's range: its first line and its length; an empty range
// names the line before it.
func span(before, n int) string {
	if n == 0 {
		return fmt.Sprintf("%d,0", before)
	}
	return fmt.Sprintf("%d,%d", before+1, n)
}

// WriteManifest writes one line per change: its kind, its path (quoted as
// git quotes it, since the agent chose it), and "binary" and "review" for
// binary content and flagged files.
func WriteManifest(w io.Writer, changes []Change) error {
	bw := bufio.NewWriter(w)
	for _, c := range changes {
		line := c.Kind + "\t" + quote(c.Path)
		if c.Binary {
			line += "\tbinary"
		}
		if c.Flagged {
			line += "\treview"
		}
		_, _ = bw.WriteString(line + "\n")
	}
	return bw.Flush()
}
