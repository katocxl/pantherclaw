// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/katocxl/pantherclaw/internal/agentconfig"
)

// protectedWrite says whether a write tool's call writes a protected agent
// configuration or memory file (G0 M30 D943), and that file's base
// directory, slash-separated path relative to it, and class. The file is
// checked against the project entries relative to cwd, the user's
// configuration directory entries relative to os.UserConfigDir, and the
// user's home entries relative to the home (HR-712: project and user scope;
// D1215 supersedes D943a(b)); the first base that marks it is the one
// returned. The target is resolved to its final path first, as far as it
// exists, so a link or junction into a protected file is the protected
// file. Anything that cannot be resolved is an error, which blocks the
// write (fail closed).
func protectedWrite(in hookInput, cwd string) (base, rel string, class agentconfig.PathClass, ok bool, err error) {
	p := in.ToolInput.FilePath
	if in.Tool == "NotebookEdit" {
		p = in.ToolInput.NotebookPath
	}
	if p == "" {
		return "", "", "", false, fmt.Errorf("a %s call names no file", in.Tool)
	}
	target, err := finalTarget(p, cwd)
	if err != nil {
		return "", "", "", false, fmt.Errorf("the file written cannot be resolved to its final path: %w", err)
	}
	if rel, ok := under(cwd, target); ok {
		if class, protected := agentconfig.Classify(rel); protected {
			return cwd, rel, class, true, nil
		}
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", "", "", false, errors.New("the home directory is unknown, so a write cannot be checked against the user's files")
	}
	config, err := os.UserConfigDir()
	if err != nil || config == "" {
		return "", "", "", false, errors.New("the configuration directory is unknown, so a write cannot be checked against the user's files")
	}
	for _, b := range []struct {
		dir  string
		root agentconfig.Root
	}{{config, agentconfig.RootConfig}, {home, agentconfig.RootHome}} {
		dir, err := resolveExisting(b.dir)
		if err != nil {
			return "", "", "", false, fmt.Errorf("the user's %s directory cannot be resolved to its final path: %w", b.root, err)
		}
		if rel, ok := under(dir, target); ok {
			if e, protected := agentconfig.MatchRoot(b.root, rel); protected {
				return dir, rel, e.Class, true, nil
			}
		}
	}
	return "", "", "", false, nil
}

// resolveExisting is the final path of a directory that may not exist yet
// (a configuration directory no client has made): its nearest existing
// ancestor resolved, joined with the rest, as for the target.
func resolveExisting(dir string) (string, error) {
	return finalTarget(dir, dir)
}

// onDiskSpelling respells each name of an absolute path as its directory
// spells it: the exact name when the directory holds it, else the one name
// equal to it without case. Past the first name the directory holds in
// neither form, the rest is kept as given. macOS file systems fold case, so
// "claude.md" opens CLAUDE.md; this gives the path the file's own spelling
// (G0 M30 D1215).
func onDiskSpelling(abs string) string {
	vol := filepath.VolumeName(abs)
	names := strings.Split(strings.TrimPrefix(abs[len(vol):], string(filepath.Separator)), string(filepath.Separator))
	dir := vol + string(filepath.Separator)
	for i, name := range names {
		if name == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return filepath.Join(append([]string{dir}, names[i:]...)...)
		}
		spelled := ""
		for _, e := range entries {
			if e.Name() == name {
				spelled = name
				break
			}
			if spelled == "" && strings.EqualFold(e.Name(), name) {
				spelled = e.Name()
			}
		}
		if spelled == "" {
			return filepath.Join(append([]string{dir}, names[i:]...)...)
		}
		dir = filepath.Join(dir, spelled)
	}
	return dir
}

// under is target's slash-separated path relative to dir, ok false when it
// is not below dir (or on another volume).
func under(dir, target string) (string, bool) {
	rel, err := filepath.Rel(dir, target)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

// finalTarget is the final path of a file about to be written: the final
// path of its nearest existing ancestor (the file itself when it exists)
// joined with the names that do not exist yet. On Windows those names are
// spelled as Windows will create them (trailing dots and spaces dropped),
// and a name with a colon (an alternate data stream) is refused.
func finalTarget(p, cwd string) (string, error) {
	if !filepath.IsAbs(p) {
		p = filepath.Join(cwd, p)
	}
	p = filepath.Clean(p)
	var rest []string
	for {
		if _, err := os.Lstat(p); err == nil {
			final, err := resolveFinal(p)
			if err != nil {
				return "", err
			}
			return filepath.Join(append([]string{final}, rest...)...), nil
		}
		parent := filepath.Dir(p)
		if parent == p {
			return "", errors.New("no part of the path exists")
		}
		name := filepath.Base(p)
		if runtime.GOOS == "windows" {
			if strings.ContainsRune(name, ':') {
				return "", errors.New("alternate data streams are not written through the hook")
			}
			name = strings.TrimRight(name, ". ")
		}
		rest = append([]string{name}, rest...)
		p = parent
	}
}
