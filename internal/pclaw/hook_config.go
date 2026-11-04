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
// directory, slash-separated path relative to it, and class. The base is
// the project in cwd when the file is in it; otherwise the user's home,
// when the file is under it and Classify marks its home-relative path
// (D943a: no paths beyond what Classify knows). The target is resolved to
// its final path first, as far as it exists, so a link or junction into a
// protected file is the protected file. Anything that cannot be resolved is
// an error, which blocks the write (fail closed).
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
		class, protected := agentconfig.Classify(rel)
		return cwd, rel, class, protected, nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", "", "", false, errors.New("the home directory is unknown, so a write outside the project cannot be checked")
	}
	if home, err = resolveFinal(home); err != nil {
		return "", "", "", false, fmt.Errorf("the home directory cannot be resolved to its final path: %w", err)
	}
	if rel, ok := under(home, target); ok {
		class, protected := agentconfig.Classify(rel)
		return home, rel, class, protected, nil
	}
	return "", "", "", false, nil
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
