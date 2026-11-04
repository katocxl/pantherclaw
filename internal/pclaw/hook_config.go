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
// configuration or memory file of the project in cwd (G0 M30 D943), and
// that file's project-relative, slash-separated path and class. The target
// is resolved to its final path first, as far as it exists, so a link or
// junction into a protected file is the protected file; a target outside
// the project is not one of its files. Anything that cannot be resolved is
// an error, which blocks the write (fail closed).
func protectedWrite(in hookInput, cwd string) (string, agentconfig.PathClass, bool, error) {
	p := in.ToolInput.FilePath
	if in.Tool == "NotebookEdit" {
		p = in.ToolInput.NotebookPath
	}
	if p == "" {
		return "", "", false, fmt.Errorf("a %s call names no file", in.Tool)
	}
	target, err := finalTarget(p, cwd)
	if err != nil {
		return "", "", false, fmt.Errorf("the file written cannot be resolved to its final path: %w", err)
	}
	rel, err := filepath.Rel(cwd, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", "", false, nil //nolint:nilerr // on another volume: not a file of this project
	}
	rel = filepath.ToSlash(rel)
	class, ok := agentconfig.Classify(rel)
	return rel, class, ok, nil
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
