// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sandbox

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"

	"github.com/katocxl/pantherclaw/internal/agentconfig"
	"github.com/katocxl/pantherclaw/internal/sandbox/docker"
	"github.com/katocxl/pantherclaw/internal/sandbox/probe"
)

// maxProtectedBinds bounds the protected files of one workspace.
const maxProtectedBinds = 256

// protectedTarget is what a bind target may be (the docker package's
// target pattern).
var protectedTarget = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)

// protectedBinds keeps the workspace's agent configuration and memory files
// read-only for the agent (G0 M30 D944, HR-713): each existing file that
// agentconfig.Classify marks protected is copied into the session's private
// directory and bound read-only over /workspace/<path>. Binds are always
// read-only, and agentChecks accepts them as regular files of the session
// directory. A protected file that cannot be bound stops the session
// (fail closed); links and .git are not followed.
func (s *Sandbox) protectedBinds(workspace string) ([]docker.Mount, error) {
	if workspace == "" {
		return nil, nil
	}
	root, err := filepath.Abs(workspace)
	if err != nil {
		return nil, err
	}
	var rels []string
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil || rel == "." {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if _, ok := agentconfig.Classify(rel); ok {
			rels = append(rels, rel)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(rels) > maxProtectedBinds {
		return nil, fmt.Errorf("sandbox: the workspace has %d agent configuration and memory files; at most %d are kept read-only", len(rels), maxProtectedBinds)
	}
	dir := filepath.Join(s.o.Dir, "protected")
	if len(rels) > 0 {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return nil, err
		}
	}
	mounts := make([]docker.Mount, 0, len(rels))
	for i, rel := range rels {
		target := path.Join(probe.Workspace, rel)
		if !protectedTarget.MatchString(target) {
			return nil, fmt.Errorf("sandbox: the agent configuration file %q cannot be kept read-only (its name)", rel)
		}
		dst := filepath.Join(dir, fmt.Sprintf("f%03d", i))
		if err := copyFile(filepath.Join(root, filepath.FromSlash(rel)), dst); err != nil {
			return nil, err
		}
		mounts = append(mounts, docker.Mount{Kind: docker.Bind, Source: dst, Target: target, ReadOnly: true})
	}
	return mounts, nil
}
