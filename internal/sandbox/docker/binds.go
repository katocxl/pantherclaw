// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package docker

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// checkBinds holds a container's bind mounts to its bind root (HR-216): the
// root is a directory reached through no link that neither is nor holds the
// engine's socket, and every bind source is a regular file or directory
// strictly inside it, reached through no link either. So no bind can hand a
// container the socket, a directory that holds it, or anything else of the
// host's.
func checkBinds(root string, mounts []Mount) error {
	var binds []Mount
	for _, m := range mounts {
		if m.Kind == Bind {
			binds = append(binds, m)
		}
	}
	if len(binds) == 0 {
		return nil
	}
	if err := unlinked(root); err != nil {
		return errors.New("the bind root is not an absolute path reached through no link")
	}
	if fi, err := os.Lstat(root); err != nil || !fi.IsDir() {
		return errors.New("the bind root is not a directory")
	}
	for _, s := range engineSockets() {
		if samePath(root, s) || within(root, s) {
			return errors.New("the bind root holds the Docker socket")
		}
	}
	for _, m := range binds {
		if unlinked(m.Source) != nil || !within(root, m.Source) {
			return errors.New("a bind source is not in the bind root, or is reached through a link")
		}
		fi, err := os.Lstat(m.Source)
		if err != nil || (!fi.Mode().IsRegular() && !fi.IsDir()) {
			return errors.New("a bind source is not a regular file or directory")
		}
	}
	return nil
}

// unlinked fails unless p is absolute, clean and reached through no
// symbolic link or junction.
func unlinked(p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return errors.New("not an absolute clean path")
	}
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		return err
	}
	if !samePath(r, p) {
		return errors.New("reached through a link")
	}
	return nil
}

// within reports whether p lies strictly inside dir.
func within(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func samePath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

// engineSockets are the places the engine's socket may be on this host:
// DOCKER_HOST's, the system's, the rootless engine's and Docker Desktop's,
// each also through its resolved directory (/var/run is often /run).
func engineSockets() []string {
	var out []string
	if h, ok := strings.CutPrefix(os.Getenv("DOCKER_HOST"), "unix://"); ok && h != "" {
		out = append(out, h)
	}
	out = append(out, "/var/run/docker.sock", "/run/docker.sock")
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		out = append(out, filepath.Join(d, "docker.sock"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		out = append(out, filepath.Join(home, ".docker", "run", "docker.sock"), filepath.Join(home, ".docker", "desktop", "docker.sock"))
	}
	for _, s := range slices.Clone(out) {
		if d, err := filepath.EvalSymlinks(filepath.Dir(s)); err == nil {
			out = append(out, filepath.Join(d, filepath.Base(s)))
		}
	}
	return out
}
