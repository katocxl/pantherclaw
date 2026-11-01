// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// errBinaryWritable refuses --all-users on a binary a person without admin
// rights could replace: it would run as root or SYSTEM (G0 M24 D249).
var errBinaryWritable = errors.New("SCAN_BINARY_WRITABLE: --all-users runs as root or SYSTEM, so pclaw must be where only an admin can replace it: " +
	"root-owned with no group or world write up its path, or under %ProgramFiles% or %SystemRoot%")

// resolvedExecutable is this binary's own path, with no link left in it.
func resolvedExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

func checkBinaryProtected() bool {
	exe, err := resolvedExecutable()
	return err == nil && platformBinaryProtected(exe)
}

// unixBinaryProtected reports whether exe and every directory above it are
// root's, with no group or world write. stat answers for one path.
func unixBinaryProtected(exe string, stat func(string) (uid uint32, mode fs.FileMode, err error)) bool {
	if !path.IsAbs(exe) {
		return false
	}
	for p := path.Clean(exe); ; p = path.Dir(p) {
		uid, mode, err := stat(p)
		if err != nil || uid != 0 || mode.Perm()&0o022 != 0 {
			return false
		}
		if p == "/" {
			return true
		}
	}
}

// windowsBinaryProtected reports whether only an admin can replace exe: it is
// under %ProgramFiles% or %ProgramFiles(x86)%, or directly in System32 (G0 M24
// D282, D292). %SystemRoot% as a whole does not count, people may write to
// %SystemRoot%\Tasks, and nor does all of System32: they may write to
// System32\spool\drivers\color.
func windowsBinaryProtected(exe, programFiles, programFilesX86, systemRoot string) bool {
	clean := func(s string) string { return strings.ToLower(strings.TrimRight(strings.ReplaceAll(s, "/", `\`), `\`)) }
	exe = clean(exe)
	if strings.Contains(exe, `\..\`) {
		return false
	}
	if slices.ContainsFunc([]string{programFiles, programFilesX86}, func(root string) bool {
		return root != "" && strings.HasPrefix(exe, clean(root)+`\`)
	}) {
		return true
	}
	if systemRoot == "" {
		return false
	}
	name, in := strings.CutPrefix(exe, clean(systemRoot)+`\system32\`)
	return in && !strings.Contains(name, `\`)
}

// Paths under a home that another machine's rules also recognize, anywhere in
// a value: /home/x, /var/home/x, /Users/x, /mnt/<drive>/Users/x, C:\Users\x,
// and each as a file:// URL (D282). A name under /mnt/<drive>/Users is a Windows
// name, so it runs to the next / with any spaces in it (D293).
var (
	windowsHome = regexp.MustCompile(`(?i)\b[a-z]:[\\/]users[\\/][^\\/]+`)
	unixHome    = regexp.MustCompile(`(?i)(^|[\s:=,"'(]|file://(?:localhost)?)(?:/mnt/[a-z]/users/[^/]*[^/\s]|(?:/mnt/[a-z]|/var)?/(?:home|users)/[^/\s]+)`)
)

// tildeHome replaces a home directory in v with ~: one of homes at its start,
// and any home-shaped path within it.
func tildeHome(v string, homes []string) string {
	for _, h := range homes {
		if h == "" || len(v) < len(h) || !strings.EqualFold(v[:len(h)], h) {
			continue
		}
		if len(v) == len(h) || v[len(h)] == '/' || v[len(h)] == '\\' {
			v = "~" + v[len(h):]
			break
		}
	}
	v = windowsHome.ReplaceAllString(v, "~")
	return unixHome.ReplaceAllString(v, "${1}~")
}

// machineIDFromFiles is the first non-empty id among paths.
func machineIDFromFiles(paths ...string) (string, error) {
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(b)) != "" { //nolint:gosec // G304: fixed paths
			return strings.TrimSpace(string(b)), nil
		}
	}
	return "", errors.New("no machine id")
}

var ioPlatformUUID = regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]{36})"`)

// parseIOPlatformUUID finds the hardware UUID in ioreg's output.
func parseIOPlatformUUID(out []byte) (string, error) {
	m := ioPlatformUUID.FindSubmatch(out)
	if m == nil {
		return "", errors.New("no IOPlatformUUID")
	}
	return string(m[1]), nil
}

// envWith is env with the non-empty settings on top.
func envWith(env Env, settings map[string]string) Env {
	return func(name string) (string, bool) {
		if v := settings[name]; v != "" {
			return v, true
		}
		return env(name)
	}
}
