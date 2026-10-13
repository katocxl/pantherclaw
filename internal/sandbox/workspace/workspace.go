// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package workspace moves an agent's workspace into and out of the
// sandbox as a tar stream (G0 M9 design decision 4): the agent never gets
// a bind mount of the host's files, so credentials elsewhere on the host
// stay out of its reach. Workspaces are patch only (founder decision
// 2026-10-11): the host's .git never goes in or out as it is.
//
// Pack writes a directory as a tar with its repository cleaned (objects and
// refs only, a generated config); Unpack writes a tar into a directory and
// refuses anything that could land outside it: absolute or parent paths,
// links, devices, and archives over the limits. PackFiles and UnpackFiles
// carry the agent's files back without any .git, and Diff turns them into
// a patch the developer applies to their own repository.
package workspace

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// Limits of one workspace.
const (
	MaxFiles = 100_000
	MaxBytes = 4 << 30
)

// ErrUnsafe reports an archive entry Unpack refuses.
var ErrUnsafe = errors.New("workspace: unsafe archive entry")

// gitMode is what a pack does with .git.
type gitMode int

const (
	// gitClean keeps the top-level repository's objects and refs only and
	// writes a generated config (copy-in).
	gitClean gitMode = iota
	// gitNone leaves every .git out (copy-out).
	gitNone
)

// gitKept are the top-level repository's files and directories copy-in
// keeps: objects (without alternates, which name host paths) and refs, and
// what names the checkout. Hooks, the config, info, logs and modules stay
// on the host; Pack writes its own config.
var gitKept = []string{".git/HEAD", ".git/index", ".git/packed-refs", ".git/shallow", ".git/objects", ".git/refs"}

// gitDropped are files under kept directories that copy-in still leaves out.
var gitDropped = []string{".git/objects/info/alternates", ".git/objects/info/http-alternates"}

// Pack writes the regular files and directories under root to w as a tar,
// for copy-in. A repository at root goes in cleaned: its objects, refs,
// HEAD, index, packed-refs and shallow, never executable, and a generated
// config without remotes, credential helpers, hooks or any other setting
// that runs a program; a nested repository or a .git file does not go in.
// Symbolic links and other special files are skipped: a link could point
// anywhere on the host.
func Pack(root string, w io.Writer) error { return pack(root, w, gitClean) }

// PackFiles writes the regular files and directories under root to w as a
// tar without any .git, for copy-out: the agent's changes come back as
// files only (founder decision 2026-10-11).
func PackFiles(root string, w io.Writer) error { return pack(root, w, gitNone) }

func pack(root string, w io.Writer, git gitMode) error {
	tw := tar.NewWriter(w)
	var files int
	var size int64
	repo := false
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil || rel == "." {
			return err
		}
		rel = filepath.ToSlash(rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() && !info.IsDir() {
			return nil
		}
		if inGit(rel) {
			if git == gitNone || !keepGit(rel, info.IsDir()) {
				if info.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			repo = repo || rel == ".git"
		}
		if files++; files > MaxFiles {
			return fmt.Errorf("workspace: more than %d files", MaxFiles)
		}
		hdr := &tar.Header{Name: rel, ModTime: info.ModTime(), Mode: 0o644, Typeflag: tar.TypeReg, Size: info.Size()}
		if info.IsDir() {
			hdr.Name, hdr.Mode, hdr.Typeflag, hdr.Size = hdr.Name+"/", 0o755, tar.TypeDir, 0
		} else if info.Mode()&0o111 != 0 && !inGit(rel) {
			hdr.Mode = 0o755
		}
		if size += hdr.Size; size > MaxBytes {
			return fmt.Errorf("workspace: more than %d bytes", MaxBytes)
		}
		if err := tw.WriteHeader(hdr); err != nil || info.IsDir() {
			return err
		}
		f, err := os.Open(p) //nolint:gosec // G304: a file of the workspace being packed
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		_, err = io.CopyN(tw, f, hdr.Size)
		return err
	})
	if err != nil {
		return err
	}
	if repo {
		config := gitConfig(filepath.Join(root, ".git", "config"))
		if err := tw.WriteHeader(&tar.Header{Name: ".git/config", Mode: 0o644, Typeflag: tar.TypeReg, Size: int64(len(config))}); err != nil {
			return err
		}
		if _, err := tw.Write(config); err != nil {
			return err
		}
	}
	return tw.Close()
}

// inGit reports whether a slash path is, or is inside, a .git as any host
// may read the name: in any case, with trailing dots or spaces (Windows
// drops them), or as its 8.3 short name GIT~1.
func inGit(rel string) bool {
	return slices.ContainsFunc(strings.Split(rel, "/"), func(s string) bool {
		s = strings.ToLower(strings.TrimRight(s, ". "))
		return s == ".git" || s == "git~1"
	})
}

// keepGit reports whether copy-in keeps a path of the top-level repository.
func keepGit(rel string, dir bool) bool {
	if rel == ".git" {
		return dir
	}
	if !strings.HasPrefix(rel, ".git/") || inGit(strings.TrimPrefix(rel, ".git/")) || slices.Contains(gitDropped, rel) {
		return false
	}
	for _, k := range gitKept {
		if rel == k || strings.HasPrefix(rel, k+"/") {
			return true
		}
	}
	return false
}

// gitConfig is the config copy-in writes for the repository: the format
// only, with the host's object format when it is SHA-256. Nothing of the
// host's config goes in.
func gitConfig(host string) []byte {
	sha256 := false
	if b, err := os.ReadFile(host); err == nil { //nolint:gosec // G304: the workspace's own repository config
		for line := range strings.Lines(strings.ToLower(string(b))) {
			if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && strings.TrimSpace(k) == "objectformat" && strings.TrimSpace(v) == "sha256" {
				sha256 = true
			}
		}
	}
	if sha256 {
		return []byte("[core]\n\trepositoryformatversion = 1\n\tbare = false\n[extensions]\n\tobjectformat = sha256\n")
	}
	return []byte("[core]\n\trepositoryformatversion = 0\n\tbare = false\n")
}

// Unpack writes the tar in r under root, which must exist. Only regular
// files and directories with relative, clean paths are written; anything
// else is refused before it is written.
func Unpack(r io.Reader, root string) error {
	_, err := unpack(r, root, false)
	return err
}

// UnpackFiles is Unpack for the agent's files coming back to the host: an
// entry in a .git is refused too, and on a Windows host so is a name
// Windows would read as something else (a stream, a device, a trailing dot
// or space). It returns the files the archive marks executable: a Windows
// host keeps no such bit.
func UnpackFiles(r io.Reader, root string) (Executables, error) { return unpack(r, root, true) }

// Executables are files marked executable, by slash path.
type Executables map[string]bool

func unpack(r io.Reader, root string, back bool) (Executables, error) {
	tr := tar.NewReader(r)
	exec := Executables{}
	var files int
	var size int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return exec, nil
		} else if err != nil {
			return nil, err
		}
		name := strings.TrimSuffix(hdr.Name, "/")
		if name == "" || path.IsAbs(name) || strings.Contains(name, "\\") || path.Clean(name) != name || name == ".." ||
			strings.HasPrefix(name, "../") || strings.ContainsRune(name, 0) {
			return nil, fmt.Errorf("%w: %q", ErrUnsafe, hdr.Name)
		}
		if back && (inGit(name) || (runtime.GOOS == "windows" && !portable(name))) {
			return nil, fmt.Errorf("%w: %q", ErrUnsafe, hdr.Name)
		}
		if files++; files > MaxFiles {
			return nil, fmt.Errorf("%w: more than %d files", ErrUnsafe, MaxFiles)
		}
		dst := filepath.Join(root, filepath.FromSlash(name))
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, 0o750); err != nil {
				return nil, err
			}
		case tar.TypeReg:
			if size += hdr.Size; hdr.Size < 0 || size > MaxBytes {
				return nil, fmt.Errorf("%w: more than %d bytes", ErrUnsafe, MaxBytes)
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
				return nil, err
			}
			mode := os.FileMode(0o644)
			if hdr.Mode&0o111 != 0 {
				mode = 0o755
				exec[name] = true
			}
			if err := write(dst, tr, hdr.Size, mode); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("%w: %q is not a file or directory", ErrUnsafe, hdr.Name)
		}
	}
}

// write creates dst, never following an existing link, and copies n bytes.
func write(dst string, r io.Reader, n int64, mode os.FileMode) error {
	if info, err := os.Lstat(dst); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s exists and is not a regular file", ErrUnsafe, dst)
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode) //nolint:gosec // G304: a path confined to root above
	if err != nil {
		return err
	}
	if _, err := io.CopyN(f, r, n); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// reserved are names Windows maps to devices, whatever the extension.
var reserved = []string{"con", "prn", "aux", "nul", "conin$", "conout$"}

// portable reports whether every element of a slash path is a name that
// Windows writes as it is: no stream (":") or other reserved character, no
// device name, no trailing dot or space.
func portable(name string) bool {
	for _, e := range strings.Split(name, "/") {
		base := strings.ToLower(e)
		if i := strings.IndexByte(base, '.'); i >= 0 {
			base = base[:i]
		}
		if strings.ContainsAny(e, `:<>"|?*`) || strings.HasSuffix(e, ".") || strings.HasSuffix(e, " ") || slices.Contains(reserved, base) ||
			(len(base) == 4 && (strings.HasPrefix(base, "com") || strings.HasPrefix(base, "lpt")) && base[3] >= '0' && base[3] <= '9') {
			return false
		}
	}
	return true
}
