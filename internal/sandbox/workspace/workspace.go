// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package workspace moves an agent's workspace into and out of the
// sandbox as a tar stream (G0 M9 design decision 10): the agent never gets
// a bind mount of the host's files, so credentials elsewhere on the host
// stay out of its reach. Pack writes a directory as a tar; Unpack writes a
// tar into a directory and refuses anything that could land outside it:
// absolute or parent paths, links, devices, and archives over the limits.
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
	"strings"
)

// Limits of one workspace.
const (
	MaxFiles = 100_000
	MaxBytes = 4 << 30
)

// ErrUnsafe reports an archive entry Unpack refuses.
var ErrUnsafe = errors.New("workspace: unsafe archive entry")

// Pack writes the regular files and directories under root to w as a tar.
// Symbolic links and other special files are skipped: a link could point
// anywhere on the host.
func Pack(root string, w io.Writer) error {
	tw := tar.NewWriter(w)
	var files int
	var size int64
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil || rel == "." {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() && !info.IsDir() {
			return nil
		}
		if files++; files > MaxFiles {
			return fmt.Errorf("workspace: more than %d files", MaxFiles)
		}
		hdr := &tar.Header{Name: filepath.ToSlash(rel), ModTime: info.ModTime(), Mode: 0o644, Typeflag: tar.TypeReg, Size: info.Size()}
		if info.IsDir() {
			hdr.Name, hdr.Mode, hdr.Typeflag, hdr.Size = hdr.Name+"/", 0o755, tar.TypeDir, 0
		} else if info.Mode()&0o111 != 0 {
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
	return tw.Close()
}

// Unpack writes the tar in r under root, which must exist. Only regular
// files and directories with relative, clean paths are written; anything
// else is refused before it is written.
func Unpack(r io.Reader, root string) error {
	tr := tar.NewReader(r)
	var files int
	var size int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return err
		}
		name := strings.TrimSuffix(hdr.Name, "/")
		if name == "" || path.IsAbs(name) || strings.Contains(name, "\\") || path.Clean(name) != name || name == ".." ||
			strings.HasPrefix(name, "../") || strings.ContainsRune(name, 0) {
			return fmt.Errorf("%w: %q", ErrUnsafe, hdr.Name)
		}
		if files++; files > MaxFiles {
			return fmt.Errorf("%w: more than %d files", ErrUnsafe, MaxFiles)
		}
		dst := filepath.Join(root, filepath.FromSlash(name))
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, 0o750); err != nil {
				return err
			}
		case tar.TypeReg:
			if size += hdr.Size; hdr.Size < 0 || size > MaxBytes {
				return fmt.Errorf("%w: more than %d bytes", ErrUnsafe, MaxBytes)
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
				return err
			}
			mode := os.FileMode(0o644)
			if hdr.Mode&0o111 != 0 {
				mode = 0o755
			}
			if err := write(dst, tr, hdr.Size, mode); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: %q is not a file or directory", ErrUnsafe, hdr.Name)
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
