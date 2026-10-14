// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package workspace

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAWorkspaceRoundTrips(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "pkg", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for p, body := range map[string]string{"go.mod": "module x\n", "pkg/sub/a.go": "package sub\n", "empty.txt": ""} {
		if err := os.WriteFile(filepath.Join(src, filepath.FromSlash(p)), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if err := Pack(src, &buf); err != nil {
		t.Fatal(err)
	}
	if err := Unpack(&buf, dst); err != nil {
		t.Fatal(err)
	}
	for p, body := range map[string]string{"go.mod": "module x\n", "pkg/sub/a.go": "package sub\n", "empty.txt": ""} {
		b, err := os.ReadFile(filepath.Join(dst, filepath.FromSlash(p)))
		if err != nil || string(b) != body {
			t.Errorf("%s: %q, %v", p, b, err)
		}
	}
}

func archive(t *testing.T, hdrs ...*tar.Header) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range hdrs {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			_, _ = tw.Write(make([]byte, h.Size))
		}
	}
	_ = tw.Close()
	return &buf
}

// TestHR216_NothingLandsOutsideTheWorkspace: an archive entry that could
// write outside the workspace, or is not a plain file or directory, is
// refused before it is written.
func TestHR216_NothingLandsOutsideTheWorkspace(t *testing.T) {
	for name, h := range map[string]*tar.Header{
		"parent":    {Name: "../escape", Typeflag: tar.TypeReg, Size: 1},
		"nested":    {Name: "a/../../escape", Typeflag: tar.TypeReg, Size: 1},
		"absolute":  {Name: "/etc/passwd", Typeflag: tar.TypeReg, Size: 1},
		"symlink":   {Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
		"hardlink":  {Name: "link", Typeflag: tar.TypeLink, Linkname: "../x"},
		"device":    {Name: "dev", Typeflag: tar.TypeChar},
		"fifo":      {Name: "fifo", Typeflag: tar.TypeFifo},
		"backslash": {Name: `a\..\..\escape`, Typeflag: tar.TypeReg, Size: 1},
	} {
		dst := t.TempDir()
		if err := Unpack(archive(t, h), dst); !errors.Is(err, ErrUnsafe) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(dst), "escape")); err == nil {
			t.Errorf("%s: a file landed outside", name)
		}
	}
}

func TestPackSkipsLinks(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "a"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(os.TempDir(), filepath.Join(src, "link")); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	var buf bytes.Buffer
	if err := Pack(src, &buf); err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(&buf)
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		if h.Name == "link" {
			t.Fatal("a link was packed")
		}
	}
}
