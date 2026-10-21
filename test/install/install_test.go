// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package install tests install.sh (G0 M13 D36).
package install

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const version = "v9.9.9"

func archive(t *testing.T, payload string) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{"pclaw": payload, "LICENSE": "licence"} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// release serves one release: checksums.txt and the linux/amd64 archive.
func release(t *testing.T, checksums string, arc []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/" + version + "/checksums.txt":
			_, _ = w.Write([]byte(checksums))
		case "/" + version + "/pantherclaw_9.9.9_linux_amd64.tar.gz":
			_, _ = w.Write(arc)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// runInstall runs install.sh against srv with gh replaced by a script
// that exits ghExit ("" leaves no gh at all).
func runInstall(t *testing.T, srv *httptest.Server, ghExit string) (string, string, error) {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("skipped: no sh on PATH (install.sh is a POSIX shell script)")
	}
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "bin")
	gh := filepath.Join(tmp, "no-gh")
	if ghExit != "" {
		gh = filepath.Join(tmp, "gh")
		if err := os.WriteFile(gh, []byte("#!/bin/sh\necho \"fake gh $*\" >&2\nexit "+ghExit+"\n"), 0o755); err != nil { //nolint:gosec // G306: an executable test script
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, sh, filepath.Join("..", "..", "install.sh"), "--version", version, "--dir", dir) //nolint:gosec // G204: the repository's install script
	cmd.Env = append(os.Environ(),
		"PANTHERCLAW_RELEASE_BASE_URL="+srv.URL, "PANTHERCLAW_GH="+filepath.ToSlash(gh),
		"PANTHERCLAW_OS=linux", "PANTHERCLAW_ARCH=amd64", "HOME="+tmp)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	return out.String(), errb.String(), err
}

func installed(t *testing.T, out string) bool {
	t.Helper()
	return strings.Contains(out, "Installed pclaw to ")
}

// TestT179_TamperedInstallerRefused: install.sh installs nothing when the
// archive does not match checksums.txt, when checksums.txt has no (or
// more than one) line for it, or when gh exists and the attestation does
// not verify; it installs a matching archive, verifying the attestation
// with gh when gh exists and printing the manual command otherwise.
func TestT179_TamperedInstallerRefused(t *testing.T) {
	good := archive(t, "the real pclaw")
	evil := archive(t, "a tampered pclaw")
	name := "pantherclaw_9.9.9_linux_amd64.tar.gz"
	line := sum(good) + "  " + name + "\n"
	other := sum([]byte("x")) + "  pantherclaw_9.9.9_darwin_arm64.tar.gz\n"

	for _, tc := range []struct {
		name      string
		checksums string
		arc       []byte
		gh        string
		ok        bool
		want      string
	}{
		{"matching, attestation verifies", other + line, good, "0", true, "Attestation verified"},
		{"matching, no gh", line, good, "", true, "gh attestation verify " + name + " --repo katocxl/pantherclaw"},
		{"tampered archive", line, evil, "0", false, "SHA-256 mismatch"},
		{"tampered archive and checksums of another file", other, evil, "0", false, "has 0 entries"},
		{"two lines for the archive", line + sum(evil) + "  " + name + "\n", evil, "0", false, "has 2 entries"},
		{"attestation fails", line, good, "1", false, "does not verify"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := release(t, tc.checksums, tc.arc)
			out, errs, err := runInstall(t, srv, tc.gh)
			if tc.ok {
				if err != nil || !installed(t, out) {
					t.Fatalf("install failed: %v\n%s\n%s", err, out, errs)
				}
			} else {
				if err == nil || installed(t, out) {
					t.Fatalf("install succeeded:\n%s\n%s", out, errs)
				}
				if !strings.Contains(errs, "nothing installed") {
					t.Errorf("no refusal: %s", errs)
				}
			}
			if !strings.Contains(out+errs, tc.want) {
				t.Errorf("output lacks %q:\n%s\n%s", tc.want, out, errs)
			}
		})
	}
}
