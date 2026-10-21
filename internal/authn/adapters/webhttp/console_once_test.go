// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp_test

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
)

// TestConsoleBundleIsReadOnce (G0 UI D97): the console serves the bundle
// as it was when the console was made; a file changed or a sibling added
// on disk later is never served.
func TestConsoleBundleIsReadOnce(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("index.html", "<!doctype html>v1")
	write("assets/app-1.js", "v1-app")
	c, err := webhttp.NewConsole(os.DirFS(dir))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	c.Mount(mux)
	write("index.html", "<!doctype html>v2")
	write("assets/app-1.js", "v2-app")
	write("assets/app-1.js.br", "BR-v2")
	write("assets/new-2.js", "new")
	if w := getEncoded(t, mux, "/app/assets/app-1.js", "br"); w.Body.String() != "v1-app" || w.Result().Header.Get("Content-Encoding") != "" {
		t.Errorf("app after a change on disk: %q %q", w.Body.String(), w.Result().Header.Get("Content-Encoding"))
	}
	if w := getEncoded(t, mux, "/app/", ""); w.Body.String() != "<!doctype html>v1" {
		t.Errorf("shell after a change on disk: %q", w.Body.String())
	}
	if w := getEncoded(t, mux, "/app/assets/new-2.js", ""); w.Code != http.StatusNotFound {
		t.Errorf("a file added after start: %d", w.Code)
	}
}
