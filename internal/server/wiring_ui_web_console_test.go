// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	"github.com/katocxl/pantherclaw/internal/extension"
)

// TestConsoleServesPrecompressedSiblingsThroughTheMount (G0 UI D97): a
// built console's .br sibling travels over HTTP through the server's
// console mount with its encoding, length, Vary and the console CSP.
func TestConsoleServesPrecompressedSiblingsThroughTheMount(t *testing.T) {
	mux := http.NewServeMux()
	set := extension.Set{Console: fstest.MapFS{
		"index.html":            {Data: []byte("<!doctype html>")},
		"assets/index-9f.js":    {Data: []byte(strings.Repeat("x", 4096))},
		"assets/index-9f.js.br": {Data: []byte("tiny-br")},
	}}
	if err := mountConsole(mux, set); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/app/assets/index-9f.js", nil)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(res.Body)
	hd := res.Header
	if res.StatusCode != http.StatusOK || hd.Get("Content-Encoding") != "br" || string(body) != "tiny-br" ||
		res.ContentLength != int64(len("tiny-br")) || hd.Get("Vary") != "Accept-Encoding" ||
		hd.Get("Content-Type") != "text/javascript; charset=utf-8" || hd.Get("Content-Security-Policy") != webhttp.ConsoleCSP {
		t.Fatalf("through the mount: %d %v %q", res.StatusCode, hd, body)
	}
}
