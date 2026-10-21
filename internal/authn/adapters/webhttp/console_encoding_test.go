// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp_test

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"testing/fstest"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
)

// encodedConsole has br and gzip siblings for the shell and the script,
// only gzip for the stylesheet, none for the image, and a br sibling for a
// font, which is never served compressed.
var encodedConsole = fstest.MapFS{
	"index.html":           {Data: []byte("<!doctype html>shell")},
	"index.html.br":        {Data: []byte("BR-shell")},
	"index.html.gz":        {Data: []byte("GZ-shell")},
	"assets/app-1.js":      {Data: []byte("console.log('app')")},
	"assets/app-1.js.br":   {Data: []byte("BR-app")},
	"assets/app-1.js.gz":   {Data: []byte("GZ-app")},
	"assets/app-1.css":     {Data: []byte("body{}")},
	"assets/app-1.css.gz":  {Data: []byte("GZ-css")},
	"assets/plain-1.js":    {Data: []byte("plain()")},
	"assets/font.woff2":    {Data: []byte("wOF2")},
	"assets/font.woff2.br": {Data: []byte("BR-font")},
}

func encodedMux(t *testing.T) http.Handler {
	t.Helper()
	c, err := webhttp.NewConsole(encodedConsole)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	c.Mount(mux)
	return mux
}

func getEncoded(t *testing.T, mux http.Handler, path, accept string, hdr ...string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, origin+path, nil)
	if accept != "" {
		r.Header.Set("Accept-Encoding", accept)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

// TestConsolePrecompressedSiblings (G0 UI D97): the console serves a
// file's .br or .gz sibling when the client accepts it, br first, with
// Accept-Encoding weights applied (q=0 refuses a coding, identity;q=0
// refuses the plain file), Content-Encoding and Vary set, the media type
// of the original name, the encoded body's length and an ETag of its own;
// fonts and images are served as they are; nothing is compressed on the
// fly.
func TestConsolePrecompressedSiblings(t *testing.T) {
	mux := encodedMux(t)
	for _, tc := range []struct {
		name, path, accept string
		status             int
		encoding, body     string
		vary               bool
	}{
		{"br first", "/app/assets/app-1.js", "gzip, deflate, br", 200, "br", "BR-app", true},
		{"gzip only", "/app/assets/app-1.js", "gzip", 200, "gzip", "GZ-app", true},
		{"x-gzip alias", "/app/assets/app-1.js", "x-gzip", 200, "gzip", "GZ-app", true},
		{"weights", "/app/assets/app-1.js", "br;q=0.5, gzip;q=0.9", 200, "gzip", "GZ-app", true},
		{"br refused", "/app/assets/app-1.js", "br;q=0, gzip", 200, "gzip", "GZ-app", true},
		{"both refused", "/app/assets/app-1.js", "br;q=0, gzip;q=0", 200, "", "console.log('app')", true},
		{"no header", "/app/assets/app-1.js", "", 200, "", "console.log('app')", true},
		{"identity preferred", "/app/assets/app-1.js", "identity;q=1, br;q=0.4", 200, "", "console.log('app')", true},
		{"star", "/app/assets/app-1.js", "*", 200, "br", "BR-app", true},
		{"star refuses all but identity", "/app/assets/app-1.js", "*;q=0, identity", 200, "", "console.log('app')", true},
		{"identity refused", "/app/assets/app-1.js", "identity;q=0, gzip", 200, "gzip", "GZ-app", true},
		{"identity refused, nothing else", "/app/assets/app-1.js", "identity;q=0", 406, "", "", true},
		{"star refused", "/app/assets/app-1.js", "*;q=0", 406, "", "", true},
		{"unreadable weight", "/app/assets/app-1.js", "br;q=high", 200, "", "console.log('app')", true},
		{"gzip sibling only", "/app/assets/app-1.css", "br, gzip", 200, "gzip", "GZ-css", true},
		{"no sibling", "/app/assets/plain-1.js", "br, gzip", 200, "", "plain()", true},
		{"font never compressed", "/app/assets/font.woff2", "br", 200, "", "wOF2", false},
		{"shell", "/app/", "br", 200, "br", "BR-shell", true},
		{"SPA fallback", "/app/agents/1", "gzip", 200, "gzip", "GZ-shell", true},
	} {
		w := getEncoded(t, mux, tc.path, tc.accept)
		hd := w.Result().Header
		if w.Code != tc.status {
			t.Errorf("%s: status %d, want %d", tc.name, w.Code, tc.status)
			continue
		}
		if (hd.Get("Vary") == "Accept-Encoding") != tc.vary {
			t.Errorf("%s: Vary %q", tc.name, hd.Get("Vary"))
		}
		if tc.status != 200 {
			continue
		}
		if hd.Get("Content-Encoding") != tc.encoding || w.Body.String() != tc.body {
			t.Errorf("%s: encoding %q body %q, want %q %q", tc.name, hd.Get("Content-Encoding"), w.Body.String(), tc.encoding, tc.body)
		}
		if hd.Get("Content-Length") != strconv.Itoa(len(tc.body)) {
			t.Errorf("%s: Content-Length %q for %d bytes", tc.name, hd.Get("Content-Length"), len(tc.body))
		}
		if hd.Get("Content-Security-Policy") != webhttp.ConsoleCSP || hd.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: page headers %v", tc.name, hd)
		}
	}
	// The media type is the original name's, not the sibling's.
	if ct := getEncoded(t, mux, "/app/assets/app-1.js", "br").Result().Header.Get("Content-Type"); ct != "text/javascript; charset=utf-8" {
		t.Errorf("js Content-Type %q", ct)
	}
	if ct := getEncoded(t, mux, "/app/agents", "br").Result().Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("shell Content-Type %q", ct)
	}
	// Each representation has its own ETag, and a conditional request
	// matches only its own.
	tags := map[string]string{}
	for _, accept := range []string{"br", "gzip", ""} {
		tags[accept] = getEncoded(t, mux, "/app/assets/app-1.js", accept).Result().Header.Get("ETag")
	}
	if tags["br"] == "" || tags["br"] == tags["gzip"] || tags["br"] == tags[""] || tags["gzip"] == tags[""] {
		t.Fatalf("ETags %v", tags)
	}
	if w := getEncoded(t, mux, "/app/assets/app-1.js", "br", "If-None-Match", tags["br"]); w.Code != http.StatusNotModified {
		t.Errorf("If-None-Match br under br = %d", w.Code)
	}
	if w := getEncoded(t, mux, "/app/assets/app-1.js", "gzip", "If-None-Match", tags["br"]); w.Code != http.StatusOK {
		t.Errorf("If-None-Match br under gzip = %d", w.Code)
	}
	// Cache policy is unchanged: hashed assets immutable, the shell never cached.
	if cc := getEncoded(t, mux, "/app/assets/app-1.js", "br").Result().Header.Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Errorf("asset Cache-Control %q", cc)
	}
	if cc := getEncoded(t, mux, "/app/", "br").Result().Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("shell Cache-Control %q", cc)
	}
}
