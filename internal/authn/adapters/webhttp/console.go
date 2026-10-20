// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"bytes"
	"errors"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"
)

// ConsoleCSP is the Content-Security-Policy of every console response
// (HR-340, G0 UI D10): only the server's own scripts, styles, images,
// fonts, manifest and API; no inline script or style, no framing, no
// base, and Trusted Types required with no policy, so no string ever
// reaches an HTML sink.
const ConsoleCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; " +
	"connect-src 'self'; manifest-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; " +
	"require-trusted-types-for 'script'; trusted-types 'none'"

// Console paths.
const (
	ConsoleRoot   = "/app/"
	consoleAssets = "/app/assets/"
	// consoleExt is reserved for extension routes (internal/extension): the
	// console never answers under it.
	consoleExt = "/app/ext/"
)

// consoleHeaders are the page headers with the console's CSP (HR-151,
// HR-340).
func consoleHeaders(w http.ResponseWriter, cache string) {
	pageHeaders(w)
	hd := w.Header()
	hd.Set("Content-Security-Policy", ConsoleCSP)
	hd.Set("Cache-Control", cache)
}

// Console serves a built console bundle (index.html at its root) at
// /app/: files by path, hashed /app/assets/* as immutable, and every other
// path under /app/ as index.html (the single-page app routes it), never
// cached. Nothing under /app/ext/ is answered: those paths belong to
// extension routes.
type Console struct {
	fsys  fs.FS
	index []byte
}

// NewConsole checks the bundle has an index.html.
func NewConsole(fsys fs.FS) (*Console, error) {
	if fsys == nil {
		return nil, errors.New("webhttp: console bundle required")
	}
	index, err := fs.ReadFile(fsys, "index.html")
	if err != nil {
		return nil, errors.New("webhttp: console bundle has no index.html")
	}
	return &Console{fsys: fsys, index: index}, nil
}

// Mount installs GET /app/ (which also answers HEAD), the /app redirect
// the mux adds, and GET / → /app/.
func (c *Console) Mount(mux *http.ServeMux) {
	mux.Handle("GET "+ConsoleRoot, c)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		consoleHeaders(w, "no-store")
		http.Redirect(w, r, ConsoleRoot, http.StatusSeeOther)
	})
}

// immutable is the cache policy of content-hashed assets.
const immutable = "public, max-age=31536000, immutable"

func (c *Console) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if strings.HasPrefix(p, consoleExt) {
		consoleHeaders(w, "no-store")
		http.NotFound(w, r)
		return
	}
	name := strings.TrimPrefix(path.Clean(p), "/app")
	name = strings.TrimPrefix(name, "/")
	if strings.HasPrefix(p, consoleAssets) {
		// A missing asset is a 404, never the app shell: a stale page would
		// otherwise run index.html as a script.
		if b, ok := c.file(name); ok {
			c.write(w, r, name, b, immutable)
			return
		}
		consoleHeaders(w, "no-store")
		http.NotFound(w, r)
		return
	}
	if name != "" && name != "index.html" {
		if b, ok := c.file(name); ok {
			c.write(w, r, name, b, "no-store")
			return
		}
	}
	c.write(w, r, "index.html", c.index, "no-store")
}

// file reads one regular file of the bundle.
func (c *Console) file(name string) ([]byte, bool) {
	if !fs.ValidPath(name) {
		return nil, false
	}
	st, err := fs.Stat(c.fsys, name)
	if err != nil || !st.Mode().IsRegular() {
		return nil, false
	}
	b, err := fs.ReadFile(c.fsys, name)
	return b, err == nil
}

// consoleTypes are the media types the bundle may contain; anything else
// is served as application/octet-stream (never sniffed: nosniff).
var consoleTypes = map[string]string{
	".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8",
	".css": "text/css; charset=utf-8", ".json": "application/json", ".webmanifest": "application/manifest+json",
	".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon", ".webp": "image/webp",
	".woff2": "font/woff2", ".woff": "font/woff", ".txt": "text/plain; charset=utf-8", ".map": "application/json",
}

func (c *Console) write(w http.ResponseWriter, r *http.Request, name string, b []byte, cache string) {
	consoleHeaders(w, cache)
	ct, ok := consoleTypes[strings.ToLower(path.Ext(name))]
	if !ok {
		if ct = mime.TypeByExtension(path.Ext(name)); ct == "" || strings.HasPrefix(ct, "text/html") {
			ct = "application/octet-stream"
		}
	}
	w.Header().Set("Content-Type", ct)
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(b))
}
