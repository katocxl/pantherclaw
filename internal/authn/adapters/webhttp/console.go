// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
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
// extension routes. The bundle is read once, when the console is made:
// every file and its .br/.gz siblings are held in memory with their ETags,
// so a bundle changed on disk later is never served, nor mixed with the
// one loaded.
type Console struct {
	files map[string]consoleFile
	index consoleFile
}

// consoleFile is one file of the bundle as loaded.
type consoleFile struct {
	body []byte
	etag string
}

// maxConsoleBytes bounds the bundle held in memory.
const maxConsoleBytes = 64 << 20

// NewConsole loads the bundle, which must have an index.html.
func NewConsole(fsys fs.FS) (*Console, error) {
	if fsys == nil {
		return nil, errors.New("webhttp: console bundle required")
	}
	c := &Console{files: map[string]consoleFile{}}
	total := 0
	err := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		b, err := fs.ReadFile(fsys, name)
		if err != nil {
			return err
		}
		if total += len(b); total > maxConsoleBytes {
			return errors.New("webhttp: console bundle larger than 64 MiB")
		}
		sum := sha256.Sum256(b)
		c.files[name] = consoleFile{body: b, etag: `"` + hex.EncodeToString(sum[:16]) + `"`}
		return nil
	})
	if err != nil {
		return nil, err
	}
	index, ok := c.files["index.html"]
	if !ok {
		return nil, errors.New("webhttp: console bundle has no index.html")
	}
	c.index = index
	return c, nil
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
		if f, ok := c.file(name); ok {
			c.write(w, r, name, f, immutable)
			return
		}
		consoleHeaders(w, "no-store")
		http.NotFound(w, r)
		return
	}
	if name != "" && name != "index.html" {
		if f, ok := c.file(name); ok {
			c.write(w, r, name, f, "no-store")
			return
		}
	}
	c.write(w, r, "index.html", c.index, "no-store")
}

// file is one loaded file of the bundle.
func (c *Console) file(name string) (consoleFile, bool) {
	if !fs.ValidPath(name) {
		return consoleFile{}, false
	}
	f, ok := c.files[name]
	return f, ok
}

// consoleTypes are the media types the bundle may contain; anything else
// is served as application/octet-stream (never sniffed: nosniff).
var consoleTypes = map[string]string{
	".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8",
	".css": "text/css; charset=utf-8", ".json": "application/json", ".webmanifest": "application/manifest+json",
	".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon", ".webp": "image/webp",
	".woff2": "font/woff2", ".woff": "font/woff", ".txt": "text/plain; charset=utf-8", ".map": "application/json",
}

// compressible are the extensions whose precompressed siblings are served.
var compressible = map[string]bool{
	".html": true, ".js": true, ".mjs": true, ".css": true, ".json": true, ".webmanifest": true, ".svg": true,
	".txt": true, ".map": true,
}

// encodings are the precompressed siblings the console serves, in order of
// preference: name.br, then name.gz. Nothing is compressed on the fly.
var encodings = []struct{ coding, suffix string }{{"br", ".br"}, {"gzip", ".gz"}}

func (c *Console) write(w http.ResponseWriter, r *http.Request, name string, f consoleFile, cache string) {
	consoleHeaders(w, cache)
	ext := strings.ToLower(path.Ext(name))
	ct, ok := consoleTypes[ext]
	if !ok {
		if ct = mime.TypeByExtension(path.Ext(name)); ct == "" || strings.HasPrefix(ct, "text/html") {
			ct = "application/octet-stream"
		}
	}
	hd := w.Header()
	hd.Set("Content-Type", ct)
	if compressible[ext] {
		hd.Set("Vary", "Accept-Encoding")
		accept := parseAcceptEncoding(r.Header.Values("Accept-Encoding"))
		// The most acceptable sibling; on equal weights the earlier one (br).
		best, bestQ := "", 0.0
		var sibling consoleFile
		for _, e := range encodings {
			q := accept.q(e.coding)
			if q <= bestQ {
				continue
			}
			if enc, ok := c.file(name + e.suffix); ok {
				best, bestQ, sibling = e.coding, q, enc
			}
		}
		identity := accept.q("identity")
		switch {
		case best != "" && bestQ >= identity:
			// A sibling at least as acceptable as the plain file wins.
			hd.Set("Content-Encoding", best)
			f = sibling
		case identity > 0:
		case best != "":
			hd.Set("Content-Encoding", best)
			f = sibling
		default:
			// Identity refused and no acceptable sibling.
			http.Error(w, "no acceptable content encoding", http.StatusNotAcceptable)
			return
		}
	}
	hd.Set("ETag", f.etag)
	if hd.Get("Content-Encoding") != "" {
		// ServeContent leaves the length out of an encoded response; an
		// encoded body is always sent whole (no ranges).
		hd.Set("Content-Length", strconv.Itoa(len(f.body)))
		r = r.Clone(r.Context())
		r.Header.Del("Range")
	}
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(f.body))
}

// acceptEncoding is a parsed Accept-Encoding header: q-values by coding
// (lower case) and the * entry.
type acceptEncoding struct {
	q8      map[string]float64
	star    float64
	hasStar bool
}

// q is coding's acceptability (RFC 9110 §12.5.3): its own entry, else
// *'s, else 0 for a content coding and identityDefault for identity:
// the plain file is acceptable unless excluded, but a coding the client
// accepts is preferred to it unless identity is weighted. Without the
// header, only identity is acceptable.
const identityDefault = 0.001

func (a acceptEncoding) q(coding string) float64 {
	if v, ok := a.q8[coding]; ok {
		return v
	}
	if a.hasStar {
		return a.star
	}
	if coding == "identity" {
		return identityDefault
	}
	return 0
}

func parseAcceptEncoding(lines []string) acceptEncoding {
	a := acceptEncoding{q8: map[string]float64{}}
	for _, line := range lines {
		for part := range strings.SplitSeq(line, ",") {
			coding, params, _ := strings.Cut(strings.TrimSpace(part), ";")
			coding = strings.ToLower(strings.TrimSpace(coding))
			if coding == "" {
				continue
			}
			q := 1.0
			for p := range strings.SplitSeq(params, ";") {
				k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
				if ok && strings.EqualFold(strings.TrimSpace(k), "q") {
					f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
					if err != nil || !(f >= 0 && f <= 1) { // also NaN
						f = 0 // an unreadable weight never selects a coding
					}
					q = f
				}
			}
			if coding == "*" {
				a.star, a.hasStar = q, true
				continue
			}
			if coding == "x-gzip" {
				coding = "gzip"
			}
			a.q8[coding] = q
		}
	}
	return a
}
