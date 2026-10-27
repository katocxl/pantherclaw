# Static documentation site

`task docs:build` renders the sources in `docs/site.json` into `dist/docs`.
The output directory must not already exist; use a fresh checkout or choose a
new `-out` path with `go -C tools run ./docsite -root .. -out ../dist/docs-preview`.
The generator never removes an existing directory. No service, database,
Node build, account, CDN or browser framework is needed.

The manifest selects public guides, runbooks, protocols, ADRs and measurements.
Planning briefs, the build tracker and internal security-review records stay
outside the site index. Links to selected Markdown pages become local HTML
links; other repository links continue to GitHub. Raw Markdown HTML and unsafe
link schemes are not rendered.

Serve the output over HTTP to preview it. Every page works without JavaScript;
search fetches a static JSON index on first use and matches locally. Search
results use text nodes. Scripts and styles are local files, with no inline
handlers, analytics, third-party runtime or credentials.

The `_headers` file provides the response headers for a compatible static host
(including Cloudflare Pages). The HTML also carries a CSP for local previews;
the response header additionally prevents framing. Publishing and DNS remain
pending the founder's external setup. A local build is not hosted G3 evidence.
