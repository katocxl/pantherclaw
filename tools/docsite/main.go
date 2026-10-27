// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Command docsite renders the curated public Markdown as a standalone static site.
package main

import (
	"bytes"
	"embed"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	gmtext "github.com/yuin/goldmark/text"
)

//go:embed assets/*
var assets embed.FS

const sourceBase = "https://github.com/katocxl/pantherclaw/blob/main/"
const imageBase = "https://raw.githubusercontent.com/katocxl/pantherclaw/main/"

type entry struct {
	Title string `json:"title"`
	URL   string `json:"url"`
	Text  string `json:"text"`
}

type page struct {
	Title  string
	Source string
	Prefix string
	Body   template.HTML // Only the safe Markdown renderer's output is trusted.
	Pages  []entry
}

func main() {
	root := flag.String("root", "..", "repository root")
	out := flag.String("out", "../dist/docs", "new, empty output directory")
	flag.Parse()
	if err := build(*root, *out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func selected(root string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(root, "docs/site.json")) //nolint:gosec // The caller explicitly selects the repository root.
	if err != nil {
		return nil, err
	}
	var manifest struct {
		Sources []string `json:"sources"`
	}
	if err := json.Unmarshal(b, &manifest); err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, source := range manifest.Sources {
		if !strings.HasPrefix(source, "docs/") || !fs.ValidPath(source) {
			return nil, fmt.Errorf("invalid source %q", source)
		}
		err := fs.WalkDir(os.DirFS(root), source, func(name string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("symlink source refused: %s", name)
			}
			if !d.IsDir() && strings.HasSuffix(name, ".md") {
				set[name] = true
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	slices.Sort(names)
	if len(names) == 0 {
		return nil, errors.New("docs manifest selected no Markdown")
	}
	return names, nil
}

func destination(source, target string, published map[string]bool) string {
	u, err := url.Parse(target)
	if err != nil || u.IsAbs() || u.Host != "" || u.Path == "" {
		return target
	}
	resolved := path.Clean(path.Join(path.Dir(source), u.Path))
	if strings.HasPrefix(resolved, "../") || path.IsAbs(u.Path) {
		return target
	}
	if published[resolved] {
		u.Path = strings.TrimSuffix(u.Path, ".md") + ".html"
		return u.String()
	}
	// Non-published links retain their repository destination, never a broken
	// local URL. The source files are public, but are not in the search index.
	u.Path = resolved
	return sourceBase + u.String()
}

func render(name string, source []byte, published map[string]bool) (entry, []byte, error) {
	md := goldmark.New(goldmark.WithExtensions(extension.GFM), goldmark.WithParserOptions(parser.WithAutoHeadingID()))
	doc := md.Parser().Parse(gmtext.NewReader(source))
	title := strings.TrimSuffix(path.Base(name), ".md")
	var text strings.Builder
	err := ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch n := n.(type) {
		case *ast.Heading:
			if n.Level == 1 {
				title = headingText(n, source)
			}
		case *ast.Link:
			n.Destination = []byte(destination(name, string(n.Destination), published))
		case *ast.Image:
			target := destination(name, string(n.Destination), nil)
			n.Destination = []byte(strings.Replace(target, sourceBase, imageBase, 1))
		case *ast.FencedCodeBlock, *ast.CodeBlock:
			for i := range n.Lines().Len() {
				line := n.Lines().At(i)
				text.Write(line.Value(source))
				text.WriteByte(' ')
			}
		case *ast.Text:
			text.Write(n.Segment.Value(source))
			text.WriteByte(' ')
		case *ast.String:
			text.Write(n.Value)
			text.WriteByte(' ')
		}
		return ast.WalkContinue, nil
	})
	if err != nil {
		return entry{}, nil, err
	}
	var html bytes.Buffer
	if err := md.Renderer().Render(&html, source, doc); err != nil {
		return entry{}, nil, err
	}
	return entry{Title: title, URL: strings.TrimSuffix(name, ".md") + ".html", Text: strings.Join(strings.Fields(text.String()), " ")}, html.Bytes(), nil
}

func headingText(node ast.Node, source []byte) string {
	var text strings.Builder
	_ = ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if entering {
			switch n := n.(type) {
			case *ast.Text:
				text.Write(n.Segment.Value(source))
			case *ast.String:
				text.Write(n.Value)
			}
		}
		return ast.WalkContinue, nil
	})
	return text.String()
}

func build(root, out string) error {
	names, err := selected(root)
	if err != nil {
		return err
	}
	tmpl, err := template.ParseFS(assets, "assets/page.html")
	if err != nil {
		return err
	}
	published := map[string]bool{}
	for _, name := range names {
		published[name] = true
	}
	pages := make([]entry, 0, len(names))
	bodies := make([][]byte, 0, len(names))
	for _, name := range names {
		source, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name))) //nolint:gosec // selected validates the public manifest paths and rejects symlinks.
		if err != nil {
			return err
		}
		item, body, err := render(name, source, published)
		if err != nil {
			return err
		}
		pages, bodies = append(pages, item), append(bodies, body)
	}
	// Refuse stale output and never recursively remove a caller's directory.
	if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
		return err
	}
	if err := os.Mkdir(out, 0o750); err != nil {
		return fmt.Errorf("output must be a new directory: %w", err)
	}
	write := func(name string, b []byte) error {
		name = filepath.Join(out, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(name), 0o750); err != nil {
			return err
		}
		return os.WriteFile(name, b, 0o600)
	}
	for _, name := range []string{"site.css", "search.js", "_headers"} {
		b, err := assets.ReadFile("assets/" + name)
		if err != nil {
			return err
		}
		if err := write(name, b); err != nil {
			return err
		}
	}
	b, err := json.Marshal(pages)
	if err != nil {
		return err
	}
	if err := write("search.json", b); err != nil {
		return err
	}
	for i, item := range pages {
		var result bytes.Buffer
		prefix := strings.Repeat("../", strings.Count(item.URL, "/"))
		if err := tmpl.Execute(&result, page{Title: item.Title, Source: sourceBase + names[i], Prefix: prefix, Body: template.HTML(bodies[i]), Pages: pages}); err != nil { //nolint:gosec // Safe renderer, raw HTML and dangerous URLs disabled.
			return err
		}
		if err := write(item.URL, result.Bytes()); err != nil {
			return err
		}
	}
	var index bytes.Buffer
	if err := tmpl.Execute(&index, page{Title: "PantherClaw documentation", Body: "<h1>PantherClaw documentation</h1><p>Start with the quickstart, then use the runbooks to install and operate PantherClaw. Search runs in your browser.</p>", Pages: pages}); err != nil {
		return err
	}
	if err := write("index.html", index.Bytes()); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stdout, "docs: built %d pages in %s\n", len(pages), out)
	return nil
}
