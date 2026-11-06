// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapping

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	pcbrowser "github.com/katocxl/pantherclaw/packages/pc-browser"
	pccomputer "github.com/katocxl/pantherclaw/packages/pc-computer"
)

// TestHR124_PcBrowserMappingGolden pins the ActionIR the pc.browser and
// pc.computer hook mappings produce: the target is the URL's host, URLs are
// in their one spelling, and the query size is a param (G0 M33 D974).
func TestHR124_PcBrowserMappingGolden(t *testing.T) {
	b, c := mapperFor(t, pcbrowser.Package), mapperFor(t, pccomputer.Package)
	ctx := context.Background()
	var out bytes.Buffer
	for _, in := range []struct {
		m          *Mapper
		tool, args string
	}{
		{b, "browser_navigate", `{"url":"HTTPS://Shop.Example.com:443/cart?item=1#top","user_agent":"Mozilla/5.0","accept_language":"en-US","call":"c1"}`},
		{b, "browser_submit", `{"url":"https://shop.example.com/checkout","page_url":"https://shop.example.com/cart","method":"post","fields":["email","qty"],"secret_fields":false,"call":"c2"}`},
		{b, "browser_download", `{"url":"https://files.example.com/a.pdf","page_url":"https://shop.example.com/","filename":"a.pdf","mime":"application/pdf","bytes":1024,"call":"c3"}`},
		{b, "browser_download", `{"url":"https://files.example.com/b.zip","filename":"b.zip","bytes":-1,"call":"c4"}`},
		{b, "browser_click", `{"page_url":"https://admin.example.com/users","selector":"button.delete","label":"Delete user","call":"c5"}`},
		{b, "browser_takeover", `{"page_url":"https://bank.example.com/login","minutes":10,"call":"c6"}`},
		{c, "computer", `{"kind":"click","button":"left","x":10,"y":20,"call":"toolu_7"}`},
		{c, "computer", `{"kind":"type","text":"hello","call":"toolu_8"}`},
	} {
		p, err := in.m.Hook(ctx, tc, in.tool, []byte(in.args))
		if err != nil {
			t.Fatalf("%s %s: %v", in.tool, in.args, err)
		}
		fmt.Fprintf(&out, "hook %s %s\n%s\n", in.tool, p.HashHex(), p.Canonical)
	}
	path := filepath.Join("testdata", "pc-browser.actionir")
	if *update {
		if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update to create it)", err)
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("mapping output changed; a mapping change must be deliberate (HR-124).\n got:\n%s\nwant:\n%s", out.Bytes(), want)
	}
}

// TestHR748_BrowserMappingsNormalizeURLs: two spellings of one address are
// one action whose target is the host and whose url is the normalized
// spelling; the download's unknown size (-1) is omitted.
func TestHR748_BrowserMappingsNormalizeURLs(t *testing.T) {
	m := mapperFor(t, pcbrowser.Package)
	ctx := context.Background()
	a, err := m.Hook(ctx, tc, "browser_navigate", []byte(`{"url":"HTTPS://Example.COM:443/a?b=1#frag","call":"c1"}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Hook(ctx, tc, "browser_navigate", []byte(`{"url":"https://example.com/a?b=1","call":"c1"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Canonical, b.Canonical) || a.Action.Target.ID != "example.com" ||
		!strings.Contains(string(a.Action.Params), `"url":"https://example.com/a?b=1"`) ||
		!strings.Contains(string(a.Action.Params), `"query_bytes":"3"`) || a.Action.DedupeKey == "" {
		t.Fatalf("not one action:\n%s\n%s", a.Canonical, b.Canonical)
	}
	d, err := m.Hook(ctx, tc, "browser_download", []byte(`{"url":"https://example.com/f","bytes":-1,"call":"c2"}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(d.Action.Params), `"bytes"`) {
		t.Fatalf("an unknown size is a param: %s", d.Action.Params)
	}
}

// TestHR748_AnInvalidURLFailsTheMapping: a url that has no spelling
// (relative, another scheme, userinfo, non-ASCII, too long) leaves the
// required value empty and fails the mapping (the hook face's
// invalid_input); so does a page_url that is not one.
func TestHR748_AnInvalidURLFailsTheMapping(t *testing.T) {
	m := mapperFor(t, pcbrowser.Package)
	ctx := context.Background()
	for name, in := range map[string]struct{ tool, args string }{
		"relative":       {"browser_navigate", `{"url":"/cart","call":"c1"}`},
		"javascript":     {"browser_navigate", `{"url":"javascript:alert(1)","call":"c1"}`},
		"ftp":            {"browser_navigate", `{"url":"ftp://example.com/","call":"c1"}`},
		"userinfo":       {"browser_navigate", `{"url":"https://admin:pw@example.com/","call":"c1"}`},
		"non-ascii":      {"browser_navigate", `{"url":"https://exämple.com/","call":"c1"}`},
		"too long":       {"browser_navigate", `{"url":"https://example.com/` + strings.Repeat("a", 2100) + `","call":"c1"}`},
		"empty":          {"browser_navigate", `{"url":"","call":"c1"}`},
		"bad page_url":   {"browser_submit", `{"url":"https://example.com/f","page_url":"nope","secret_fields":false,"call":"c1"}`},
		"bad click page": {"browser_click", `{"page_url":"file:///etc/passwd","selector":"a","call":"c1"}`},
		"no call":        {"browser_navigate", `{"url":"https://example.com/"}`},
		"long minutes":   {"browser_takeover", `{"page_url":"https://example.com/","minutes":11,"call":"c1"}`},
	} {
		if _, err := m.Hook(ctx, tc, in.tool, []byte(in.args)); !errors.Is(err, actionir.ErrAmbiguous) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
