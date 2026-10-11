// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package egress

import (
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
)

// mockPackage loads the reviewed mock payments package, whose dispatch
// templates the fuzzers build from.
func mockPackage(tb testing.TB) *defs.Package {
	tb.Helper()
	raw, err := os.ReadFile("../../../packages/mock-payments/package.yaml")
	if err != nil {
		tb.Fatal(err)
	}
	p, err := manifest.Decode(raw)
	if err != nil {
		tb.Fatal(err)
	}
	return p
}

// FuzzOutboundURL (G0 M6, HR-073, HR-075): no connection base URL or
// target id panics the template substitution, and a request that is built
// goes to the connection's own scheme and host, under its base path, to
// exactly the template's segments with the id as one escaped segment that
// reads back as the id, with no query, fragment or userinfo; an id that
// would change the path is refused.
func FuzzOutboundURL(f *testing.F) {
	get, ok := mockPackage(f).Definition("payments.refund.get")
	if !ok {
		f.Fatal("payments.refund.get is not in the mock package")
	}
	for _, seed := range [][2]string{
		{"https://payments.example.test", "re_1"},
		{"https://payments.example.test/api/", "re_0192-ab"},
		{"http://127.0.0.1:9090", "re_a/../b"},
		{"https://payments.example.test", "re_a%2fb"},
		{"https://payments.example.test/a%2Fb/", "re 1;x=y"},
		{"https://[::1]:8443/", ".."},
		{"https://user@payments.example.test", "re_1"},
		{"https://payments.example.test/?x=1", "re_1#frag"},
		{"https://payments.example.test", "re_1\r\nHost: evil.example"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, baseURL, id string) {
		a := actionir.ActionIR{Operation: get.Operation, Target: actionir.Target{Type: "payments.refund", ID: id}, Params: []byte(`{}`)}
		r, err := Build(baseURL, get, a, txn)
		if err != nil {
			if !errors.Is(err, ErrBuild) {
				t.Fatalf("an error outside ErrBuild: %v", err)
			}
			return
		}
		base, err := url.Parse(baseURL)
		if err != nil {
			t.Fatalf("built from a base URL that does not parse: %v", err)
		}
		if id == "" || id == "." || id == ".." || strings.ContainsAny(id, unsafe) {
			t.Fatalf("built %s from the target id %q", r.URL, id)
		}
		sent, err := url.Parse(r.URL.String()) // what the client puts on the wire
		if err != nil {
			t.Fatalf("the built URL %q does not parse: %v", r.URL, err)
		}
		for _, u := range []*url.URL{r.URL, sent} {
			want := strings.TrimSuffix(base.EscapedPath(), "/") + "/v1/refunds/" + url.PathEscape(id)
			if u.Scheme != base.Scheme || u.Host != base.Host || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
				u.EscapedPath() != want {
				t.Fatalf("base %q and id %q built %s (path %q, want %q)", baseURL, id, u, u.EscapedPath(), want)
			}
			segs := strings.Split(u.EscapedPath(), "/")
			if last, err := url.PathUnescape(segs[len(segs)-1]); err != nil || last != id {
				t.Fatalf("the id %q reads back as %q (%v)", id, last, err)
			}
		}
		if r.Method != get.Dispatch.HTTP.Method || r.Body != nil {
			t.Fatalf("built %s %v with a body", r.Method, r.URL)
		}
	})
}
