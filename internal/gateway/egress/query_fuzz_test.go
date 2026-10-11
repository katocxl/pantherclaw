// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package egress

import (
	"encoding/json/v2"
	"errors"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// FuzzQueryTemplate (G0 M7 design decision 5, HR-073): no charge id,
// page cursor or start time panics dispatch.http.query, and a built
// listing's query is exactly the template's names, each once, carrying
// the action's own values (an absent optional one left out), in the
// gateway's canonical encoding; the path stays the template's, and a
// value with a control character is refused.
func FuzzQueryTemplate(f *testing.F) {
	p := mockPackage(f)
	list, ok1 := p.Definition("payments.refund.list")
	recent, ok2 := p.Definition("payments.refund.recent")
	if !ok1 || !ok2 {
		f.Fatal("the listing definitions are not in the mock package")
	}
	f.Add(false, "ch_1", "", "")
	f.Add(false, "ch_1", "re_0192-ab", "")
	f.Add(false, "ch_1&charge=ch_2", "re_1", "")
	f.Add(false, "ch_1\r\nX: y", "", "")
	f.Add(false, "ch_1 #?/%", "re_x&y", "")
	f.Add(true, "01920000-0000-7000-8000-000000000007", "", "1760097600")
	f.Add(true, "01920000-0000-7000-8000-000000000007", "re_1", "-1")
	f.Add(true, "x", "", "1e3")
	f.Fuzz(func(t *testing.T, targetLog bool, target, after, since string) {
		d, typ := list, "payments.charge"
		params := map[string]string{}
		if after != "" {
			params["starting_after"] = after
		}
		if targetLog {
			d, typ = recent, "pc.connection"
			params["created_gte"] = since
		}
		raw, err := json.Marshal(params)
		if err != nil {
			return // invalid UTF-8
		}
		a := actionir.ActionIR{Operation: d.Operation, Target: actionir.Target{Type: typ, ID: target}, Params: raw}
		r, err := Build("https://payments.example.test", d, a, txn)
		if err != nil {
			if !errors.Is(err, ErrBuild) {
				t.Fatalf("an error outside ErrBuild: %v", err)
			}
			return
		}
		if r.URL.Scheme != "https" || r.URL.Host != "payments.example.test" || r.URL.EscapedPath() != "/v1/refunds" ||
			r.URL.Fragment != "" || r.Body != nil {
			t.Fatalf("built %s with a body of %d bytes", r.URL, len(r.Body))
		}
		q, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil || q.Encode() != r.URL.RawQuery {
			t.Fatalf("the query %q is not in its canonical encoding (%v)", r.URL.RawQuery, err)
		}
		vals, err := d.DecodeParams(raw)
		if err != nil {
			t.Fatalf("built from params that do not decode: %v", err)
		}
		want := url.Values{}
		if targetLog {
			want.Set("created_gte", strconv.FormatInt(vals["created_gte"].Int, 10))
		} else {
			want.Set("charge", target)
		}
		if after != "" {
			want.Set("starting_after", after)
		}
		if !maps.EqualFunc(q, want, slices.Equal[[]string]) {
			t.Fatalf("target %q, after %q, since %q built the query %v, want %v", target, after, since, q, want)
		}
		for _, vs := range q {
			if strings.ContainsFunc(vs[0], func(c rune) bool { return c < 0x20 || c == 0x7f }) {
				t.Fatalf("a control character reached the query: %q", vs[0])
			}
		}
	})
}
