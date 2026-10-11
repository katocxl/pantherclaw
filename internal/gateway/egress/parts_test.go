// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package egress

import (
	"encoding/json/v2"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
)

// TestHR073_TargetPartsAreSingleSegments: target.id.<group> sends one
// named group of the target id pattern as one path segment (G0 M8); an id
// that does not match the pattern builds nothing.
func TestHR073_TargetPartsAreSingleSegments(t *testing.T) {
	d := &defs.Definition{
		Operation: "github.pull_request.merge",
		Target: defs.TargetSpec{
			Type:      "github.pull_request",
			IDPattern: `^(?P<owner>[a-z0-9][a-z0-9-]{0,38})/(?P<repo>[a-z0-9._-]{1,100})#(?P<number>[1-9][0-9]{0,9})$`,
		},
		Params: map[string]defs.ParamSpec{"sha": {Type: defs.TypeIdentifier, Material: true, Required: true}},
		Dispatch: &defs.Dispatch{HTTP: &defs.HTTPDispatch{
			Method: "PUT", Path: "/repos/{target.id.owner}/{target.id.repo}/pulls/{target.id.number}/merge",
			Body: map[string]string{"sha": "params.sha"},
		}},
	}
	a := actionir.ActionIR{
		Target: actionir.Target{Type: "github.pull_request", ID: "acme/pay.ments#7"},
		Params: []byte(`{"sha":"0123456789abcdef0123456789abcdef01234567"}`),
	}
	r, err := Build("https://api.github.example.test", d, a, txn)
	if err != nil || r.URL.String() != "https://api.github.example.test/repos/acme/pay.ments/pulls/7/merge" ||
		string(r.Body) != `{"sha":"0123456789abcdef0123456789abcdef01234567"}` {
		t.Fatalf("built %v %s %v", r.URL, r.Body, err)
	}
	for _, id := range []string{"acme/../x#7", "acme/payments#7/../../x", "Acme/payments#7", "acme/payments", "acme/x/y#7"} {
		bad := a
		bad.Target.ID = id
		if r, err := Build("https://api.github.example.test", d, bad, txn); !errors.Is(err, ErrBuild) {
			t.Errorf("target %q: %v %v", id, r.URL, err)
		}
	}
}

// TestHR073_RestPathsAreCheckedSegments: a {params.x*} reference sends
// each "/"-separated part of the value as one escaped segment; an empty or
// dot part, or one holding a separator or escape, builds nothing.
func TestHR073_RestPathsAreCheckedSegments(t *testing.T) {
	d := &defs.Definition{
		Operation: "github.contents.read",
		Target:    defs.TargetSpec{Type: "github.repository", IDPattern: `^(?P<owner>[a-z]+)/(?P<repo>[a-z]+)$`},
		Params:    map[string]defs.ParamSpec{"path": {Type: defs.TypeIdentifier, Material: true, Required: true}},
		Dispatch: &defs.Dispatch{HTTP: &defs.HTTPDispatch{
			Method: "GET", Path: "/repos/{target.id.owner}/{target.id.repo}/contents/{params.path*}",
		}},
	}
	a := actionir.ActionIR{Target: actionir.Target{Type: "github.repository", ID: "acme/payments"}, Params: []byte(`{"path":"src/a\"b/main.go"}`)}
	r, err := Build("https://api.github.example.test", d, a, txn)
	if err != nil || r.URL.EscapedPath() != "/repos/acme/payments/contents/src/a%22b/main.go" {
		t.Fatalf("built %v %v", r.URL, err)
	}
	for _, path := range []string{"src//x", "../x", "src/./x", "/x", "x/", `a\b`, "a%2Fb", "a?b", "a#b"} {
		bad := a
		bad.Params, _ = json.Marshal(map[string]string{"path": path})
		if r, err := Build("https://api.github.example.test", d, bad, txn); !errors.Is(err, ErrBuild) {
			t.Errorf("path %q: %v %v", path, r.URL, err)
		}
	}
}
