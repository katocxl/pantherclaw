// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package egress

import (
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	pcgithub "github.com/katocxl/pantherclaw/packages/pc-github"
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

// TestHR075_GitHubRequestsComeFromTheBoundAction: every pc.github
// operation's dispatch template builds its REST request from the mapped
// action alone, with the target's parts in their own segments.
func TestHR075_GitHubRequestsComeFromTheBoundAction(t *testing.T) {
	p, err := manifest.Decode(pcgithub.Package)
	if err != nil {
		t.Fatal(err)
	}
	m, err := mapping.New(p, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	const sha = "0123456789abcdef0123456789abcdef01234567"
	for _, c := range []struct{ tool, args, method, url, body string }{
		{"get_file_contents", `{"owner":"acme","repo":"payments","path":".mcp.json","ref":"fix/a"}`, "GET", "/repos/acme/payments/contents/.mcp.json?ref=fix%2Fa", ""},
		{"list_branches", `{"owner":"acme","repo":"payments"}`, "GET", "/repos/acme/payments/branches", ""},
		{
			"create_branch", `{"owner":"acme","repo":"payments","branch":"fix/a","sha":"` + sha + `"}`,
			"POST", "/repos/acme/payments/git/refs", `{"ref":"refs/heads/fix/a","sha":"` + sha + `"}`,
		},
		{
			"create_pull_request", `{"owner":"acme","repo":"payments","title":"Fix \"a\"","head":"fix/a","base":"main"}`,
			"POST", "/repos/acme/payments/pulls", `{"base":"main","head":"fix/a","title":"Fix \"a\""}`,
		},
		{
			"merge_pull_request", `{"owner":"acme","repo":"payments","pullNumber":7,"expectedHeadSha":"` + sha + `"}`,
			"PUT", "/repos/acme/payments/pulls/7/merge", `{"sha":"` + sha + `"}`,
		},
		{"update_repository", `{"owner":"acme","repo":"payments","allow_merge_commit":false}`, "PATCH", "/repos/acme/payments", `{"allow_merge_commit":false}`},
	} {
		a := mapped(t, m, c.tool, c.args)
		d, _ := p.Definition(a.Operation)
		r, err := Build("https://api.github.example.test", d, a, txn)
		if err != nil || r.Method != c.method || r.URL.String() != "https://api.github.example.test"+c.url || string(r.Body) != c.body ||
			r.IdempotencyHeader != "" {
			t.Errorf("%s: built %s %v %s %v", c.tool, r.Method, r.URL, r.Body, err)
		}
	}
	// The merge verifier reads the pull request from the target alone.
	get, _ := p.Definition("github.pull_request.get")
	r, err := Build("https://api.github.example.test", get, actionir.ActionIR{
		Target: actionir.Target{Type: "github.pull_request", ID: "acme/payments#7"}, Params: []byte(`{}`),
	}, txn)
	if err != nil || r.URL.Path != "/repos/acme/payments/pulls/7" {
		t.Fatalf("verifier read: %v %v", r.URL, err)
	}
}
