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
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	pcgithub "github.com/katocxl/pantherclaw/packages/pc-github"
)

const (
	headSHA = "0123456789abcdef0123456789abcdef01234567"
	blobSHA = "89abcdef0123456789abcdef0123456789abcdef"
	// parserGo is "package parser\n", base64-encoded as the contents API
	// takes it.
	parserGo = "cGFja2FnZSBwYXJzZXIK"
)

// githubCall is one effect asked for through the GitHub MCP server's tool
// and through the REST route it calls.
type githubCall struct {
	tool, args                string
	method, path, query, body string
}

var githubCalls = []githubCall{
	{
		"get_file_contents", `{"owner":"acme","repo":"payments","path":"src/parser/main.go","ref":"main"}`,
		"GET", "/repos/acme/payments/contents/src/parser/main.go", "ref=main", "",
	},
	{"pull_request_read", `{"method":"get","owner":"acme","repo":"payments","pullNumber":7}`, "GET", "/repos/acme/payments/pulls/7", "", ""},
	{
		"create_branch", `{"owner":"acme","repo":".github","branch":"fix/cve-2026-1234","sha":"` + headSHA + `"}`,
		"POST", "/repos/acme/.github/git/refs", "", `{"ref":"refs/heads/fix/cve-2026-1234","sha":"` + headSHA + `"}`,
	},
	{
		"create_or_update_file",
		`{"owner":"acme","repo":"payments","path":"src/parser.go","content":"` + parserGo + `","message":"Fix the parser\n","branch":"fix/cve-2026-1234","sha":"` + blobSHA + `"}`,
		"PUT", "/repos/acme/payments/contents/src/parser.go", "",
		`{"content":"` + parserGo + `","message":"Fix the parser\n","branch":"fix/cve-2026-1234","sha":"` + blobSHA + `"}`,
	},
	{
		"create_pull_request", `{"owner":"acme","repo":"payments","title":"Fix CVE-2026-1234","body":"Bumps the parser.\n","head":"fix/cve-2026-1234","base":"main","draft":false}`,
		"POST", "/repos/acme/payments/pulls", "", `{"title":"Fix CVE-2026-1234","body":"Bumps the parser.\n","head":"fix/cve-2026-1234","base":"main","draft":false}`,
	},
	{
		"merge_pull_request", `{"owner":"acme","repo":"payments","pullNumber":7,"expectedHeadSha":"` + headSHA + `","merge_method":"squash"}`,
		"PUT", "/repos/acme/payments/pulls/7/merge", "", `{"sha":"` + headSHA + `","merge_method":"squash"}`,
	},
	{
		"update_repository", `{"owner":"acme","repo":"payments","default_branch":"main","delete_branch_on_merge":true}`,
		"PATCH", "/repos/acme/payments", "", `{"default_branch":"main","delete_branch_on_merge":true}`,
	},
}

func githubMapper(t testing.TB) *Mapper {
	t.Helper()
	return mapperFor(t, pcgithub.Package)
}

// TestHR124_GitHubMappingGolden pins the ActionIR the reviewed mappings of
// pc.github produce for fixed calls on both channels.
func TestHR124_GitHubMappingGolden(t *testing.T) {
	m := githubMapper(t)
	ctx := context.Background()
	var out bytes.Buffer
	for _, c := range githubCalls {
		a, err := m.MCP(ctx, tc, c.tool, []byte(c.args))
		if err != nil {
			t.Fatalf("mcp %s: %v", c.tool, err)
		}
		b, err := m.HTTP(ctx, tc, c.method, c.path, c.query, []byte(c.body))
		if err != nil {
			t.Fatalf("http %s %s: %v", c.method, c.path, err)
		}
		fmt.Fprintf(&out, "mcp %s %s\n%s\nhttp %s %s %s\n%s\n", c.tool, a.HashHex(), a.Canonical, c.method, c.path, b.HashHex(), b.Canonical)
	}
	path := filepath.Join("testdata", "pc-github.actionir")
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

// TestF099_GitHubMCPAndRESTReachTheSameAction: for every operation, the
// GitHub MCP server's tool and a direct call to the REST API produce the
// same operation, target, params, dedupe key, route and pinned definition,
// so they get the same decision; only the channel differs.
func TestF099_GitHubMCPAndRESTReachTheSameAction(t *testing.T) {
	m := githubMapper(t)
	ctx := context.Background()
	for _, c := range githubCalls {
		a, err := m.MCP(ctx, tc, c.tool, []byte(c.args))
		if err != nil {
			t.Fatalf("mcp %s: %v", c.tool, err)
		}
		b, err := m.HTTP(ctx, tc, c.method, c.path, c.query, []byte(c.body))
		if err != nil {
			t.Fatalf("http %s %s: %v", c.method, c.path, err)
		}
		x, y := a.Action, b.Action
		if x.Operation != y.Operation || x.Target != y.Target || !bytes.Equal(x.Params, y.Params) || x.DedupeKey != y.DedupeKey ||
			x.Route != y.Route || x.Definition != y.Definition || x.Channel != "mcp" || y.Channel != "http" {
			t.Errorf("%s: channels disagree:\n%s\n%s", c.tool, a.Canonical, b.Canonical)
		}
	}
}

// TestHR205_AGitHubMergeNeedsAnExactHead: a merge without the head SHA, with
// a shortened one, or with fields the mapping does not review is refused,
// and so is any identity that is not the one lowercase spelling (HR-102,
// HR-103).
func TestHR205_AGitHubMergeNeedsAnExactHead(t *testing.T) {
	m := githubMapper(t)
	ctx := context.Background()
	for name, args := range map[string]string{
		"no head":           `{"owner":"acme","repo":"payments","pullNumber":7}`,
		"short head":        `{"owner":"acme","repo":"payments","pullNumber":7,"expectedHeadSha":"0123456"}`,
		"uppercase head":    `{"owner":"acme","repo":"payments","pullNumber":7,"expectedHeadSha":"0123456789ABCDEF0123456789abcdef01234567"}`,
		"commit title":      `{"owner":"acme","repo":"payments","pullNumber":7,"expectedHeadSha":"` + headSHA + `","commit_title":"x"}`,
		"uppercase owner":   `{"owner":"Acme","repo":"payments","pullNumber":7,"expectedHeadSha":"` + headSHA + `"}`,
		"dot repository":    `{"owner":"acme","repo":"..","pullNumber":7,"expectedHeadSha":"` + headSHA + `"}`,
		"padded number":     `{"owner":"acme","repo":"payments","pullNumber":"07","expectedHeadSha":"` + headSHA + `"}`,
		"zero number":       `{"owner":"acme","repo":"payments","pullNumber":0,"expectedHeadSha":"` + headSHA + `"}`,
		"unknown method":    `{"owner":"acme","repo":"payments","pullNumber":7,"expectedHeadSha":"` + headSHA + `","merge_method":"fast-forward"}`,
		"repository in id":  `{"owner":"acme/payments","repo":"x","pullNumber":7,"expectedHeadSha":"` + headSHA + `"}`,
		"number not number": `{"owner":"acme","repo":"payments","pullNumber":[7],"expectedHeadSha":"` + headSHA + `"}`,
	} {
		if _, err := m.MCP(ctx, tc, "merge_pull_request", []byte(args)); !errors.Is(err, actionir.ErrAmbiguous) {
			t.Errorf("mcp %s: %v", name, err)
		}
	}
	for name, c := range map[string]struct{ path, body string }{
		"no sha":        {"/repos/acme/payments/pulls/7/merge", `{"merge_method":"merge"}`},
		"padded number": {"/repos/acme/payments/pulls/07/merge", `{"sha":"` + headSHA + `"}`},
		"uppercase":     {"/repos/ACME/payments/pulls/7/merge", `{"sha":"` + headSHA + `"}`},
		"commit body":   {"/repos/acme/payments/pulls/7/merge", `{"sha":"` + headSHA + `","commit_message":"x"}`},
	} {
		if _, err := m.HTTP(ctx, tc, "PUT", c.path, "", []byte(c.body)); !errors.Is(err, actionir.ErrAmbiguous) {
			t.Errorf("http %s: %v", name, err)
		}
	}
}

// TestGitHubContentsWritesNeverTouchGitHubDirectory: a write under .github/
// is refused on both channels (CANNOT_AUTHORIZE), so an agent cannot
// rewrite the workflows its merges are judged by; reads there are fine.
func TestGitHubContentsWritesNeverTouchGitHubDirectory(t *testing.T) {
	m := githubMapper(t)
	ctx := context.Background()
	body := `{"content":"` + parserGo + `","message":"x","branch":"main"}`
	for _, path := range []string{".github/workflows/deploy.yml", ".github/actions/x/action.yml", ".github", ".github/CODEOWNERS"} {
		args := `{"owner":"acme","repo":"payments","path":"` + path + `","content":"` + parserGo + `","message":"x","branch":"main"}`
		if _, err := m.MCP(ctx, tc, "create_or_update_file", []byte(args)); !errors.Is(err, actionir.ErrAmbiguous) {
			t.Errorf("mcp %s: %v", path, err)
		}
		if _, err := m.HTTP(ctx, tc, "PUT", "/repos/acme/payments/contents/"+path, "", []byte(body)); !errors.Is(err, actionir.ErrAmbiguous) {
			t.Errorf("http %s: %v", path, err)
		}
	}
	for _, path := range []string{".githubx/a", "docs/.github/x", ".gitignore"} {
		args := `{"owner":"acme","repo":"payments","path":"` + path + `","content":"` + parserGo + `","message":"x","branch":"main"}`
		if _, err := m.MCP(ctx, tc, "create_or_update_file", []byte(args)); err != nil {
			t.Errorf("mcp %s: %v", path, err)
		}
	}
	if _, err := m.HTTP(ctx, tc, "GET", "/repos/acme/payments/contents/.github/workflows/deploy.yml", "", nil); err != nil {
		t.Fatalf("reading a workflow: %v", err)
	}
	for _, path := range []string{"src/../.github/x", "src//x", "src%2Fx"} {
		if _, err := m.HTTP(ctx, tc, "PUT", "/repos/acme/payments/contents/"+path, "", []byte(body)); err == nil {
			t.Errorf("http %s mapped", path)
		}
	}
}
