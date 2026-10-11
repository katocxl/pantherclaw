// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package githubscan

import (
	"context"
	"encoding/json/v2"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/sim/github"
)

// planted is a token-shaped value a configuration may hold; it must never
// reach a finding (HR-209).
var planted = "ghp_" + strings.Repeat("Z", 36)

const agentWorkflow = `name: claude
on: [issue_comment]
permissions:
  contents: write
  pull-requests: write
jobs:
  claude:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          prompt: "do not leak ` + "ghp_" + `ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
`

var mcpConfig = `{"mcpServers": {
  "github": {"command": "npx -y @modelcontextprotocol/server-github --token PLANTED", "args": ["--pat", "PLANTED"],
             "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "PLANTED"}},
  "remote": {"url": "https://mcp.example.test/?token=PLANTED", "headers": {"Authorization": "Bearer PLANTED"}}
}}`

func newWorld(t *testing.T) (*github.Server, Getter) {
	t.Helper()
	sim := github.New(slog.New(slog.DiscardHandler))
	sim.CreateRepo("acme/payments", "main", map[string]string{
		"README.md":                    "# p\n",
		".github/workflows/claude.yml": agentWorkflow,
		".github/workflows/ci.yml":     "on: push\njobs: {t: {runs-on: x, steps: [{run: make}]}}\n",
		".mcp.json":                    strings.ReplaceAll(mcpConfig, "PLANTED", planted),
		"src/secrets.env":              "TOKEN=" + planted,
	})
	sim.CreateRepo("acme/web", "main", map[string]string{"README.md": "# w\n"})
	sim.AddToken("ghp_scanner", "scanner", []string{"acme/payments", "acme/web"}, map[string]string{"metadata": "read", "contents": "read"})
	srv := httptest.NewServer(sim.Handler())
	t.Cleanup(srv.Close)
	get := func(ctx context.Context, path string) (egress.Response, error) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
		req.Header.Set("Authorization", "token ghp_scanner")
		res, err := srv.Client().Do(req)
		if err != nil {
			return egress.Response{}, err
		}
		defer res.Body.Close()
		b, err := io.ReadAll(res.Body)
		return egress.Response{Status: res.StatusCode, Body: b}, err
	}
	return sim, get
}

// TestHR209_TheScanReadsNamedFilesAndKeepsNamesOnly: the scan reads each
// repository's workflow files and committed MCP configuration and nothing
// else; it keeps which agent actions a workflow runs and what it may
// write, and which servers a configuration names with which command,
// environment variable and header names. A token planted in an
// environment value, a header, an argument, a URL or a prompt never
// reaches a finding.
func TestHR209_TheScanReadsNamedFilesAndKeepsNamesOnly(t *testing.T) {
	sim, get := newWorld(t)
	repos := []Repository{{FullName: "acme/payments", DefaultBranch: "main"}, {FullName: "acme/web", DefaultBranch: "main"}}
	r := ScanRepositories(context.Background(), get, repos, time.Now().Add(time.Minute))
	if r.Counts["repositories"] != 2 || r.Counts["workflows"] != 2 || r.Counts["agent_workflows"] != 1 || r.Counts["mcp_servers"] != 2 {
		t.Fatalf("counts %v", r.Counts)
	}
	byKind := map[string][]Finding{}
	for _, f := range r.Findings {
		byKind[f.Kind] = append(byKind[f.Kind], f)
		if len(f.Attributes) > 16 {
			t.Errorf("%d attributes", len(f.Attributes))
		}
		for k, v := range f.Attributes {
			if len(v) > 256 || strings.Contains(v, "ghp_") || strings.Contains(v, planted) || strings.Contains(k, "ghp_") {
				t.Errorf("%s=%q", k, v)
			}
		}
	}
	wf := byKind["github_workflow"]
	if len(wf) != 1 || wf[0].Attributes["actions"] != "anthropics/claude-code-action" ||
		wf[0].Attributes["permissions"] != "contents:write,pull-requests:write" || wf[0].Attributes["path"] != ".github/workflows/claude.yml" {
		t.Fatalf("workflows %+v", wf)
	}
	mcp := byKind["github_mcp_config"]
	if len(mcp) != 2 || mcp[0].Attributes["name"] != "github" || mcp[0].Attributes["command"] != "npx" ||
		mcp[0].Attributes["env"] != "GITHUB_PERSONAL_ACCESS_TOKEN" || mcp[1].Attributes["transport"] != "remote" ||
		mcp[1].Attributes["headers"] != "Authorization" {
		t.Fatalf("mcp %+v", mcp)
	}
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), "ghp_") || strings.Contains(string(raw), "PLANTED") {
		t.Fatal("a planted value reached the result")
	}
	// Only the named files were read: never README.md or src/.
	for _, req := range sim.Requests() {
		if strings.Contains(req.Path, "README") || strings.Contains(req.Path, "src/") || strings.Contains(req.Path, "/secrets") {
			t.Fatalf("read %s", req.Path)
		}
		if !slices.Contains([]string{http.MethodGet}, req.Method) {
			t.Fatalf("%s %s", req.Method, req.Path)
		}
	}
	fields := r.Fields()
	if fields["/counts/agent_workflows"] != "1" || fields["/scanned/mcp_configs"] != "true" || len(fields) > 16 {
		t.Fatalf("fields %v", fields)
	}
}

// TestHR209_WhatTheScanCouldNotReadIsNotScanned: past the deadline, the
// repositories left are recorded as not scanned; a repository that cannot
// be read is not counted as having nothing.
func TestHR209_WhatTheScanCouldNotReadIsNotScanned(t *testing.T) {
	_, get := newWorld(t)
	repos := []Repository{{FullName: "acme/payments", DefaultBranch: "main"}, {FullName: "acme/secret", DefaultBranch: "main"}}
	r := ScanRepositories(context.Background(), get, repos, time.Now().Add(time.Minute))
	if r.Counts["repositories"] != 1 || r.NotScanned["contents"] == "" {
		t.Fatalf("an unreadable repository: %+v", r)
	}
	r = ScanRepositories(context.Background(), get, repos, time.Now().Add(-time.Second))
	if r.Counts["repositories"] != 0 || !strings.HasPrefix(r.NotScanned["repositories"], "time limit") || len(r.Findings) != 0 {
		t.Fatalf("past the deadline: %+v", r)
	}
}

// FuzzMCPConfig: whatever a configuration holds, the parser keeps names
// only: nothing longer than a name, and nothing shaped like a credential,
// even where a name was expected (HR-209).
func FuzzMCPConfig(f *testing.F) {
	f.Add([]byte(strings.ReplaceAll(mcpConfig, "PLANTED", planted)))
	f.Add([]byte(`{"servers": {"x": {"command": "/usr/bin/` + planted + ` arg"}}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		servers, err := ParseMCPConfig(raw)
		if err != nil {
			return
		}
		for _, s := range servers {
			for _, v := range append(append([]string{s.Name, s.Command, s.Transport}, s.Env...), s.Headers...) {
				if len(v) > 64 || secretShaped.MatchString(v) {
					t.Fatalf("%q is no name", v)
				}
			}
		}
	})
}
