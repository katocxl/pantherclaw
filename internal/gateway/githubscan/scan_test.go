// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package githubscan

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/gateway/githubfacts"
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
	// The attributes are the ones coverage reads (N20): repo, path, and for a
	// workflow agent_actions, permissions, writes and deploys.
	wf := byKind["github_workflow"]
	if len(wf) != 1 || wf[0].Attributes["agent_actions"] != "anthropics/claude-code-action" || wf[0].Attributes["repo"] != "acme/payments" ||
		wf[0].Attributes["permissions"] != "contents:write,pull-requests:write" || wf[0].Attributes["path"] != ".github/workflows/claude.yml" ||
		wf[0].Attributes["writes"] != "true" || wf[0].Attributes["deploys"] != "false" || wf[0].Attributes["permissions_default"] != "" {
		t.Fatalf("workflows %+v", wf)
	}
	mcp := byKind["github_mcp_config"]
	if len(mcp) != 1 || mcp[0].Attributes["servers"] != "github,remote" || mcp[0].Attributes["commands"] != "npx" ||
		mcp[0].Attributes["transports"] != "stdio,remote" || mcp[0].Attributes["env"] != "GITHUB_PERSONAL_ACCESS_TOKEN" ||
		mcp[0].Attributes["headers"] != "Authorization" || mcp[0].Attributes["repo"] != "acme/payments" || mcp[0].Attributes["path"] != ".mcp.json" {
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
	if r.Counts["repositories"] != 1 || !strings.Contains(r.NotScanned["repositories"], "could not be read") ||
		r.NotScanned["workflows"] == "" || r.NotScanned["mcp_configs"] == "" || len(r.Scanned) != 0 {
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

// TestHR209_FilesTheScanSkipsAreNotScanned: workflow files past the limit,
// one the parser refuses and an MCP configuration with comments are not
// read, and say so: their source is reported not scanned with why, never
// scanned with nothing found. A list too long for one attribute says it
// was cut; a workflow without permissions runs with the repository's
// defaults, which may write; one that names an environment deploys.
func TestHR209_FilesTheScanSkipsAreNotScanned(t *testing.T) {
	sim, get := newWorld(t)
	files := map[string]string{
		".github/workflows/anchors.yml": "on: &x push\njobs: {}\n",
		".vscode/mcp.json":              "{\n  // a comment\n  \"servers\": {\"x\": {\"command\": \"node\"}}\n}\n",
		".github/workflows/deploy.yml":  "on: push\njobs:\n  d:\n    environment: production\n    steps: [{uses: openai/codex-action@v1}]\n",
	}
	var perms strings.Builder
	for i := range 40 {
		fmt.Fprintf(&perms, "      scope_%02d: write\n", i)
	}
	files[".github/workflows/many.yml"] = "on: push\njobs:\n  a:\n    permissions:\n" + perms.String() + "    steps: [{uses: anthropics/claude-code-action@v1}]\n"
	for i := range githubfacts.MaxWorkflowFiles {
		files[fmt.Sprintf(".github/workflows/w%02d.yml", i)] = "on: push\njobs: {t: {runs-on: x}}\n"
	}
	sim.Push("acme/payments", "main", files)
	r := ScanRepositories(context.Background(), get, []Repository{{FullName: "acme/payments", DefaultBranch: "main"}}, time.Now().Add(time.Minute))
	if !strings.Contains(r.NotScanned["workflows"], "over the 20-file limit") || slices.Contains(r.Scanned, "workflows") {
		t.Fatalf("workflows past the limit: %+v %v", r.NotScanned, r.Scanned)
	}
	if !strings.Contains(r.NotScanned["mcp_configs"], "not strict JSON") || slices.Contains(r.Scanned, "mcp_configs") {
		t.Fatalf("an MCP configuration with comments: %+v %v", r.NotScanned, r.Scanned)
	}
	read := map[string]Finding{}
	for _, f := range r.Findings {
		read[f.Attributes["path"]] = f
	}
	// Files are read in name order, so the limit leaves out the w*.yml at
	// the end, after anchors, claude, deploy and many.
	if !strings.Contains(r.NotScanned["workflows"], "refused by the parser") {
		t.Fatalf("a workflow the parser refuses: %+v", r.NotScanned)
	}
	if d := read[".github/workflows/deploy.yml"].Attributes; d["deploys"] != "true" || d["environments"] != "production" ||
		d["permissions_default"] != "true" || d["writes"] != "true" {
		t.Fatalf("a deploying workflow on the default permissions: %v", d)
	}
	if m := read[".github/workflows/many.yml"].Attributes; m["permissions_incomplete"] != "true" || len(m["permissions"]) > 256 {
		t.Fatalf("a permission list too long: %v", m)
	}
}

// TestHR209_ACommandKeepsOnlyItsProgramName: an MCP server's command keeps
// the base name of the program it runs and nothing else: a leading
// NAME=value assignment is skipped like an argument, so a secret in it is
// never kept (HR-209).
func TestHR209_ACommandKeepsOnlyItsProgramName(t *testing.T) {
	for command, want := range map[string]string{
		"PGPASSWORD=hunter2 psql -h db":             "psql",
		"FOO=a BAR=b /usr/local/bin/node server.js": "node",
		`C:\tools\server.exe --key hunter2`:         "server.exe",
		"API_KEY=hunter2":                           "",
		"$(cat key) run":                            "",
	} {
		raw := []byte(`{"mcpServers": {"s": {"command": ` + strconv.Quote(command) + `}}}`)
		servers, err := ParseMCPConfig(raw)
		if err != nil || len(servers) != 1 || servers[0].Command != want {
			t.Errorf("%q: %+v %v, want %q", command, servers, err, want)
		}
		if strings.Contains(servers[0].Command, "hunter2") {
			t.Fatalf("%q kept a secret", command)
		}
	}
}

// TestHR209_AgentUseTheScanCannotCheckIsReported: the scan recognizes agent
// actions only; a workflow that calls a reusable workflow, a local or
// Docker action, or runs an agent's CLI directly may run an agent it
// cannot see, so it is counted and workflows are reported not scanned
// with why, never as "no agent here". The step's text is never kept.
func TestHR209_AgentUseTheScanCannotCheckIsReported(t *testing.T) {
	sim, get := newWorld(t)
	sim.Push("acme/payments", "main", map[string]string{
		".github/workflows/reuse.yml": "on: push\njobs: {r: {uses: acme/ci/.github/workflows/agent.yml@main}}\n",
		".github/workflows/cli.yml":   "on: push\njobs:\n  a:\n    runs-on: x\n    steps: [{run: 'npx @anthropic-ai/claude-code -p \"fix ` + planted + `\"'}, {uses: ./.github/actions/review}]\n",
	})
	r := ScanRepositories(context.Background(), get, []Repository{{FullName: "acme/payments", DefaultBranch: "main"}}, time.Now().Add(time.Minute))
	why := r.NotScanned["workflows"]
	for _, how := range []string{"a reusable workflow", "an agent CLI run directly", "a local action"} {
		if !strings.Contains(why, "agent use not checked ("+how+")") {
			t.Errorf("%s not reported: %q", how, why)
		}
	}
	if r.Counts["workflows_agent_unchecked"] != 3 || slices.Contains(r.Scanned, "workflows") {
		t.Fatalf("counts %v, scanned %v", r.Counts, r.Scanned)
	}
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), planted) || strings.Contains(string(raw), "fix ") {
		t.Fatal("a run step's text reached the result")
	}
}

// TestHR209_EveryMCPServerEntryIsCounted (G5 review follow-up): a file
// holding both mcpServers and servers gives both, and an entry that is not
// an object the parser understands is kept as unknown, by its name only,
// so no server is missed.
func TestHR209_EveryMCPServerEntryIsCounted(t *testing.T) {
	servers, err := ParseMCPConfig([]byte(`{"mcpServers": {"github": {"command": "npx gh-mcp"}, "odd": ["not", "an", "object"]},
		"servers": {"remote": {"url": "https://mcp.example.test"}, "weird": {"command": 42}}}`))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, s := range servers {
		got[s.Name] = s.Transport
		if s.Transport == "unknown" && (s.Command != "" || len(s.Env) != 0 || len(s.Headers) != 0) {
			t.Errorf("an unknown entry kept more than its name: %+v", s)
		}
	}
	want := map[string]string{"github": "stdio", "odd": "unknown", "remote": "remote", "weird": "unknown"}
	if len(got) != len(want) {
		t.Fatalf("servers %v, want %v", got, want)
	}
	for name, transport := range want {
		if got[name] != transport {
			t.Errorf("%s: %q, want %q", name, got[name], transport)
		}
	}
}

// TestHR209_ATooLargeFileIsNeverFetched (G5 review follow-up): a workflow
// file the listing says is over the limit is skipped without being
// fetched, and reported not scanned; one within it is read.
func TestHR209_ATooLargeFileIsNeverFetched(t *testing.T) {
	sim, get := newWorld(t)
	sim.Push("acme/payments", "main", map[string]string{
		".github/workflows/huge.yml": "on: push\njobs: {t: {runs-on: x}}\n# " + strings.Repeat("x", githubfacts.MaxWorkflowBytes) + "\n",
		".github/workflows/ok.yml":   "on: push\njobs: {t: {runs-on: x}}\n",
	})
	r := ScanRepositories(context.Background(), get, []Repository{{FullName: "acme/payments", DefaultBranch: "main"}}, time.Now().Add(time.Minute))
	if !strings.Contains(r.NotScanned["workflows"], "too large") {
		t.Fatalf("a too large workflow: %+v", r.NotScanned)
	}
	okRead := false
	for _, req := range sim.Requests() {
		if strings.Contains(req.Path, "huge.yml") {
			t.Fatalf("the too large file was fetched: %+v", req)
		}
		okRead = okRead || strings.Contains(req.Path, "ok.yml")
	}
	if !okRead {
		t.Fatal("the workflow within the limit was not read")
	}
}
