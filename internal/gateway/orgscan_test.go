// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/gateway/githubscan"
	"github.com/katocxl/pantherclaw/internal/sim/github"
)

type scanSubmissions struct {
	mu       sync.Mutex
	scans    []string
	findings []githubscan.Finding
}

func (s *scanSubmissions) submit(_ context.Context, scan string, findings []githubscan.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scans = append(s.scans, scan)
	s.findings = append(s.findings, findings...)
	return nil
}

// runOrgScan gives the gateway one org_scan lease of run and returns what
// it submitted and reported.
func runOrgScan(t *testing.T, h *harness, run string) (*scanSubmissions, dispatch.Observation) {
	t.Helper()
	fv := &fakeVerifications{leases: []dispatch.Lease{{
		Purpose: "org_scan", Connection: connID, Task: "01920000-0000-7000-8000-00000000ab01", Operation: "github.org_scan",
		Request: []byte(`{"run":"` + run + `"}`),
	}}}
	subs := &scanSubmissions{}
	h.gw.verifications, h.gw.submitScan = fv, subs.submit
	h.gw.verifyDue(context.Background())
	if len(fv.reports) != 1 {
		t.Fatalf("%d reports", len(fv.reports))
	}
	return subs, fv.reports[0]
}

// TestHR209_TheGatewayScansTheOrganizationWithReadOnlyTokens: an org_scan
// lease makes the gateway list the installation's repositories and read
// their workflow and MCP configuration files with read-only tokens of its
// own, each revoked; it submits names only, to the lease's scan, and
// reports the summary, with what the App may not read (the organization's
// installations, here) and what it does not read yet (rulesets) as not
// scanned.
func TestHR209_TheGatewayScansTheOrganizationWithReadOnlyTokens(t *testing.T) {
	w := newGitHubWorld(t)
	planted := "ghp_" + strings.Repeat("Y", 36)
	w.sim.Push("acme/payments", "main", map[string]string{
		".github/workflows/claude.yml": "on: [issue_comment]\npermissions: {contents: write}\njobs:\n  c:\n    runs-on: x\n    steps: [{uses: anthropics/claude-code-action@v1, with: {token: " + planted + "}}]\n",
		".mcp.json":                    `{"mcpServers": {"github": {"command": "npx", "env": {"GITHUB_TOKEN": "` + planted + `"}}}}`,
	})
	h := setup(t, withGitHubApp(t, w))
	subs, o := runOrgScan(t, h, "01920000-0000-7000-8000-00000000ab02")
	if !o.Found || o.Complete || o.Fields["/counts/repositories"] != "1" || o.Fields["/counts/agent_workflows"] != "1" ||
		o.Fields["/counts/mcp_servers"] != "1" || o.Fields["/not_scanned/org_installations"] == "" || o.Fields["/not_scanned/rulesets"] == "" {
		t.Fatalf("report %+v", o)
	}
	kinds := []string{}
	for _, f := range subs.findings {
		kinds = append(kinds, f.Kind)
		for k, v := range f.Attributes {
			if strings.Contains(v, planted) || strings.Contains(v, "ghp_") {
				t.Fatalf("%s=%q was submitted", k, v)
			}
		}
	}
	slices.Sort(kinds)
	if !slices.Equal(kinds, []string{"github_mcp_config", "github_workflow"}) || !slices.Equal(subs.scans, []string{"01920000-0000-7000-8000-00000000ab02"}) {
		t.Fatalf("submitted %v to %v", kinds, subs.scans)
	}
	tokens := w.sim.Tokens()
	if len(tokens) < 2 {
		t.Fatalf("%d tokens", len(tokens))
	}
	for _, tok := range tokens {
		for p, level := range tok.Permissions {
			if level != "read" {
				t.Errorf("a scan token with %s:%s", p, level)
			}
		}
		if !tok.Revoked {
			t.Errorf("token %+v not revoked", tok)
		}
	}
	for _, req := range w.sim.Requests() {
		if req.User == "alice" || strings.HasSuffix(req.Path, "/access_tokens") || req.Path == "/installation/token" {
			continue // the test's own setup, and minting and revoking the scan's tokens
		}
		if req.Method != http.MethodGet || req.Write || strings.Contains(req.Path, "README") {
			t.Fatalf("the scan sent %s %s", req.Method, req.Path)
		}
	}
}

// TestHR209_AnAppThatMayReadTheOrganizationListsItsApps: with
// organization_administration:read, the scan also lists the Apps installed
// on the organization, each a github_app finding, and says it read them.
func TestHR209_AnAppThatMayReadTheOrganizationListsItsApps(t *testing.T) {
	w := newGitHubWorld(t)
	w.sim.Install(github.Installation{ID: 7, Account: "acme", Repos: []string{"payments"}, Permissions: map[string]string{
		"contents": "write", "pull_requests": "write", "metadata": "read", "checks": "read", "organization_administration": "read",
	}})
	w.sim.AddOrgApp("acme", github.OrgApp{ID: 99, Slug: "deploy-bot", Permissions: map[string]string{"contents": "write"}, Selection: "all"})
	h := setup(t, withGitHubApp(t, w))
	subs, o := runOrgScan(t, h, "01920000-0000-7000-8000-00000000ab03")
	if o.Fields["/scanned/org_installations"] != "true" || o.Fields["/counts/apps"] != "1" || o.Fields["/not_scanned/org_installations"] != "" {
		t.Fatalf("report %+v", o)
	}
	var app *githubscan.Finding
	for i, f := range subs.findings {
		if f.Kind == "github_app" {
			app = &subs.findings[i]
		}
	}
	if app == nil || app.Attributes["app"] != "deploy-bot" || app.Attributes["permissions"] != "contents:write" || app.Attributes["repository_selection"] != "all" {
		t.Fatalf("apps %+v", subs.findings)
	}
}

// TestT084_APlantedTokenNeverLeavesTheScan (T-084, the scan part): a
// token committed to a repository, in a workflow's inputs, an MCP
// server's env, header, arguments or URL, never reaches what the gateway
// submits, reports or logs.
func TestT084_APlantedTokenNeverLeavesTheScan(t *testing.T) {
	w := newGitHubWorld(t)
	planted := "ghp_" + strings.Repeat("X", 36)
	w.sim.Push("acme/payments", "main", map[string]string{
		".github/workflows/agent.yml": "on: [push]\njobs:\n  a:\n    runs-on: x\n    env: {T: " + planted + "}\n    steps: [{uses: openai/codex-action@v1, with: {key: " + planted + "}}]\n",
		".vscode/mcp.json": `{"servers": {"s": {"command": "/opt/` + planted + `/bin/server --key ` + planted + `", "args": ["` + planted + `"],
			"env": {"K": "` + planted + `"}, "headers": {"Authorization": "Bearer ` + planted + `"}},
			"r": {"url": "https://x.test/?t=` + planted + `"}}}`,
	})
	h := setup(t, withGitHubApp(t, w))
	var logs strings.Builder
	h.gw.log = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	subs, o := runOrgScan(t, h, "01920000-0000-7000-8000-00000000ab04")
	if len(subs.findings) != 3 {
		t.Fatalf("%d findings", len(subs.findings))
	}
	everything := logs.String()
	for _, f := range subs.findings {
		for k, v := range f.Attributes {
			everything += k + "=" + v + "\n"
		}
	}
	for k, v := range o.Fields {
		everything += k + "=" + v + "\n"
	}
	if strings.Contains(everything, planted) || strings.Contains(everything, "XXXXXXXXXXXXXXXX") {
		t.Fatalf("the planted token left the scan:\n%s", everything)
	}
}
