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
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/gateway/githubscan"
	"github.com/katocxl/pantherclaw/internal/sim/github"
)

type scanSubmissions struct {
	mu       sync.Mutex
	scans    []string
	leases   []string
	findings []githubscan.Finding
	// drop is how many findings the server drops per submission.
	drop int32
}

func (s *scanSubmissions) submit(_ context.Context, scan string, lease []byte, findings []githubscan.Finding) (int32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scans, s.leases = append(s.scans, scan), append(s.leases, string(lease))
	s.findings = append(s.findings, findings...)
	return s.drop, nil
}

// orgScanLease is the org_scan lease of run the tests give the gateway.
func orgScanLease(run string) dispatch.Lease {
	return dispatch.Lease{
		Purpose: "org_scan", Connection: connID, Task: "01920000-0000-7000-8000-00000000ab01", Operation: "github.org_scan",
		Request: []byte(`{"installation":"7","run":"` + run + `"}`), Secret: []byte("the lease's secret"),
	}
}

// runOrgScan gives the gateway one org_scan lease of run and returns what
// it submitted and reported.
func runOrgScan(t *testing.T, h *harness, run string, drop ...int32) (*scanSubmissions, dispatch.Observation) {
	t.Helper()
	fv := &fakeVerifications{leases: []dispatch.Lease{orgScanLease(run)}}
	subs := &scanSubmissions{}
	if len(drop) > 0 {
		subs.drop = drop[0]
	}
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
	if app == nil || app.Attributes["app_slug"] != "deploy-bot" || app.Attributes["permissions"] != "contents:write" ||
		app.Attributes["repository_selection"] != "all" || app.Attributes["connection"] != connID {
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
	if len(subs.findings) != 2 { // the workflow, and the MCP configuration (one finding per file)
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

// TestHR209_FindingsNameTheirConnectionAndGoUnderTheLease: every finding
// names the connection it was scanned through (coverage keys on it, N20),
// each submission carries the lease's secret, and findings the server
// dropped are reported as not scanned, never as complete.
func TestHR209_FindingsNameTheirConnectionAndGoUnderTheLease(t *testing.T) {
	w := newGitHubWorld(t)
	w.sim.Push("acme/payments", "main", map[string]string{
		".github/workflows/claude.yml": "on: [issue_comment]\njobs:\n  c:\n    environment: production\n    steps: [{uses: anthropics/claude-code-action@v1}]\n",
	})
	h := setup(t, withGitHubApp(t, w))
	subs, o := runOrgScan(t, h, "01920000-0000-7000-8000-00000000ab05", 1)
	if len(subs.findings) == 0 || !slices.Equal(subs.leases, []string{"the lease's secret"}) {
		t.Fatalf("submitted %+v under %q", subs.findings, subs.leases)
	}
	for _, f := range subs.findings {
		if f.Attributes["connection"] != connID || f.Attributes["repo"] != "acme/payments" {
			t.Fatalf("finding %+v", f)
		}
	}
	if !strings.Contains(o.Fields["/not_scanned/findings"], "1 findings dropped") || o.Complete {
		t.Fatalf("report with a dropped finding %+v", o)
	}
}

// TestHR209_TheScanFitsItsLeaseFromTheClaim: the scan's reads end
// OrgScanTime after the lease was claimed, not after the scan started, so
// a scan that starts late still submits and reports within its lease; what
// it had no time to read is not scanned.
func TestHR209_TheScanFitsItsLeaseFromTheClaim(t *testing.T) {
	w := newGitHubWorld(t)
	h := setup(t, withGitHubApp(t, w))
	fv := &fakeVerifications{}
	subs := &scanSubmissions{}
	h.gw.verifications, h.gw.submitScan = fv, subs.submit
	conn := h.gw.config.Current().ByID[connID]
	h.gw.orgScan(context.Background(), conn, orgScanLease("01920000-0000-7000-8000-00000000ab06"), time.Now().Add(-dispatch.OrgScanTime))
	if len(fv.reports) != 1 {
		t.Fatalf("%d reports", len(fv.reports))
	}
	if o := fv.reports[0]; o.Fields["/not_scanned/repositories"] == "" || o.Fields["/scanned/repositories"] != "" || o.Complete {
		t.Fatalf("a scan past its time %+v", o)
	}
}

// TestF048_TheScanReportsItsOwnInstallation: an org scan reads the
// connection's own GitHub App installation with the App's JWT, minting no
// token for it, and reports its permissions and repository selection with
// the run. When the read fails, the report says nothing about it, so the
// server keeps the installation unread ("not observed"), and the scan
// still runs.
func TestF048_TheScanReportsItsOwnInstallation(t *testing.T) {
	w := newGitHubWorld(t)
	h := setup(t, withGitHubApp(t, w))
	_, o := runOrgScan(t, h, "01920000-0000-7000-8000-00000000ab07")
	in := o.Installation
	if in == nil || in.ID != 7 || in.RepositorySelection != "selected" || in.Permissions["contents"] != "write" ||
		in.Permissions["metadata"] != "read" || in.Permissions["deployments"] != "read" || len(in.Permissions) != 6 {
		t.Fatalf("installation %+v", in)
	}
	read := slices.ContainsFunc(w.sim.Requests(), func(r github.Request) bool {
		return r.Method == http.MethodGet && r.Path == "/app/installations/7" && r.Status == http.StatusOK
	})
	if !read {
		t.Fatal("the installation was not read with the App's JWT")
	}
	for _, tok := range w.sim.Tokens() {
		for p, level := range tok.Permissions {
			if level != "read" {
				t.Errorf("a token with %s:%s was minted", p, level)
			}
		}
	}
	// A lease scheduled for another installation (a re-seal since) carries
	// none of it.
	fv := &fakeVerifications{leases: []dispatch.Lease{orgScanLease("01920000-0000-7000-8000-00000000ab09")}}
	fv.leases[0].Request = []byte(`{"installation":"8","run":"01920000-0000-7000-8000-00000000ab09"}`)
	h.gw.verifications, h.gw.submitScan = fv, (&scanSubmissions{}).submit
	h.gw.verifyDue(context.Background())
	if len(fv.reports) != 1 || fv.reports[0].Installation != nil {
		t.Fatalf("a lease for another installation: %+v", fv.reports)
	}
	w.sim.SetFaults(github.Faults{InstallationStatus: http.StatusInternalServerError})
	_, o = runOrgScan(t, h, "01920000-0000-7000-8000-00000000ab08")
	if o.Installation != nil || !o.Found {
		t.Fatalf("after a failed read: installation %+v, found %v", o.Installation, o.Found)
	}
}
