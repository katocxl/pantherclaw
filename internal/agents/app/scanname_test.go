// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import "testing"

// TestScanNamesUseTheFindingsAttributes: a discovered agent from an org
// scan is named after what the scan found, by the attributes the gateway
// sends (G0 M8 N20), never left blank.
func TestScanNamesUseTheFindingsAttributes(t *testing.T) {
	for _, c := range []struct {
		f    ScanFinding
		want string
	}{
		{
			ScanFinding{Kind: "github_workflow", Attributes: map[string]string{"repo": "acme/payments", "path": ".github/workflows/claude.yml"}},
			"GitHub workflow acme/payments .github/workflows/claude.yml",
		},
		{
			ScanFinding{Kind: "github_mcp_config", Attributes: map[string]string{"repo": "acme/payments", "path": ".mcp.json"}},
			"MCP configuration acme/payments .mcp.json",
		},
		{ScanFinding{Kind: "github_app", Attributes: map[string]string{"app_slug": "deploy-bot"}}, "GitHub App deploy-bot"},
		{ScanFinding{Kind: "mcp_server", Attributes: map[string]string{"name": "github", "client": "cursor"}}, "MCP server github (cursor)"},
	} {
		if got := scanName(c.f); got != c.want {
			t.Errorf("%s: %q, want %q", c.f.Kind, got, c.want)
		}
	}
}
