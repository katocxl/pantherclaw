// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"bytes"
	"context"
	"maps"
	"path/filepath"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gateway/githubfacts"
)

// TestGitHubSubcommand: the App key is created once and reused, and the
// MCP address goes with its token file.
func TestGitHubSubcommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Run(context.Background(), []string{"github"}, &out, &errb); code != 1 {
		t.Fatalf("no --app-key: %d %s", code, errb.String())
	}
	key := filepath.Join(t.TempDir(), "app.pem")
	if code := Run(context.Background(), []string{"github", "--app-key", key, "--mcp-addr", "127.0.0.1:0"}, &out, &errb); code != 1 {
		t.Fatalf("--mcp-addr without a token file: %d", code)
	}
	a, err := appKey(key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := appKey(key)
	if err != nil || !a.Equal(b) {
		t.Fatalf("the key is not reused: %v", err)
	}
}

// TestGitHubInstallationGrantsTheFactReads: the installation the CLI makes
// grants every permission the gateway's fact reads and the deployment
// verifier need (the list is derived from githubfacts.Scopes; the
// verifier's deployments read is named here), at the level they ask or
// more, so the gateway's fact token is never refused.
func TestGitHubInstallationGrantsTheFactReads(t *testing.T) {
	granted := installationPermissions()
	rank := map[string]int{"read": 1, "write": 2, "admin": 3}
	need := map[string]string{"deployments": "read"} // the deployment verifier's reads
	maps.Copy(need, githubfacts.Scopes)
	for perm, level := range need {
		if rank[granted[perm]] < rank[level] {
			t.Errorf("the installation grants %q %q, the gateway needs %q", perm, granted[perm], level)
		}
	}
}
