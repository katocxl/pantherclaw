// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
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
