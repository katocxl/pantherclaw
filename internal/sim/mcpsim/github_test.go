// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcpsim

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/sim/github"
)

// TestGitHubTools: with a GitHub simulator the server lists the GitHub MCP
// server's tools and runs them against that simulator, as the real server
// runs them against GitHub with its token.
func TestGitHubTools(t *testing.T) {
	gh := github.New(slog.New(slog.DiscardHandler))
	gh.CreateRepo("acme/payments", "main", map[string]string{"README.md": "# payments\n"})
	gh.AddToken("ghp_server", "developer", []string{"acme/payments"}, map[string]string{"contents": "read"})
	s := New(Faults{GitHub: gh, GitHubToken: "ghp_server"})
	var names []string
	for _, tool := range s.Tools() {
		var d struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(tool, &d)
		names = append(names, d.Name)
	}
	if !slices.Contains(names, "merge_pull_request") || !slices.Contains(names, "create_refund") {
		t.Fatalf("tools %v", names)
	}
	result, rpcErr := s.call(t.Context(), jsontext.Value(`{"name":"get_file_contents","arguments":{"owner":"acme","repo":"payments","path":"README.md"}}`))
	if rpcErr != nil || result["isError"] != false || !strings.Contains(string(result["structuredContent"].(jsontext.Value)), `"encoding":"base64"`) {
		t.Fatalf("get_file_contents: %v %v", result, rpcErr)
	}
	// The token reads only: a branch is refused by the API, as a tool error.
	result, rpcErr = s.call(t.Context(), jsontext.Value(`{"name":"create_branch","arguments":{"owner":"acme","repo":"payments","branch":"x"}}`))
	if rpcErr != nil || result["isError"] != true || s.Calls() != 2 {
		t.Fatalf("create_branch: %v %v", result, rpcErr)
	}
	// The refund tools still take string arguments only.
	if _, rpcErr := s.call(t.Context(), jsontext.Value(`{"name":"create_refund","arguments":{"charge":1}}`)); rpcErr == nil {
		t.Fatal("a non-string refund argument")
	}
}
