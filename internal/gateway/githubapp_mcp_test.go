// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"encoding/json/v2"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gateway/upstream"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/sim/github"
	"github.com/katocxl/pantherclaw/internal/sim/mcpsim"
)

// withGitHubMCP makes the connection a GitHub App connection of kind mcp to
// a simulated GitHub MCP server over w's repositories, which calls the API
// with the bearer token each request carries, as GitHub's hosted server
// does. Its package dispatches merges to merge_pull_request, and the
// gateway mints at w's API (github.api_url).
func withGitHubMCP(t *testing.T, w *gitHubWorld) (*mcpsim.Server, func(*harness)) {
	t.Helper()
	sim := mcpsim.New(mcpsim.Faults{GitHub: w.sim, GitHubBearer: true})
	ts := httptest.NewServer(sim.Handler())
	t.Cleanup(ts.Close)
	digest := ""
	for _, tool := range sim.Tools() {
		var n struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(tool, &n) == nil && n.Name == github.MergeTool {
			d, err := upstream.ToolDigest(tool)
			if err != nil {
				t.Fatal(err)
			}
			digest = d
		}
	}
	app := withGitHubApp(t, w)
	return sim, func(h *harness) {
		app(h)
		h.conn.Kind, h.targetURL, h.githubAPI = "mcp", ts.URL+"/mcp", w.url
		h.mutatePkg = func(raw []byte) []byte {
			out, err := github.MCPMergePackage(raw, "1.0.1", digest)
			if err != nil {
				t.Fatal(err)
			}
			return out
		}
	}
}

// mergeArgs are merge_pull_request's arguments for pull request 1 at head.
func mergeArgs(head string) string {
	return `"name":"merge_pull_request","arguments":{"owner":"acme","repo":"payments","pullNumber":1,"expectedHeadSha":"` + head +
		`","merge_method":"squash"}`
}

// TestHR203_TheMCPFaceMintsATokenPerActionForGitHubsMCPServer: on a GitHub
// App connection to GitHub's MCP server, an authorized merge is sent with
// an installation token minted at GitHub's API for exactly its repository
// and the merge's permissions, placed as a bearer token on the requests to
// the MCP server and revoked once the answer is read (ADR-0021 item 2). The
// receipt says what the token allowed.
func TestHR203_TheMCPFaceMintsATokenPerActionForGitHubsMCPServer(t *testing.T) {
	w := newGitHubWorld(t)
	sim, opt := withGitHubMCP(t, w)
	h := setup(t, opt)
	r := h.mcpCall(t, http.MethodPost, mcpPath, jsonRPC("tools/call", mergeArgs(w.head)), nil)
	res := r.body.Result
	if r.code != http.StatusOK || res.IsError || len(res.Content) != 1 || !strings.Contains(res.Content[0].Text, `"merged":true`) ||
		sim.Calls() != 1 {
		t.Fatalf("merge = %d %+v %+v, %d upstream runs", r.code, r.body.Error, res, sim.Calls())
	}
	if p, _ := w.sim.PullRequest("acme/payments", 1); !p.Merged {
		t.Fatal("the pull request was not merged")
	}
	tokens := w.sim.Tokens()
	if len(tokens) != 1 {
		t.Fatalf("%d tokens minted, want one for the action: %+v", len(tokens), tokens)
	}
	tok := tokens[0]
	if !tok.Revoked || !slices.Equal(tok.Repos, []string{"acme/payments"}) || tok.Installation != 7 ||
		!maps.Equal(tok.Permissions, map[string]string{"contents": "write", "metadata": "read"}) {
		t.Fatalf("token %+v", tok)
	}
	// The merge reached GitHub with that token, through the MCP server.
	var merged bool
	for _, req := range w.sim.Requests() {
		if req.Method == http.MethodPut && strings.HasSuffix(req.Path, "/pulls/1/merge") && req.Status == http.StatusOK && req.Installation == 7 {
			merged = true
		}
	}
	if !merged {
		t.Fatalf("no merge with the installation's token: %+v", w.sim.Requests())
	}
	s := h.auth.snap()
	if s.outcome() != pb.Outcome_OUTCOME_ACCEPTED {
		t.Fatalf("recorded %+v", s.records)
	}
	a := s.records[len(s.records)-1].GetCredentialAccess()
	if a.GetInstallationId() != 7 || a.GetRepository() != "acme/payments" || a.GetRevocation() != "revoked" ||
		!maps.Equal(a.GetRequested(), map[string]string{"contents": "write"}) {
		t.Fatalf("the receipt's access %+v", a)
	}
}

// TestHR203_AWiderGrantOverTheMCPFaceSendsNothing: when GitHub grants more
// than the merge asked for, the token is revoked, nothing reaches the MCP
// server, and the dispatch fails with credential_scope_mismatch, its
// receipt naming what was granted (ADR-0021 item 3).
func TestHR203_AWiderGrantOverTheMCPFaceSendsNothing(t *testing.T) {
	w := newGitHubWorld(t)
	w.sim.SetFaults(github.Faults{WiderGrant: true})
	sim, opt := withGitHubMCP(t, w)
	h := setup(t, opt)
	r := h.mcpCall(t, http.MethodPost, mcpPath, jsonRPC("tools/call", mergeArgs(w.head)), nil)
	if !r.body.Result.IsError || !strings.Contains(string(r.body.Result.Meta["io.pantherclaw/error"]), "credential_scope_mismatch") ||
		sim.Calls() != 0 {
		t.Fatalf("a wider grant: %+v, %d upstream runs", r.body.Result, sim.Calls())
	}
	if p, _ := w.sim.PullRequest("acme/payments", 1); p.Merged {
		t.Fatal("merged with a wider token")
	}
	for _, tok := range w.sim.Tokens() {
		if !tok.Revoked {
			t.Fatalf("a wider token left valid: %+v", tok)
		}
	}
	s := h.auth.snap()
	if s.outcome() != pb.Outcome_OUTCOME_FAILED || s.records[len(s.records)-1].GetCredentialAccess().GetRevocation() != "revoked" {
		t.Fatalf("recorded %+v", s.records)
	}
}

// TestHR081_ADriftCheckOfGitHubsMCPServerUsesAReadOnlyToken: a drift
// check outside any call lists the tools with a token of its own that can
// only read metadata, revoked after the listing; the reviewed merge tool
// matches its pin.
func TestHR081_ADriftCheckOfGitHubsMCPServerUsesAReadOnlyToken(t *testing.T) {
	w := newGitHubWorld(t)
	_, opt := withGitHubMCP(t, w)
	h := setup(t, opt)
	drifts, err := h.gw.engine.CheckDrift(t.Context(), h.conn)
	if err != nil || len(drifts) != 0 {
		t.Fatalf("drift check: %v %+v", err, drifts)
	}
	tokens := w.sim.Tokens()
	if len(tokens) != 1 || !tokens[0].Revoked || !maps.Equal(tokens[0].Permissions, map[string]string{"metadata": "read"}) {
		t.Fatalf("tokens %+v", tokens)
	}
}
