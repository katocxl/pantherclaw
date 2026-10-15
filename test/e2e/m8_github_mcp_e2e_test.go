// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	defsapp "github.com/katocxl/pantherclaw/internal/definitions/app"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/gateway/upstream"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
	"github.com/katocxl/pantherclaw/internal/sim/github"
	"github.com/katocxl/pantherclaw/internal/sim/mcpsim"
	pcgithub "github.com/katocxl/pantherclaw/packages/pc-github"
)

// toGitHubMCP makes the stack's github connection a connection of kind mcp
// to a simulated GitHub MCP server over the simulator's repositories, at /mcp
// on the simulator's origin, which
// calls the API with the bearer token each request carries, as GitHub's
// hosted server does. The connection still holds the App; its package, a
// pc.github version whose merge dispatches to merge_pull_request, is
// imported, activated and pinned, and the gateway reloads.
func (s *stack) toGitHubMCP(t *testing.T) *mcpsim.Server {
	t.Helper()
	sim := mcpsim.New(mcpsim.Faults{GitHub: s.gh.sim, GitHubBearer: true})
	// On the simulator's own origin: the App credential is bound to it.
	h := sim.Handler()
	s.gh.mcp.Store(&h)
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
	const version = "1.0.2"
	raw, err := github.MCPMergePackage(pcgithub.Package, version, digest)
	if err != nil {
		t.Fatal(err)
	}
	priv, kid, err := rootkey.Generate(rootkey.PurposePackages)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := jws.NewSigner(kid, priv)
	sum := sha256.Sum256(raw)
	doc, err := trust.Sign(trust.Targets{
		Version: 2, Expires: time.Now().Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339),
		Targets: map[string]trust.Target{trust.Key(pcgithub.Name, version): {
			Length: int64(len(raw)), Hashes: map[string]string{"sha256": hex.EncodeToString(sum[:])},
		}},
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	im := &defsapp.Importer{Roots: trust.Roots{kid: signer.Public()}, Repo: &defspg.Store{Pool: s.pool}, Clock: clock.System{}}
	if _, err := im.Import(ctx, s.org, pcgithub.Name, version, doc, raw, nil); err != nil {
		t.Fatalf("import the MCP variant: %v", err)
	}
	if err := im.Transition(ctx, s.org, pcgithub.Name, version, defs.StateActive, nil); err != nil {
		t.Fatalf("activate the MCP variant: %v", err)
	}
	s.db.AdminExec(t, "UPDATE pc.connections SET kind = 'mcp', base_url = $2 WHERE id = $1", s.gh.conn, s.gh.url+"/mcp")
	gw := s.gatewayID(t)
	s.db.AdminExec(t, "UPDATE pc.gateways SET config_version = config_version + 1 WHERE id = $1", gw)
	s.waitConfig(t, s.configVersion(t, gw))
	return sim
}

// openPull pushes branch to the simulator and opens a pull request from it
// into main, as a person would, and returns its head.
func (g *githubSim) openPull(t *testing.T, branch string, files map[string]string) string {
	t.Helper()
	head := g.sim.Push(g.repo, branch, files)
	g.sim.AddToken("ghp_e2e_open", "dev", []string{g.repo}, map[string]string{"pull_requests": "write"})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, g.url+"/repos/"+g.repo+"/pulls",
		strings.NewReader(`{"title":"Fix","head":"`+branch+`","base":"main"}`))
	req.Header.Set("Authorization", "token ghp_e2e_open")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("open the pull request: %v %v", resp, err)
	}
	_ = resp.Body.Close()
	return head
}

// TestE2E_M8_MergeThroughGitHubsMCPServer: the MCP face on a GitHub App
// connection to GitHub's MCP server (ADR-0021 item 2, M8 deviation 2). In
// monitor mode the merge, which would be held, is dispatched (HR-184): the
// gateway mints at GitHub's API a token for exactly the repository and the
// merge's permissions, sends the MCP server the call with it, and revokes
// it after. The pull request merges, the execution receipt says what the
// token allowed and that it was revoked, and every token minted, for the
// facts and for the merge, was revoked.
func TestE2E_M8_MergeThroughGitHubsMCPServer(t *testing.T) {
	s := start(t, options{budget: "1000.00", github: true})
	mcp := s.toGitHubMCP(t)
	s.db.AdminExec(t, `INSERT INTO pc.connection_routes (org_id, connection_id, route, mode, changed_by)
		VALUES ($1, $2, 'github-pull-merge', 'monitor', 'e2e') ON CONFLICT (org_id, connection_id, route) DO UPDATE SET mode = 'monitor'`,
		s.org, s.gh.conn)
	gw := s.gatewayID(t)
	s.db.AdminExec(t, "UPDATE pc.gateways SET config_version = config_version + 1 WHERE id = $1", gw)
	s.waitConfig(t, s.configVersion(t, gw))
	head := s.gh.openPull(t, "fix/mcp", map[string]string{"src/parser.go": "package parser // fixed\n"})

	if refused := s.ghMergeMCP(t, 1, head); refused != nil {
		t.Fatalf("the merge through GitHub's MCP server: %v", refused)
	}
	if p, _ := s.gh.sim.PullRequest(ghRepo, 1); !p.Merged || p.HeadSHA != head || mcp.Calls() != 1 {
		t.Fatalf("pull request %+v, %d MCP calls", p, mcp.Calls())
	}
	// The merge reached GitHub through the MCP server with a token for
	// exactly this repository and the merge's permissions, revoked after.
	var mergeToken string
	revoked := map[string]bool{}
	for _, r := range s.gh.sim.Requests() {
		switch {
		case r.Method == http.MethodPut && strings.HasSuffix(r.Path, "/merge") && r.Status == http.StatusOK:
			if mergeToken != "" || !slices.Equal(r.Repos, []string{ghRepo}) || r.Installation != ghInstallation ||
				!maps.Equal(r.Permissions, map[string]string{"contents": "write", "metadata": "read"}) {
				t.Fatalf("the merge's token: %+v", r)
			}
			mergeToken = r.Token
		case r.Method == http.MethodDelete && r.Path == "/installation/token" && r.Status == http.StatusNoContent:
			revoked[r.Token] = true
		}
	}
	if mergeToken == "" || !revoked[mergeToken] {
		t.Fatalf("the merge's token %q was not revoked", mergeToken)
	}
	for _, tok := range s.gh.sim.Tokens() {
		if tok.Installation == ghInstallation && !tok.Revoked {
			t.Fatalf("a token left valid: %+v", tok)
		}
	}
	// Recorded: monitor mode, accepted, and the receipt names the token's
	// access without the token.
	var mode, outcome, receipt string
	s.query(t, `SELECT t.mode, a.outcome, r.receipt_jws FROM pc.transactions t
		JOIN pc.execution_attempts a ON a.org_id = t.org_id AND a.transaction_id = t.id
		JOIN pc.execution_receipts r ON r.org_id = a.org_id AND r.attempt_id = a.id
		WHERE t.operation = 'github.pull.merge' AND t.channel = 'mcp'`, nil, &mode, &outcome, &receipt)
	parts := strings.Split(receipt, ".")
	if len(parts) != 3 {
		t.Fatalf("receipt %q", receipt)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	if mode != "monitor" || outcome != "accepted" || !strings.Contains(string(payload), `"revocation":"revoked"`) ||
		!strings.Contains(string(payload), `"`+ghRepo+`"`) {
		t.Fatalf("recorded %s %s, receipt %s", mode, outcome, payload)
	}
}
