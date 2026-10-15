// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/version"
	"github.com/katocxl/pantherclaw/internal/sim/github"
	"github.com/katocxl/pantherclaw/internal/sim/mcpsim"
)

// demoWorkflow deploys to production on every push to main: merging into
// main is a deployment consequence (§43).
const demoWorkflow = `name: deploy
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - run: echo deploying
`

// runGitHub serves the simulated GitHub API with one App installed on one
// account, and, with --mcp-addr, the GitHub MCP server's tools over the
// same repositories, authenticated with a personal token (the route an
// agent with a found token takes).
func runGitHub(ctx context.Context, args []string, stderr io.Writer) error {
	fl := flag.NewFlagSet("github", flag.ContinueOnError)
	fl.SetOutput(stderr)
	addr := fl.String("addr", "127.0.0.1:9092", "listen address (loopback)")
	appID := fl.Int64("app-id", 1, "the App's id")
	clientID := fl.String("client-id", "Iv23liSimulated", "the App's client id")
	keyFile := fl.String("app-key", "", "the App's private key (PEM); created when it does not exist, for pclaw seal")
	installation := fl.Int64("installation", 1, "the installation's id")
	account := fl.String("account", "acme", "the account the App is installed on")
	repos := fl.String("repos", "payments", "comma-separated repositories to create and install on")
	mcpAddr := fl.String("mcp-addr", "", "also serve the GitHub MCP server's tools here")
	tokenFile := fl.String("mcp-token-file", "", "the personal token the MCP server uses (required with --mcp-addr)")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" || (*mcpAddr != "") != (*tokenFile != "") {
		return errors.New("--app-key is required, and --mcp-addr goes with --mcp-token-file")
	}
	key, err := appKey(*keyFile)
	if err != nil {
		return err
	}
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-sim", Version: version.Get().Version})
	sim := github.New(log)
	sim.RegisterApp(*appID, *clientID, &key.PublicKey)
	names := strings.Split(*repos, ",")
	sim.Install(github.Installation{ID: *installation, Account: *account, Repos: names, Permissions: installationPermissions()})
	full := make([]string, len(names))
	for i, n := range names {
		full[i] = *account + "/" + n
		sim.CreateRepo(full[i], "main", map[string]string{"README.md": "# " + n + " (SIMULATED)\n", ".github/workflows/deploy.yml": demoWorkflow})
		sim.DeployOnPush(full[i], "main", "production", 2*time.Minute)
		sim.SetEnvironments(full[i], github.Environment{Name: "production"})
	}
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return serve(ctx, *addr, sim.Handler(), log, "sim.github_listening") })
	if *mcpAddr != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return err
		}
		token := strings.TrimSpace(string(b))
		sim.AddToken(token, "developer", full, map[string]string{"contents": "write", "pull_requests": "write"})
		mcp := mcpsim.New(mcpsim.Faults{GitHub: sim, GitHubToken: token})
		g.Go(func() error { return serve(ctx, *mcpAddr, mcp.Handler(), log, "sim.github_mcp_listening") })
	}
	return g.Wait()
}

// appKey reads the App's private key, or creates it (mode 0600) when the
// file does not exist.
func appKey(path string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the operator names the file
	if errors.Is(err, fs.ErrNotExist) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		out := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		return key, os.WriteFile(path, out, 0o600)
	}
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("--app-key: not a PEM file")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// installationPermissions are the permissions the simulated App is installed
// with: what docs/runbooks/github-app.md asks of a real App. Among them are
// the gateway's fact reads (githubfacts.Scopes: metadata, contents, pull
// requests, checks and commit statuses, read) and the deployment verifier's
// (deployments, read); without one, the gateway's fact token is refused (422)
// and branch creations and contents writes are held as CONSEQUENCE_UNKNOWN.
func installationPermissions() map[string]string {
	return map[string]string{
		"metadata": "read", "contents": "write", "pull_requests": "write", "administration": "write", "actions": "read",
		"checks": "read", "statuses": "read", "deployments": "read",
	}
}
