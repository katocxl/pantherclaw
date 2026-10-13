// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	credentials "github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/gateway/githubscan"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// OrgScanTime bounds an organization scan's reads, from the moment its
// lease was claimed: a lease lasts at most 30 seconds (HR-190), and the
// rest is for submitting the findings and reporting. What is left is
// reported as not scanned.
const OrgScanTime = 20 * time.Second

var errNotGitHubApp = errors.New("dispatch: an organization scan needs a GitHub App connection")

// ScanOrg scans the organization behind a GitHub App connection (G0 M8,
// PN-001.2, HR-209) until deadline, with read-only tokens of its own, each
// revoked after its use: metadata of all the installation's repositories
// to list them; metadata and contents of those for their workflow and MCP
// configuration files; and, when the App may read them, the organization's
// App installations. Ruleset bypass actors are not read yet, and say so.
// Every finding names the connection it was scanned through. An error
// means the App could not be used at all.
func (e *Engine) ScanOrg(ctx context.Context, conn *control.Connection, deadline time.Time) (githubscan.Result, error) {
	if conn.Credential.GetKind() != credentials.KindGitHubApp {
		return githubscan.Result{}, errNotGitHubApp
	}
	c, err := e.client(conn)
	if err != nil {
		return githubscan.Result{}, err
	}
	app, err := e.openApp(conn)
	if err != nil {
		return githubscan.Result{}, err
	}
	defer app.Clear()
	// The installation's own permissions, with the App's JWT and no token
	// (F048). A failed read leaves the installation unread on the server.
	var installation *githubscan.Installation
	if in, err := broker.ReadInstallation(ctx, c, conn.GetBaseUrl(), conn.Credential.GetAllowedHosts(), app, time.Now()); err != nil {
		e.log.WarnContext(ctx, "gateway.installation_not_read", slog.String("connection_id", conn.GetId()), pclog.Err(err))
	} else {
		installation = &githubscan.Installation{ID: app.Installation, Permissions: in.Permissions, RepositorySelection: in.RepositorySelection}
	}
	mint := func(repos []string, perms map[string]string) (*broker.Installation, error) {
		return broker.MintScanToken(ctx, c, conn.GetBaseUrl(), conn.Credential.GetAllowedHosts(), app, repos, perms, time.Now())
	}
	use := func(tok *broker.Installation, read func(githubscan.Getter)) {
		read(tokenGetter(conn, c, tok))
		if err := tok.Revoke(context.WithoutCancel(ctx), c); err != nil {
			e.log.WarnContext(ctx, "gateway.installation_token_not_revoked", slog.String("connection_id", conn.GetId()), pclog.Err(err))
		}
	}
	list, err := mint(nil, map[string]string{"metadata": "read"})
	if err != nil {
		return githubscan.Result{}, err
	}
	var repos []githubscan.Repository
	all := true
	use(list, func(get githubscan.Getter) { repos, all, err = githubscan.ListRepositories(ctx, get) })
	if err != nil {
		return githubscan.Result{}, err
	}
	r := githubscan.Result{Counts: map[string]int64{}, NotScanned: map[string]string{}}
	if len(repos) > 0 {
		names := make([]string, len(repos))
		for i, repo := range repos {
			_, names[i], _ = strings.Cut(repo.FullName, "/")
		}
		contents, err := mint(names, map[string]string{"metadata": "read", "contents": "read"})
		if err != nil {
			return githubscan.Result{}, err
		}
		use(contents, func(get githubscan.Getter) { r = githubscan.ScanRepositories(ctx, get, repos, deadline) })
	}
	if !all {
		// Repositories past the first 500 are not read, nor their files.
		for _, s := range []string{"repositories", "workflows", "mcp_configs"} {
			why := fmt.Sprintf("the installation reaches more than %d repositories: only the first %d were read", len(repos), len(repos))
			if r.NotScanned[s] != "" {
				why = r.NotScanned[s] + "; " + why
			}
			r.NotScanned[s] = why
		}
		r.Scanned = slices.DeleteFunc(r.Scanned, func(s string) bool { return r.NotScanned[s] != "" })
	}
	if org, err := mint(nil, map[string]string{"organization_administration": "read"}); err != nil {
		r.NotScanned["org_installations"] = "the App may not read the organization's installations (organization_administration:read)"
	} else {
		use(org, func(get githubscan.Getter) {
			apps, every, err := githubscan.Apps(ctx, get, app.Account)
			if err != nil {
				r.NotScanned["org_installations"] = "the organization's installations could not be read"
				return
			}
			r.Findings = append(r.Findings, apps...)
			r.Counts["apps"] = int64(len(apps))
			if !every {
				r.NotScanned["org_installations"] = fmt.Sprintf("more than %d installations: only the first %d were read", len(apps), len(apps))
				return
			}
			r.Scanned = append(r.Scanned, "org_installations")
		})
	}
	r.NotScanned["rulesets"] = "ruleset bypass actors are not read by this gateway version"
	r.Installation = installation
	for i := range r.Findings {
		r.Findings[i].Attributes["connection"] = conn.GetId()
	}
	return r, nil
}

// openApp opens the connection's GitHub App credential, for its
// recorded installation only; the caller clears it.
func (e *Engine) openApp(conn *control.Connection) (credentials.GitHubApp, error) {
	plain, err := e.openCredential(conn)
	if err != nil {
		return credentials.GitHubApp{}, err
	}
	app, err := credentials.DecodeGitHubApp(plain)
	clear(plain)
	if err != nil {
		return credentials.GitHubApp{}, err
	}
	if !installed(conn, app) {
		app.Clear()
		return credentials.GitHubApp{}, errInstallation
	}
	return app, nil
}

// tokenGetter reads one GitHub path through the connection's egress client
// with tok placed.
func tokenGetter(conn *control.Connection, c *egress.Client, tok *broker.Installation) githubscan.Getter {
	base := strings.TrimSuffix(conn.GetBaseUrl(), "/")
	return func(ctx context.Context, path string) (egress.Response, error) {
		u, err := url.Parse(base + path)
		if err != nil {
			return egress.Response{}, err
		}
		req, err := c.HTTPRequest(ctx, egress.Request{Method: http.MethodGet, URL: u})
		if err != nil {
			return egress.Response{}, err
		}
		if err := tok.Place(req); err != nil {
			return egress.Response{}, err
		}
		return c.Do(req)
	}
}
