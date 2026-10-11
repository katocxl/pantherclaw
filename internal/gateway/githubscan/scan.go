// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package githubscan is the gateway's side of the organization scan (G0
// M8, PN-001.2, HR-209): through the connection's App, with read-only
// tokens of its own, it reads the installation's repositories, their
// workflow files and their committed MCP configuration files, and nothing
// else of their contents. It keeps names only: which agent actions a
// workflow runs and what it may write, which MCP servers a repository
// configures and with which command. Every value, argument and URL is
// dropped in memory before a finding is built. A source it could not read
// is reported as not scanned, never as "none found".
package githubscan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/githubfacts"
)

// Getter reads one GitHub API path with the scan's token placed.
type Getter = githubfacts.Getter

// Repository is one repository the installation reaches.
type Repository struct {
	FullName, DefaultBranch string
}

// Finding is one thing found, for SubmitScanFindings: a kind, a stable key
// and untrusted attributes (at most 16, each at most 256 bytes).
type Finding struct {
	Kind       string
	Key        [32]byte
	Attributes map[string]string
}

// Result is what a scan found and how far it got.
type Result struct {
	Findings   []Finding
	Counts     map[string]int64
	Scanned    []string
	NotScanned map[string]string
}

// maxWorkflows is the most workflow files read per repository.
const maxWorkflows = githubfacts.MaxWorkflowFiles

// ScanRepositories reads each repository's workflow files and committed
// MCP configuration files at its default branch, until deadline.
func ScanRepositories(ctx context.Context, get Getter, repos []Repository, deadline time.Time) Result {
	r := Result{Counts: map[string]int64{}, NotScanned: map[string]string{}}
	failed := 0
	for i, repo := range repos {
		if time.Now().After(deadline) || ctx.Err() != nil {
			r.NotScanned["repositories"] = fmt.Sprintf("time limit: %d of %d repositories read", i, len(repos))
			break
		}
		if err := r.repository(ctx, get, repo); err != nil {
			failed++
			continue
		}
		r.Counts["repositories"]++
	}
	if failed > 0 {
		r.NotScanned["contents"] = fmt.Sprintf("%d repositories could not be read", failed)
	}
	r.Scanned = []string{"mcp_configs", "repositories", "workflows"}
	return r
}

func (r *Result) repository(ctx context.Context, get Getter, repo Repository) error {
	owner, name, ok := strings.Cut(repo.FullName, "/")
	if !ok {
		return fmt.Errorf("githubscan: repository %q", repo.FullName)
	}
	repoPath := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name)
	// GitHub answers 404 for a file that is not there and for a repository
	// the token cannot see: read the repository first, so an unreadable one
	// is never taken for one with nothing in it.
	if res, err := get(ctx, repoPath); err != nil {
		return err
	} else if res.Status != http.StatusOK {
		return fmt.Errorf("githubscan: %s answered %d", repo.FullName, res.Status)
	}
	base := repoPath + "/contents/"
	at := "?ref=" + url.QueryEscape(repo.DefaultBranch)
	file := func(p string) ([]byte, bool, error) {
		res, err := get(ctx, base+githubfacts.EscapeRef(p)+at)
		switch {
		case err != nil:
			return nil, false, err
		case res.Status == http.StatusNotFound:
			return nil, false, nil
		case res.Status != http.StatusOK || res.Truncated:
			return nil, false, fmt.Errorf("githubscan: %s answered %d", p, res.Status)
		}
		var f struct {
			Type     string `json:"type"`
			Encoding string `json:"encoding"`
			Content  string `json:"content"`
		}
		if bytes.HasPrefix(bytes.TrimSpace(res.Body), []byte("[")) {
			return nil, false, nil // a directory: not a configuration
		}
		if err := json.Unmarshal(res.Body, &f); err != nil {
			return nil, false, fmt.Errorf("githubscan: %s: %w", p, err)
		}
		if f.Type != "file" || f.Encoding != "base64" {
			return nil, false, nil // too large to come inline: not read
		}
		raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(f.Content, "\n", ""))
		return raw, err == nil, err
	}
	// Workflows: the directory listing, then each workflow file.
	res, err := get(ctx, base+".github/workflows"+at)
	if err != nil {
		return err
	}
	if res.Status == http.StatusOK {
		var listing []struct {
			Type string `json:"type"`
			Path string `json:"path"`
		}
		if json.Unmarshal(res.Body, &listing) != nil {
			return fmt.Errorf("githubscan: workflow listing of %s", repo.FullName)
		}
		read := 0
		for _, e := range listing {
			if e.Type != "file" || (!strings.HasSuffix(e.Path, ".yml") && !strings.HasSuffix(e.Path, ".yaml")) || read == maxWorkflows {
				continue
			}
			read++
			raw, ok, err := file(e.Path)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			r.Counts["workflows"]++
			w, err := ParseWorkflow(raw)
			if err != nil || len(w.Actions) == 0 {
				continue
			}
			r.Counts["agent_workflows"]++
			r.add("github_workflow", map[string]string{
				"repository": repo.FullName, "path": clip(e.Path), "actions": joined(w.Actions), "permissions": joined(w.Permissions),
			}, repo.FullName, e.Path)
		}
	} else if res.Status != http.StatusNotFound {
		return fmt.Errorf("githubscan: workflow listing of %s answered %d", repo.FullName, res.Status)
	}
	// Committed MCP configuration, by name only.
	for _, p := range MCPConfigPaths {
		raw, ok, err := file(p)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		servers, err := ParseMCPConfig(raw)
		clear(raw)
		if err != nil {
			continue
		}
		r.Counts["mcp_configs"]++
		for _, s := range servers {
			r.Counts["mcp_servers"]++
			r.add("github_mcp_config", map[string]string{
				"repository": repo.FullName, "path": p, "name": s.Name, "command": s.Command, "transport": s.Transport,
				"env": joined(s.Env), "headers": joined(s.Headers),
			}, repo.FullName, p, s.Name)
		}
	}
	return nil
}

// add records a finding, keyed by what identifies it.
func (r *Result) add(kind string, attrs map[string]string, id ...string) {
	for k, v := range attrs {
		if v == "" {
			delete(attrs, k)
		}
	}
	r.Findings = append(r.Findings, Finding{Kind: kind, Key: sha256.Sum256([]byte(kind + "\x00" + strings.Join(id, "\x00"))), Attributes: attrs})
}

// joined is a list as one attribute, at most 256 bytes, cut at a name.
func joined(list []string) string {
	s := ""
	for _, v := range list {
		if len(s)+len(v)+1 > 256 {
			return s
		}
		if s != "" {
			s += ","
		}
		s += v
	}
	return s
}

// Fields is the run's summary as the org_scan report carries it.
func (r Result) Fields() map[string]string {
	out := map[string]string{}
	for k, v := range r.Counts {
		out["/counts/"+k] = strconv.FormatInt(v, 10)
	}
	for _, s := range r.Scanned {
		out["/scanned/"+s] = "true"
	}
	for s, why := range r.NotScanned {
		if len(why) > 256 {
			why = why[:256]
		}
		out["/not_scanned/"+s] = why
	}
	return out
}

// ListRepositories reads the repositories an installation token reaches
// (GET /installation/repositories), at most 500.
func ListRepositories(ctx context.Context, get Getter) ([]Repository, error) {
	var out []Repository
	for page := 1; page <= 5; page++ {
		res, err := get(ctx, "/installation/repositories?per_page=100&page="+strconv.Itoa(page))
		if err != nil {
			return nil, err
		}
		var list struct {
			Repositories []struct {
				FullName      string `json:"full_name"`
				DefaultBranch string `json:"default_branch"`
			} `json:"repositories"`
		}
		if res.Status != http.StatusOK || json.Unmarshal(res.Body, &list) != nil {
			return nil, fmt.Errorf("githubscan: the installation's repositories answered %d", res.Status)
		}
		for _, r := range list.Repositories {
			out = append(out, Repository{FullName: strings.ToLower(r.FullName), DefaultBranch: r.DefaultBranch})
		}
		if len(list.Repositories) < 100 {
			break
		}
	}
	return out, nil
}

// Apps reads the other Apps installed on the organization (GET
// /orgs/{org}/installations), each a github_app finding: its slug, id,
// permissions and repository selection.
func Apps(ctx context.Context, get Getter, org string) ([]Finding, error) {
	res, err := get(ctx, "/orgs/"+url.PathEscape(org)+"/installations?per_page=100")
	if err != nil {
		return nil, err
	}
	var list struct {
		Installations []struct {
			AppID       int64             `json:"app_id"`
			AppSlug     string            `json:"app_slug"`
			Permissions map[string]string `json:"permissions"`
			Selection   string            `json:"repository_selection"`
		} `json:"installations"`
	}
	if res.Status != http.StatusOK || json.Unmarshal(res.Body, &list) != nil {
		return nil, fmt.Errorf("githubscan: the organization's installations answered %d", res.Status)
	}
	var r Result
	for _, in := range list.Installations {
		perms := make([]string, 0, len(in.Permissions))
		for k, v := range in.Permissions {
			perms = append(perms, clip(k)+":"+clip(v))
		}
		slices.Sort(perms)
		r.add("github_app", map[string]string{
			"organization": org, "app": clip(in.AppSlug), "app_id": strconv.FormatInt(in.AppID, 10), "permissions": joined(perms),
			"repository_selection": clip(in.Selection),
		}, org, strconv.FormatInt(in.AppID, 10))
	}
	return r.Findings, nil
}
