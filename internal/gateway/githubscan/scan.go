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
	"maps"
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
	// skipped counts what a source did not read, by reason.
	skipped map[string]map[string]int
}

// maxWorkflows is the most workflow files read per repository.
const maxWorkflows = githubfacts.MaxWorkflowFiles

// repositorySources are the sources ScanRepositories reads.
var repositorySources = []string{"mcp_configs", "repositories", "workflows"}

// ScanRepositories reads each repository's workflow files and committed
// MCP configuration files at its default branch, until deadline. What it
// could not read (repositories left at the deadline or unreadable, files
// over the limit, too large, not plain files or refused by the parser) is
// reported as not scanned, with why, and that source is then not reported
// as scanned.
func ScanRepositories(ctx context.Context, get Getter, repos []Repository, deadline time.Time) Result {
	r := Result{Counts: map[string]int64{}, NotScanned: map[string]string{}}
	failed, tried := 0, 0
	for _, repo := range repos {
		if time.Now().After(deadline) || ctx.Err() != nil {
			break
		}
		tried++
		if err := r.repository(ctx, get, repo); err != nil {
			failed++
			continue
		}
		r.Counts["repositories"]++
	}
	var why []string
	if tried < len(repos) {
		why = append(why, fmt.Sprintf("time limit: %d of %d repositories read", tried, len(repos)))
	}
	if failed > 0 {
		why = append(why, fmt.Sprintf("%d repositories could not be read", failed))
	}
	if why != nil {
		r.NotScanned["repositories"] = strings.Join(why, "; ")
		for _, s := range []string{"workflows", "mcp_configs"} {
			r.skip(s, "in repositories not read", len(repos)-tried+failed)
		}
	}
	for _, s := range slices.Sorted(maps.Keys(r.skipped)) {
		var parts []string
		for _, reason := range slices.Sorted(maps.Keys(r.skipped[s])) {
			parts = append(parts, fmt.Sprintf("%d %s", r.skipped[s][reason], reason))
		}
		r.NotScanned[s] = "not read: " + strings.Join(parts, ", ")
	}
	r.Scanned = nil
	for _, s := range repositorySources {
		if _, not := r.NotScanned[s]; !not {
			r.Scanned = append(r.Scanned, s)
		}
	}
	return r
}

// skip counts n things of source not read, for reason.
func (r *Result) skip(source, reason string, n int) {
	if r.skipped == nil {
		r.skipped = map[string]map[string]int{}
	}
	if r.skipped[source] == nil {
		r.skipped[source] = map[string]int{}
	}
	r.skipped[source][reason] += n
}

// fileState is what a read of one file found.
type fileState int

const (
	absent fileState = iota // not there, or a directory
	present
	unread // there, but too large to come inline or not a plain file
)

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
	file := func(p string) ([]byte, fileState, error) {
		res, err := get(ctx, base+githubfacts.EscapeRef(p)+at)
		switch {
		case err != nil:
			return nil, absent, err
		case res.Status == http.StatusNotFound:
			return nil, absent, nil
		case res.Status != http.StatusOK || res.Truncated:
			return nil, absent, fmt.Errorf("githubscan: %s answered %d", p, res.Status)
		}
		var f struct {
			Type     string `json:"type"`
			Encoding string `json:"encoding"`
			Content  string `json:"content"`
		}
		if bytes.HasPrefix(bytes.TrimSpace(res.Body), []byte("[")) {
			return nil, absent, nil // a directory: not a configuration
		}
		if err := json.Unmarshal(res.Body, &f); err != nil {
			return nil, absent, fmt.Errorf("githubscan: %s: %w", p, err)
		}
		if f.Type != "file" || f.Encoding != "base64" {
			return nil, unread, nil // a symlink, or too large to come inline
		}
		raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(f.Content, "\n", ""))
		if err != nil {
			return nil, absent, err
		}
		return raw, present, nil
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
			if !strings.HasPrefix(e.Path, ".github/workflows/") || (!strings.HasSuffix(e.Path, ".yml") && !strings.HasSuffix(e.Path, ".yaml")) {
				continue
			}
			switch {
			case e.Type != "file":
				r.skip("workflows", "not plain files", 1)
				continue
			case read == maxWorkflows:
				r.skip("workflows", fmt.Sprintf("over the %d-file limit of a repository", maxWorkflows), 1)
				continue
			}
			read++
			raw, state, err := file(e.Path)
			if err != nil {
				return err
			}
			if state != present || len(raw) > githubfacts.MaxWorkflowBytes {
				r.skip("workflows", "too large or not plain files", 1)
				continue
			}
			r.Counts["workflows"]++
			w, err := ParseWorkflow(raw)
			if err != nil {
				r.skip("workflows", "refused by the parser", 1)
				continue
			}
			for _, how := range w.Unchecked {
				// Reported, not guessed: the scan recognizes agent actions
				// only, so these may run an agent it cannot see.
				r.Counts["workflows_agent_unchecked"]++
				r.skip("workflows", "with agent use not checked ("+how+")", 1)
			}
			if len(w.Actions) == 0 {
				continue
			}
			r.Counts["agent_workflows"]++
			attrs := map[string]string{
				"repo": repo.FullName, "path": clip(e.Path),
				"writes": strconv.FormatBool(w.Writes()), "deploys": strconv.FormatBool(len(w.Environments) > 0),
			}
			put(attrs, "agent_actions", w.Actions)
			put(attrs, "permissions", w.Permissions)
			put(attrs, "environments", w.Environments)
			if w.DefaultPermissions {
				attrs["permissions_default"] = "true"
			}
			r.add("github_workflow", attrs, repo.FullName, e.Path)
		}
	} else if res.Status != http.StatusNotFound {
		return fmt.Errorf("githubscan: workflow listing of %s answered %d", repo.FullName, res.Status)
	}
	// Committed MCP configuration, by name only: one finding per file.
	for _, p := range MCPConfigPaths {
		raw, state, err := file(p)
		if err != nil {
			return err
		}
		switch state {
		case absent:
			continue
		case unread:
			r.skip("mcp_configs", "too large or not plain files", 1)
			continue
		case present:
		}
		servers, err := ParseMCPConfig(raw)
		clear(raw)
		if err != nil {
			r.skip("mcp_configs", "not strict JSON (comments, trailing commas) or not a configuration", 1)
			continue
		}
		r.Counts["mcp_configs"]++
		r.Counts["mcp_servers"] += int64(len(servers))
		var names, commands, transports, env, headers []string
		for _, s := range servers {
			names = append(names, s.Name)
			commands, transports = appendNew(commands, s.Command), appendNew(transports, s.Transport)
			for _, e := range s.Env {
				env = appendNew(env, e)
			}
			for _, h := range s.Headers {
				headers = appendNew(headers, h)
			}
		}
		attrs := map[string]string{"repo": repo.FullName, "path": p}
		put(attrs, "servers", names)
		put(attrs, "commands", commands)
		put(attrs, "transports", transports)
		put(attrs, "env", env)
		put(attrs, "headers", headers)
		r.add("github_mcp_config", attrs, repo.FullName, p)
	}
	return nil
}

// appendNew appends v unless it is empty or there.
func appendNew(list []string, v string) []string {
	if v == "" || slices.Contains(list, v) {
		return list
	}
	return append(list, v)
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

// put sets attrs[key] to list as one attribute; when the list did not fit,
// key_incomplete says so (HR-209: nothing is cut silently).
func put(attrs map[string]string, key string, list []string) {
	s, cut := joined(list)
	if s != "" {
		attrs[key] = s
	}
	if cut {
		attrs[key+"_incomplete"] = "true"
	}
}

// joined is a list as one attribute, at most 256 bytes, cut at a name, and
// whether it was cut. Lists come most important first.
func joined(list []string) (string, bool) {
	s := ""
	for _, v := range list {
		if len(s)+len(v)+1 > 256 {
			return s, true
		}
		if s != "" {
			s += ","
		}
		s += v
	}
	return s, false
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

// maxPages bounds a listing the scan pages through: 5 pages of 100.
const maxPages = 5

// ListRepositories reads the repositories an installation token reaches
// (GET /installation/repositories), at most 500, and whether that was all
// of them.
func ListRepositories(ctx context.Context, get Getter) ([]Repository, bool, error) {
	var out []Repository
	for page := 1; page <= maxPages; page++ {
		res, err := get(ctx, "/installation/repositories?per_page=100&page="+strconv.Itoa(page))
		if err != nil {
			return nil, false, err
		}
		var list struct {
			Repositories []struct {
				FullName      string `json:"full_name"`
				DefaultBranch string `json:"default_branch"`
			} `json:"repositories"`
		}
		if res.Status != http.StatusOK || json.Unmarshal(res.Body, &list) != nil {
			return nil, false, fmt.Errorf("githubscan: the installation's repositories answered %d", res.Status)
		}
		for _, r := range list.Repositories {
			out = append(out, Repository{FullName: strings.ToLower(r.FullName), DefaultBranch: r.DefaultBranch})
		}
		if len(list.Repositories) < 100 {
			return out, true, nil
		}
	}
	return out, false, nil
}

// Apps reads the other Apps installed on the organization (GET
// /orgs/{org}/installations, at most 500), each a github_app finding: its
// app_slug, app_id, permissions (the ones that may write first) and
// repository_selection; and whether that was all of them.
func Apps(ctx context.Context, get Getter, org string) ([]Finding, bool, error) {
	var r Result
	for page := 1; page <= maxPages; page++ {
		res, err := get(ctx, "/orgs/"+url.PathEscape(org)+"/installations?per_page=100&page="+strconv.Itoa(page))
		if err != nil {
			return nil, false, err
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
			return nil, false, fmt.Errorf("githubscan: the organization's installations answered %d", res.Status)
		}
		for _, in := range list.Installations {
			perms := make([]string, 0, len(in.Permissions))
			for k, v := range in.Permissions {
				perms = append(perms, clip(k)+":"+clip(v))
			}
			slices.SortFunc(perms, func(a, b string) int {
				if c := permissionRank(a) - permissionRank(b); c != 0 {
					return c
				}
				return strings.Compare(a, b)
			})
			attrs := map[string]string{
				"organization": org, "app_slug": clip(in.AppSlug), "app_id": strconv.FormatInt(in.AppID, 10),
				"repository_selection": clip(in.Selection),
			}
			put(attrs, "permissions", perms)
			r.add("github_app", attrs, org, strconv.FormatInt(in.AppID, 10))
		}
		if len(list.Installations) < 100 {
			return r.Findings, true, nil
		}
	}
	return r.Findings, false, nil
}
