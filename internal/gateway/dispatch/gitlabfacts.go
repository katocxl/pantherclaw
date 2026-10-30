// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"encoding/json/v2"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/gateway/gitlabfacts"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// gitlabProjectRead is the read whose definition (credential pattern) a
// GitLab fact read goes by: the package's connection test.
const gitlabProjectRead = "gitlab.project.read"

// needsGitLabFacts reports whether def's prerequisites name a GitLab fact.
func needsGitLabFacts(def *defs.Definition) bool {
	return slices.ContainsFunc(def.Prerequisites, func(p defs.Prerequisite) bool { return slices.Contains(gitlabfacts.Names, p.Fact) })
}

// reportGitLabFacts reads a merge request's head, approvals, head pipeline
// and target branch protection with the connection's token, within the
// fact timeout, and reports them before the decision (G0 M20 D254,
// HR-160, HR-521). What it could not read is reported unread, so the
// server counts the fact missing. It reports whether it tried, and
// unreported when the report itself failed (as reportSlackFacts).
func (e *Engine) reportGitLabFacts(ctx context.Context, conn *control.Connection, a actionir.ActionIR) (tried bool, unreported error) {
	if e.reportFacts == nil || conn.Package == nil || conn.GetKind() != "http" {
		return false, nil
	}
	def, ok := conn.Package.Definition(a.Operation)
	if !ok || !needsGitLabFacts(def) {
		return false, nil
	}
	read, cancel := context.WithTimeout(ctx, e.factTimeout)
	defer cancel()
	values := e.readGitLab(read, conn, def, a.Target)
	now := timestamppb.New(time.Now())
	var obs []*pb.FactObservation
	for _, name := range gitlabfacts.Names {
		raw, err := json.Marshal(map[string]any{"object": values[name]}, json.Deterministic(true))
		if err != nil {
			return true, nil
		}
		obs = append(obs, &pb.FactObservation{Name: name, SubjectType: a.Target.Type, SubjectId: a.Target.ID, Value: raw, ObserveTime: now})
	}
	if err := e.reportFacts(ctx, conn.GetId(), obs); err != nil {
		e.log.WarnContext(ctx, "gateway.facts_not_reported", slog.String("connection_id", conn.GetId()), slog.String("operation", a.Operation),
			pclog.Err(err))
		return true, err
	}
	return true, nil
}

// readGitLab reads the merge request the target names: every fact is
// unread when anything before its own read failed.
func (e *Engine) readGitLab(ctx context.Context, conn *control.Connection, def *defs.Definition, target actionir.Target) map[string]map[string]any {
	out := map[string]map[string]any{}
	unread := func(why string) map[string]map[string]any {
		for _, n := range gitlabfacts.Names {
			if out[n] == nil {
				out[n] = gitlabfacts.Unread(why)
			}
		}
		return out
	}
	warn := func(err error) {
		e.log.WarnContext(ctx, "gateway.facts_unavailable", slog.String("connection_id", conn.GetId()), pclog.Err(err))
	}
	readDef, ok := conn.Package.Definition(gitlabProjectRead)
	if !ok {
		return unread("the package has no project read")
	}
	ps, okP := def.Target.Part(target.ID, "project")
	is, okI := def.Target.Part(target.ID, "iid")
	project, errP := strconv.Atoi(ps)
	iid, errI := strconv.Atoi(is)
	if !okP || !okI || errP != nil || errI != nil {
		return unread("the target is not a merge request")
	}
	c, err := e.client(conn)
	if err != nil {
		warn(err)
		return unread("no GitLab client")
	}
	base := strings.TrimSuffix(conn.GetBaseUrl(), "/") + "/api/v4/projects/" + ps
	get := func(raw string) (int, []byte, string) {
		u, err := url.Parse(raw)
		if err != nil {
			return 0, nil, "no GitLab URL"
		}
		req, err := c.HTTPRequest(ctx, egress.Request{Method: http.MethodGet, URL: u})
		if err != nil {
			warn(err)
			return 0, nil, "no GitLab request"
		}
		_, release, _, err := e.credential(ctx, conn, readDef, target, req, c, "facts")
		if err != nil {
			warn(err)
			return 0, nil, "the access token could not be used"
		}
		defer release()
		resp, err := c.Do(req)
		if err != nil {
			warn(err)
			return 0, nil, "GitLab could not be reached"
		}
		return resp.Status, resp.Body, ""
	}
	mrURL := base + "/merge_requests/" + is
	status, body, why := get(mrURL)
	if why != "" {
		return unread(why)
	}
	mr := gitlabfacts.ParseMergeRequest(status, body, project, iid)
	out[gitlabfacts.MergeRequestHead], out[gitlabfacts.MergeRequestPipeline] = mr.Head, mr.Pipeline
	if status, body, why = get(mrURL + "/approvals"); why != "" {
		return unread(why)
	}
	out[gitlabfacts.MergeRequestApprovals] = gitlabfacts.Approvals(status, body, project, iid)
	if mr.TargetBranch == "" {
		return unread("the merge request's target branch was not read")
	}
	if status, body, why = get(base + "/protected_branches/" + url.PathEscape(mr.TargetBranch)); why != "" {
		return unread(why)
	}
	out[gitlabfacts.BranchProtection] = gitlabfacts.Protection(status, body, mr.TargetBranch)
	return out
}
