// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"encoding/json/v2"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/gateway/jirafacts"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// jiraProjectRead is the read whose definition (credential pattern) a Jira
// fact read goes by: the package's connection test.
const jiraProjectRead = "jira.project.read"

// needsJiraFacts reports whether def's prerequisites or its package's
// consequence rules name fact.
func needsJiraFacts(conn *control.Connection, def *defs.Definition, fact string) bool {
	for _, p := range def.Prerequisites {
		if p.Fact == fact {
			return true
		}
	}
	for _, c := range conn.Package.Consequences {
		if c.Operation == def.Operation {
			for _, f := range c.RequiresFacts {
				if f == fact {
					return true
				}
			}
		}
	}
	return false
}

// reportJiraFacts reads the external fact of an action's issue or
// project with the connection's credential, within the fact timeout, and
// reports it before the decision (G0 M20 D254, HR-160, HR-522). What it
// could not read is reported unread, so the server counts the fact missing:
// never an internal project. It reports whether it tried, and unreported
// when the report itself failed (as reportSlackFacts).
func (e *Engine) reportJiraFacts(ctx context.Context, conn *control.Connection, a actionir.ActionIR) (tried bool, unreported error) {
	if e.reportFacts == nil || conn.Package == nil || conn.GetKind() != "http" {
		return false, nil
	}
	def, ok := conn.Package.Definition(a.Operation)
	fact := jirafacts.Fact(a.Target.Type)
	if !ok || fact == "" || !needsJiraFacts(conn, def, fact) {
		return false, nil
	}
	read, cancel := context.WithTimeout(ctx, e.factTimeout)
	defer cancel()
	value := e.readJira(read, conn, a.Target)
	raw, err := json.Marshal(map[string]any{"object": value}, json.Deterministic(true))
	if err != nil {
		return true, nil
	}
	obs := []*pb.FactObservation{{
		Name: fact, SubjectType: a.Target.Type, SubjectId: a.Target.ID, Value: raw, ObserveTime: timestamppb.New(time.Now()),
	}}
	if err := e.reportFacts(ctx, conn.GetId(), obs); err != nil {
		e.log.WarnContext(ctx, "gateway.facts_not_reported", slog.String("connection_id", conn.GetId()), slog.String("operation", a.Operation),
			pclog.Err(err))
		return true, err
	}
	return true, nil
}

// readJira reads the target's issue or project; any failure is an unread
// value.
func (e *Engine) readJira(ctx context.Context, conn *control.Connection, target actionir.Target) map[string]any {
	warn := func(err error) {
		e.log.WarnContext(ctx, "gateway.facts_unavailable", slog.String("connection_id", conn.GetId()), pclog.Err(err))
	}
	readDef, ok := conn.Package.Definition(jiraProjectRead)
	if !ok {
		return jirafacts.Unread("the package has no project read")
	}
	base := strings.TrimSuffix(conn.GetBaseUrl(), "/")
	var raw string
	switch target.Type {
	case jirafacts.IssueTarget:
		raw = base + "/rest/api/2/issue/" + url.PathEscape(target.ID) + "?" + url.Values{"fields": {"project,security"}}.Encode()
	case jirafacts.ProjectTarget:
		raw = base + "/rest/api/2/project/" + url.PathEscape(target.ID)
	default:
		return jirafacts.Unread("the target is neither an issue nor a project")
	}
	c, err := e.client(conn)
	if err != nil {
		warn(err)
		return jirafacts.Unread("no Jira client")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return jirafacts.Unread("no Jira URL")
	}
	req, err := c.HTTPRequest(ctx, egress.Request{Method: http.MethodGet, URL: u})
	if err != nil {
		warn(err)
		return jirafacts.Unread("no Jira request")
	}
	_, release, _, err := e.credential(ctx, conn, readDef, target, req, c, "facts")
	if err != nil {
		warn(err)
		return jirafacts.Unread("the credential could not be used")
	}
	defer release()
	resp, err := c.Do(req)
	if err != nil {
		warn(err)
		return jirafacts.Unread("Jira could not be reached")
	}
	if target.Type == jirafacts.ProjectTarget {
		return jirafacts.Project(resp.Status, resp.Body, target.ID)
	}
	return jirafacts.Issue(resp.Status, resp.Body, target.ID)
}
