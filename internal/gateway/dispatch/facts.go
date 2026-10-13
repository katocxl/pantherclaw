// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"encoding/json/v2"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/actionir"
	credentials "github.com/katocxl/pantherclaw/internal/credentials/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/githubfacts"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// FactReporter reports what the gateway read about an action's target as
// the connection's fact provider (GatewayService.ReportFacts).
type FactReporter func(ctx context.Context, connection string, obs []*pb.FactObservation) error

// DefaultFactTimeout bounds the fact reads before a decision (gateway
// configuration github.fact_timeout).
const DefaultFactTimeout = 2 * time.Second

// githubFactNames are the github.* facts an operation's prerequisites and
// its package's consequence rules name, in that order.
func githubFactNames(conn *control.Connection, def *defs.Definition) []string {
	var names []string
	add := func(n string) {
		if strings.HasPrefix(n, "github.") && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	for _, p := range def.Prerequisites {
		add(p.Fact)
	}
	for _, c := range conn.Package.Consequences {
		if c.Operation == def.Operation {
			for _, f := range c.RequiresFacts {
				add(f)
			}
		}
	}
	return names
}

// reportGitHubFacts reads the github.* facts an action needs with a
// read-only installation token of its own, within the fact timeout, and
// reports them before the decision (G0 M8 decision 5, HR-160). It reports
// no value it could not read: the decision then sees the fact missing,
// which is CANNOT_AUTHORIZE for a prerequisite and "Consequence unknown"
// for a consequence (HR-206). A deploy-trigger fact it could not read is
// reported unknown, so an earlier observation still fresh (a "none" read
// before a deploy workflow was pushed) is never what the decision uses. It
// never fails the call itself, and reports whether it read.
func (e *Engine) reportGitHubFacts(ctx context.Context, conn *control.Connection, a actionir.ActionIR) bool {
	if e.reportFacts == nil || conn.Credential.GetKind() != credentials.KindGitHubApp || conn.Package == nil {
		return false
	}
	def, ok := conn.Package.Definition(a.Operation)
	if !ok {
		return false
	}
	names := githubFactNames(conn, def)
	s, ok := subject(def, a)
	if len(names) == 0 || !ok {
		return false
	}
	// The reads are bounded; the report is the control plane's own call.
	read, cancel := context.WithTimeout(ctx, e.factTimeout)
	defer cancel()
	observed := timestamppb.New(time.Now())
	warn := func(event string, err error) {
		e.log.WarnContext(ctx, event, slog.String("connection_id", conn.GetId()), slog.String("operation", a.Operation), pclog.Err(err))
	}
	var obs []*pb.FactObservation
	add := func(name string, value map[string]any) {
		raw, err := json.Marshal(map[string]any{"object": value}, json.Deterministic(true))
		if err == nil {
			obs = append(obs, &pb.FactObservation{Name: name, SubjectType: a.Target.Type, SubjectId: a.Target.ID, Value: raw, ObserveTime: observed})
		}
	}
	// report sends what was read, with every deploy-trigger fact that was
	// not read as unknown.
	report := func(why string) {
		for _, n := range names {
			if (n == githubfacts.RepoTriggers || n == githubfacts.BranchTriggers) &&
				!slices.ContainsFunc(obs, func(o *pb.FactObservation) bool { return o.GetName() == n }) {
				add(n, githubfacts.Unread(s.Branch, s.At, why))
			}
		}
		if len(obs) == 0 {
			return
		}
		if err := e.reportFacts(ctx, conn.GetId(), obs); err != nil {
			warn("gateway.facts_not_reported", err)
		}
	}
	c, err := e.client(conn)
	if err != nil {
		warn("gateway.facts_unavailable", err)
		report("no GitHub client")
		return true
	}
	tok, err := e.mint(read, conn, s.Owner, s.Repo, githubfacts.Scopes, c)
	if err != nil {
		warn("gateway.facts_unavailable", err)
		report("no read token")
		return true
	}
	defer func() {
		if err := tok.Revoke(context.WithoutCancel(ctx), c); err != nil {
			warn("gateway.installation_token_not_revoked", err)
			e.revokeFailed(ctx, conn, "facts", tok)
		}
	}()
	get := tokenGetter(conn, c, tok)
	if s.Branch != "" && s.At == "" {
		// A contents write: its files are the branch's with the write
		// applied, and it never writes under .github/, so the workflows
		// are the branch head's.
		if s.At, err = githubfacts.BranchHead(read, get, s.Owner, s.Repo, s.Branch); err != nil {
			warn("gateway.facts_unavailable", err)
			report("the branch head was not read")
			return true
		}
	}
	for _, f := range githubfacts.Read(read, get, s, names) {
		add(f.Name, f.Value)
	}
	report("the workflows were not read")
	return true
}

// subject is what an action's facts are about, from its target's parts:
// a pull request, or a branch. For a branch creation, the branch will be
// at params.sha.
func subject(def *defs.Definition, a actionir.ActionIR) (githubfacts.Subject, bool) {
	part := func(g string) string { p, _ := def.Target.Part(a.Target.ID, g); return p }
	s := githubfacts.Subject{Owner: part("owner"), Repo: part("repo"), Branch: part("branch")}
	if n, err := strconv.Atoi(part("number")); err == nil {
		s.Number = n
	}
	if s.Branch != "" && def.Operation == "github.branch.create" {
		var p struct {
			SHA string `json:"sha"`
		}
		if json.Unmarshal(a.Params, &p) != nil || p.SHA == "" {
			return s, false
		}
		s.At = p.SHA
	}
	return s, s.Owner != "" && s.Repo != "" && (s.Number > 0 || s.Branch != "")
}

// mint opens the connection's GitHub App credential and mints a token for
// owner/repo with scopes.
func (e *Engine) mint(ctx context.Context, conn *control.Connection, owner, repo string, scopes map[string]string, c broker.Sender) (*broker.Installation, error) {
	app, err := e.openApp(conn)
	if err != nil {
		return nil, err
	}
	defer app.Clear()
	return broker.MintInstallationToken(ctx, c, conn.GetBaseUrl(), conn.Credential.GetAllowedHosts(), app, owner, repo, scopes, time.Now())
}
