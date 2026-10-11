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
	credentials "github.com/katocxl/pantherclaw/internal/credentials/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
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
// nothing it could not read: the decision then sees the fact missing,
// which is CANNOT_AUTHORIZE for a prerequisite and "Consequence unknown"
// for a consequence (HR-206). It never fails the call itself, and
// reports whether it read.
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
	c, err := e.client(conn)
	if err != nil {
		warn("gateway.facts_unavailable", err)
		return true
	}
	tok, err := e.mint(read, conn, s.Owner, s.Repo, githubfacts.Scopes, c)
	if err != nil {
		warn("gateway.facts_unavailable", err)
		return true
	}
	defer func() {
		if err := tok.Revoke(context.WithoutCancel(ctx), c); err != nil {
			warn("gateway.installation_token_not_revoked", err)
		}
	}()
	base := strings.TrimSuffix(conn.GetBaseUrl(), "/")
	get := func(ctx context.Context, path string) (egress.Response, error) {
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
	if s.Branch != "" && s.At == "" {
		// A contents write: its files are the branch's with the write
		// applied, and it never writes under .github/, so the workflows
		// are the branch head's.
		if s.At, err = githubfacts.BranchHead(read, get, s.Owner, s.Repo, s.Branch); err != nil {
			warn("gateway.facts_unavailable", err)
			return true
		}
	}
	var obs []*pb.FactObservation
	for _, f := range githubfacts.Read(read, get, s, names) {
		raw, err := json.Marshal(map[string]any{"object": f.Value}, json.Deterministic(true))
		if err != nil {
			continue
		}
		obs = append(obs, &pb.FactObservation{Name: f.Name, SubjectType: a.Target.Type, SubjectId: a.Target.ID, Value: raw, ObserveTime: observed})
	}
	if len(obs) == 0 {
		return true
	}
	if err := e.reportFacts(ctx, conn.GetId(), obs); err != nil {
		warn("gateway.facts_not_reported", err)
	}
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
	plain, err := e.openCredential(conn)
	if err != nil {
		return nil, err
	}
	app, err := credentials.DecodeGitHubApp(plain)
	clear(plain)
	defer app.Clear()
	if err != nil {
		return nil, err
	}
	return broker.MintInstallationToken(ctx, c, conn.GetBaseUrl(), conn.Credential.GetAllowedHosts(), app, owner, repo, scopes, time.Now())
}
