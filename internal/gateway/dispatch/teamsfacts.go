// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"encoding/json/v2"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/gateway/teamsfacts"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// teamsChannelRead is the read whose definition a Teams fact read goes by.
const teamsChannelRead = "teams.channel.read"

// needsTeamsFacts reports whether def's prerequisites or its package's
// consequence rules name teams.channel.external.
func needsTeamsFacts(conn *control.Connection, def *defs.Definition) bool {
	for _, p := range def.Prerequisites {
		if p.Fact == teamsfacts.ChannelExternal {
			return true
		}
	}
	for _, c := range conn.Package.Consequences {
		if c.Operation == def.Operation {
			for _, f := range c.RequiresFacts {
				if f == teamsfacts.ChannelExternal {
					return true
				}
			}
		}
	}
	return false
}

// reportTeamsFacts reads teams.channel.external for an action's channel
// from the Bot Connector's paged members, with a token minted for the read,
// within the fact timeout, and reports it before the decision (G0 M20
// D254, HR-160, HR-524). A channel it could not read whole is reported
// unread, so the server counts the fact missing: never an internal
// channel. It reports whether it tried, and unreported when the report
// itself failed (as reportSlackFacts).
func (e *Engine) reportTeamsFacts(ctx context.Context, conn *control.Connection, a actionir.ActionIR) (tried bool, unreported error) {
	if e.reportFacts == nil || conn.Package == nil || conn.GetKind() != "http" {
		return false, nil
	}
	def, ok := conn.Package.Definition(a.Operation)
	if !ok || !needsTeamsFacts(conn, def) {
		return false, nil
	}
	read, cancel := context.WithTimeout(ctx, e.factTimeout)
	defer cancel()
	value := e.readTeamsChannel(read, conn, a.Target)
	raw, err := json.Marshal(map[string]any{"object": value}, json.Deterministic(true))
	if err != nil {
		return true, nil
	}
	obs := []*pb.FactObservation{{
		Name: teamsfacts.ChannelExternal, SubjectType: a.Target.Type, SubjectId: a.Target.ID, Value: raw, ObserveTime: timestamppb.New(time.Now()),
	}}
	if err := e.reportFacts(ctx, conn.GetId(), obs); err != nil {
		e.log.WarnContext(ctx, "gateway.facts_not_reported", slog.String("connection_id", conn.GetId()), slog.String("operation", a.Operation),
			pclog.Err(err))
		return true, err
	}
	return true, nil
}

// readTeamsChannel reads every page of one channel's members; any failure
// is an unread value.
func (e *Engine) readTeamsChannel(ctx context.Context, conn *control.Connection, target actionir.Target) map[string]any {
	warn := func(err error) {
		e.log.WarnContext(ctx, "gateway.facts_unavailable", slog.String("connection_id", conn.GetId()), pclog.Err(err))
	}
	readDef, ok := conn.Package.Definition(teamsChannelRead)
	if !ok {
		return teamsfacts.Unread("the package has no channel read")
	}
	if !readDef.Target.MatchID(target.ID) || !readDef.Target.MatchAccount(target.Account) || target.Account == "" {
		return teamsfacts.Unread("not a Teams channel of a tenant")
	}
	c, err := e.client(conn)
	if err != nil {
		warn(err)
		return teamsfacts.Unread("no Teams client")
	}
	var tally teamsfacts.Tally
	next := ""
	for range teamsfacts.MaxPages {
		q := url.Values{"pageSize": {strconv.Itoa(teamsfacts.PageSize)}}
		if next != "" {
			q.Set("continuationToken", next)
		}
		// The channel id is the target's, checked against the read's
		// anchored pattern above, and escaped as one path segment.
		u, err := url.Parse(strings.TrimSuffix(conn.GetBaseUrl(), "/") + "/v3/conversations/" + url.PathEscape(target.ID) + "/pagedmembers?" + q.Encode())
		if err != nil {
			return teamsfacts.Unread("no Teams URL")
		}
		req, err := c.HTTPRequest(ctx, egress.Request{Method: http.MethodGet, URL: u})
		if err != nil {
			warn(err)
			return teamsfacts.Unread("no Teams request")
		}
		_, release, _, err := e.credential(ctx, conn, readDef, target, req, c, "facts")
		if err != nil {
			warn(err)
			return teamsfacts.Unread("the bot's token could not be minted")
		}
		resp, err := c.Do(req)
		release()
		if err != nil {
			warn(err)
			return teamsfacts.Unread("Teams could not be reached")
		}
		var why string
		if next, why = tally.Page(resp.Status, resp.Body, target.Account); why != "" {
			return teamsfacts.Unread(why)
		}
		if next == "" {
			return tally.Value()
		}
	}
	return teamsfacts.Unread("the channel has more members than one read lists")
}
