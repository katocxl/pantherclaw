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
	"github.com/katocxl/pantherclaw/internal/gateway/slackfacts"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// slackChannelRead is the read whose definition (credential pattern) a
// Slack fact read goes by.
const slackChannelRead = "slack.channel.read"

// needsSlackFacts reports whether def's prerequisites or its package's
// consequence rules name slack.channel.external.
func needsSlackFacts(conn *control.Connection, def *defs.Definition) bool {
	for _, p := range def.Prerequisites {
		if p.Fact == slackfacts.ChannelExternal {
			return true
		}
	}
	for _, c := range conn.Package.Consequences {
		if c.Operation == def.Operation {
			for _, f := range c.RequiresFacts {
				if f == slackfacts.ChannelExternal {
					return true
				}
			}
		}
	}
	return false
}

// reportSlackFacts reads slack.channel.external for an action's channel
// with conversations.info and the connection's bot token, within the fact
// timeout, and reports it before the decision (G0 M14 D25, HR-160,
// HR-316). A channel it could not read is reported unread, so the server
// counts the fact missing: never an internal channel. It reports whether
// it tried, and unreported when the report itself failed (as
// reportGitHubFacts).
func (e *Engine) reportSlackFacts(ctx context.Context, conn *control.Connection, a actionir.ActionIR) (tried bool, unreported error) {
	if e.reportFacts == nil || conn.Package == nil || conn.GetKind() != "http" {
		return false, nil
	}
	def, ok := conn.Package.Definition(a.Operation)
	if !ok || !needsSlackFacts(conn, def) {
		return false, nil
	}
	read, cancel := context.WithTimeout(ctx, e.factTimeout)
	defer cancel()
	value := e.readSlackChannel(read, conn, a.Target)
	raw, err := json.Marshal(map[string]any{"object": value}, json.Deterministic(true))
	if err != nil {
		return true, nil
	}
	obs := []*pb.FactObservation{{
		Name: slackfacts.ChannelExternal, SubjectType: a.Target.Type, SubjectId: a.Target.ID, Value: raw, ObserveTime: timestamppb.New(time.Now()),
	}}
	if err := e.reportFacts(ctx, conn.GetId(), obs); err != nil {
		e.log.WarnContext(ctx, "gateway.facts_not_reported", slog.String("connection_id", conn.GetId()), slog.String("operation", a.Operation),
			pclog.Err(err))
		return true, err
	}
	return true, nil
}

// readSlackChannel reads one channel; any failure is an unread value.
func (e *Engine) readSlackChannel(ctx context.Context, conn *control.Connection, target actionir.Target) map[string]any {
	warn := func(err error) {
		e.log.WarnContext(ctx, "gateway.facts_unavailable", slog.String("connection_id", conn.GetId()), pclog.Err(err))
	}
	readDef, ok := conn.Package.Definition(slackChannelRead)
	if !ok {
		return slackfacts.Unread("the package has no channel read")
	}
	c, err := e.client(conn)
	if err != nil {
		warn(err)
		return slackfacts.Unread("no Slack client")
	}
	u, err := url.Parse(strings.TrimSuffix(conn.GetBaseUrl(), "/") + "/conversations.info?" + url.Values{"channel": {target.ID}}.Encode())
	if err != nil {
		return slackfacts.Unread("no Slack URL")
	}
	req, err := c.HTTPRequest(ctx, egress.Request{Method: http.MethodGet, URL: u})
	if err != nil {
		warn(err)
		return slackfacts.Unread("no Slack request")
	}
	_, release, _, err := e.credential(ctx, conn, readDef, target, req, c, "facts")
	if err != nil {
		warn(err)
		return slackfacts.Unread("the bot token could not be used")
	}
	defer release()
	resp, err := c.Do(req)
	if err != nil {
		warn(err)
		return slackfacts.Unread("Slack could not be reached")
	}
	return slackfacts.Channel(resp.Status, resp.Body, target.ID)
}
