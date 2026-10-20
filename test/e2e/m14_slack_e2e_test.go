// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	credapp "github.com/katocxl/pantherclaw/internal/credentials/app"
	creddomain "github.com/katocxl/pantherclaw/internal/credentials/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
	"github.com/katocxl/pantherclaw/internal/sim/slack"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Simulated Slack channels (G0 M14 D24): approvals and outside are internal
// to the workspace, external is shared with another organization.
const (
	slackApprovals = "C0APPROVAL1"
	slackExternal  = "C0EXTERNAL1"
	slackOutside   = "C0OUTSIDE01"
	// slackBotToken is the bot token the simulator accepts and the gateway
	// holds for the agent-side connection; a test value, not a real token.
	slackBotToken = "xoxb-simulated-e2e-agent-token"
)

var seededSlack = regexp.MustCompile(`seeded slack connection ([0-9a-f-]{36}) `)

// slackSim is the Slack simulator of a stack and the seeded connection
// "slack" to it.
type slackSim struct {
	sim  *slack.Server
	url  string
	conn ids.UUID
}

func startSlackSim(t *testing.T) *slackSim {
	t.Helper()
	sim := slack.New([]slack.Channel{
		{ID: slackApprovals, Name: "approvals", Member: true},
		{ID: slackExternal, Name: "partner-shared", Member: true, ExtShared: true, Shared: true},
		{ID: slackOutside, Name: "general", Member: true},
	}, slack.Faults{}, pclog.Discard()).WithRequire(slack.Require{Token: slackBotToken})
	srv := httptest.NewServer(sim.Handler())
	t.Cleanup(srv.Close)
	return &slackSim{sim: sim, url: srv.URL}
}

// seeded reads the connection dev seed made from its output.
func (s *slackSim) seeded(t *testing.T, out string) {
	t.Helper()
	m := seededSlack.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("dev seed output %q", out)
	}
	s.conn = mustUUID(t, m[1])
}

// sealFor seals a static secret for conn, as a gateway admin does with
// pclaw seal, and returns the gateway configuration version that carries
// it.
func (s *stack) sealFor(t *testing.T, conn ids.UUID, secret string) int64 {
	t.Helper()
	// A gateway admin without a security key: an invalid test key would break
	// the approver keys export of a scenario that also approves.
	id := ids.NewV7()
	s.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'slack-gateway-admin')", s.org, id)
	admin := tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: s.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: id},
		Bindings: []td.Binding{{Role: td.RoleGatewayAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: s.org.UUID()}}},
	}, Credential: tapp.CredAccessToken})
	svc := credapp.New(s.pool, nil)
	k, err := svc.GetSealingKey(admin, conn)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := pccrypto.ParseSealPublicKey(k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := pccrypto.Seal(pub, k.Binding.Info(), creddomain.AAD, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PutCredential(admin, credapp.PutInput{
		Connection: conn, BrokerKey: mustUUID(t, k.Binding.BrokerKey), Version: k.Binding.Version, Sealed: sealed,
		AllowedHosts: k.Binding.AllowedHosts, Header: k.Binding.Header, Scheme: k.Binding.Scheme,
	}); err != nil {
		t.Fatal(err)
	}
	return s.configVersion(t, k.Gateway)
}

// slackPost has the scenario's agent post through the gateway's connection
// "slack" over the Web API route.
func (d *rangeDriver) slackPost(t *testing.T, channel, text string) domain.Observation {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"channel": channel, "text": text})
	obs, _, err := d.callOnce(callWith{Face: "http", Connection: "slack", Method: http.MethodPost, Path: "/chat.postMessage", Body: body}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	return obs
}

// TestE2E_M14_SlackApprovalCards is the M14 Slack exit scenario on the real
// stack (G0 M14 D24, D90). The e2e server is Community: adding a slack_app
// channel is refused there with EDITION_REQUIRED, nothing is stored and
// Slack is never asked; PantherClaw serves no Slack inbound route, so
// nothing sent "from Slack" reaches it (HR-313); and an agent posts through
// pc.slack with the bot token only the gateway holds, to an internal
// channel its grant names, never to a shared one or outside its
// destinations, and never when the channel cannot be read (HR-316). The
// card lifecycle needs the Team edition and runs in-process on a real
// database with the approvals service (internal/notifications/app,
// TestT145_*).
func TestE2E_M14_SlackApprovalCards(t *testing.T) {
	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", people: &p, slack: true})
	d := newRangeDriver(t)
	d.s, d.people = s, &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p}
	d.sc = domain.Scenario{ID: "M14-SLACK", Requires: []string{string(capSlackPost)}}
	d.bindRoles("grant_issuer", "run_launcher")
	d.admin.login(t, s.org.String(), "")

	// 1. Community: no slack_app channel, nothing stored, Slack not asked.
	rc := connect.NewClient(connecthttp.NewTransport(&http.Client{Timeout: 30 * time.Second, Transport: keyBearer{bearerOf(t, d.admin)}}, s.apiURL))
	notifications := pantherclawv1connect.NewNotificationServiceClient(rc)
	_, err := notifications.CreateChannel(context.Background(), &pantherclawv1.CreateChannelRequest{
		Name: "slack-approvals", Kind: pantherclawv1.ChannelKind_CHANNEL_KIND_SLACK_APP, EventTypes: []string{"approval.*"},
		SlackApp: &pantherclawv1.SlackAppConfig{ChannelId: slackApprovals, BotToken: slackBotToken},
	})
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "EDITION_REQUIRED") {
		t.Fatalf("a slack_app channel on Community: %v", err)
	}
	if n := s.row(t, "SELECT count(*)::text FROM pc.notification_channels WHERE kind = 'slack_app'"); n != "0" {
		t.Fatalf("%s slack_app channels stored", n)
	}
	if n := s.row(t, "SELECT count(*)::text FROM pc.slack_app_channels"); n != "0" {
		t.Fatalf("%s slack_app configurations stored", n)
	}
	if c := s.slack.sim.Calls(); c["auth.test"]+c["conversations.info"]+c["chat.postMessage"] != 0 {
		t.Fatalf("Slack was asked: %v", c)
	}

	// 2. No Slack inbound route, on the server or the gateway (HR-313).
	c := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, base := range []string{s.apiURL, s.gateway} {
		for _, path := range slackForgedPaths {
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				req, _ := http.NewRequest(method, base+path, strings.NewReader("payload=%7B%22type%22%3A%22block_actions%22%7D"))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				resp, err := c.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_ = resp.Body.Close()
				if resp.StatusCode < 400 {
					t.Fatalf("%s %s%s: %d, want a refusal", method, base, path, resp.StatusCode)
				}
			}
		}
	}

	// 3. An agent posts through pc.slack with the token the gateway holds.
	d.setupSlack()
	if obs := d.slackPost(t, slackApprovals, "Build e2e finished"); obs.Outcome != domain.OutcomeAllow {
		t.Fatalf("internal post: %+v", obs)
	}
	ms := s.slack.sim.Messages()
	if len(ms) != 1 || ms[0].Channel != slackApprovals || ms[0].Text != "Build e2e finished" {
		t.Fatalf("posted: %+v", ms)
	}
	for _, tok := range s.slack.sim.Tokens() {
		if tok != slackBotToken {
			t.Fatalf("Slack saw another token: %q", tok)
		}
	}
	for name, c := range map[string]struct {
		channel, reason string
		outcome         domain.Outcome
	}{
		"shared channel":     {slackExternal, "OPERATION_NOT_GRANTED", domain.OutcomeDeny},
		"outside the grant":  {slackOutside, "DESTINATION_NOT_GRANTED", domain.OutcomeDeny},
		"lowercase id":       {"c0approval1", "", ""},
		"channel unreadable": {slackApprovals, "FACT_MISSING", domain.OutcomeDeny},
	} {
		if name == "channel unreadable" {
			s.slack.sim.SetFaults(slack.Faults{ChannelNotFound: true})
		}
		obs := d.slackPost(t, c.channel, "Customer export "+name)
		s.slack.sim.SetFaults(slack.Faults{})
		switch {
		case c.outcome == "" && obs.Outcome == domain.OutcomeAllow:
			t.Fatalf("%s: allowed %+v", name, obs)
		case c.outcome != "" && (obs.Outcome != c.outcome || (c.reason != "" && !slices.Contains(obs.Reasons, c.reason))):
			t.Fatalf("%s: %+v, want %s %s", name, obs, c.outcome, c.reason)
		}
	}
	if n := len(s.slack.sim.Messages()); n != 1 {
		t.Fatalf("%d messages: only the internal post may reach Slack", n)
	}
}

// TestHR316_ASlackPostWithoutADestinationBoundIsDenied: pc.slack requires a
// destination set (D57, D78): a grant that names the agent's channels as
// targets but bounds no destinations lets it post nowhere, DENY
// DESTINATION_SET_REQUIRED, and nothing reaches Slack.
func TestHR316_ASlackPostWithoutADestinationBoundIsDenied(t *testing.T) {
	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", people: &p, slack: true})
	d := newRangeDriver(t)
	d.s, d.people = s, &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p}
	d.ownGrant(`{"operations": ["slack.message.post"], "targets": {"slack_channel": {"ids": ["`+slackApprovals+`"]}}}`, "")
	obs := d.slackPost(t, slackApprovals, "Build finished")
	if obs.Outcome != domain.OutcomeDeny || !slices.Contains(obs.Reasons, "DESTINATION_SET_REQUIRED") {
		t.Fatalf("a post without a destination bound: %+v", obs)
	}
	if n := len(s.slack.sim.Messages()); n != 0 {
		t.Fatalf("%d messages reached Slack", n)
	}
}
