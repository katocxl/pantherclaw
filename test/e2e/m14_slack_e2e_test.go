// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"net/http/httptest"
	"regexp"
	"testing"

	credapp "github.com/katocxl/pantherclaw/internal/credentials/app"
	creddomain "github.com/katocxl/pantherclaw/internal/credentials/domain"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
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
