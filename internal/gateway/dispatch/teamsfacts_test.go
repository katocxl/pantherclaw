// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	credentials "github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/sim"
	"github.com/katocxl/pantherclaw/internal/sim/teams"
	pcteams "github.com/katocxl/pantherclaw/packages/pc-teams"
)

// TestT226_TheGatewayReadsWhetherATeamsChannelIsExternal: the gateway's own
// channel reader, with a token minted for the read, reports a channel with
// a member of another tenant external and one of the tenant's own people
// internal; a channel the bot was never added to, and an id the post's
// pattern refuses, are unread, never internal (HR-160).
// Covers: T-226, HR-524
func TestT226_TheGatewayReadsWhetherATeamsChannelIsExternal(t *testing.T) {
	s := teams.New(sim.TeamsChannels(), teams.Faults{}, slog.New(slog.DiscardHandler))
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	plain, err := credentials.OAuthClient{
		V: 1, TokenURL: srv.URL + "/botframework.com/oauth2/v2.0/token", ClientID: teams.AppID, Scope: teams.Scope, ClientSecret: []byte("bot~secret"),
	}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	p, err := manifest.Decode(pcteams.Package)
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{broker: &plainOpener{plain: plain}, allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		clients: map[string]clientEntry{}, tokenClients: map[string]clientEntry{}, log: pclog.Discard()}
	conn := &control.Connection{GatewayConnection: &pb.GatewayConnection{Id: "c", Kind: "http", BaseUrl: srv.URL + "/teams"}, Package: p,
		Credential: &pb.SealedCredential{Kind: credentials.KindOAuthClient, AllowedHosts: []string{u.Host}, Header: "Authorization", Scheme: "Bearer"}}
	def, _ := p.Definition("teams.message.post")
	read := func(channel string) map[string]any {
		return e.readTeamsChannel(context.Background(), conn, def, actionir.Target{Type: "teams_channel", ID: channel, Account: teams.TenantID})
	}
	if v := read(sim.TeamsGeneral); v["external"] != false {
		t.Fatalf("General: %v", v)
	}
	if v := read(sim.TeamsExternal); v["external"] != true || v["other_tenant"] != true {
		t.Fatalf("shared: %v", v)
	}
	for _, ch := range []string{sim.TeamsOutside, "19:x/../y@thread.tacv2", "C0APPROVAL1"} {
		if v := read(ch); v["unread"] == nil {
			t.Fatalf("%s: %v", ch, v)
		}
	}
	if s.Issued() == 0 || s.Calls()["conversation.members"] != 3 {
		t.Fatalf("issued %d, member reads %d", s.Issued(), s.Calls()["conversation.members"])
	}
}
