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
// channel reader, with one token minted for the read, reports a channel
// with a member of another tenant external and one of the home tenant's own
// people internal; a channel wholly in another tenant is external whatever
// tenant the agent names, since the home tenant is pinned by the sealed
// token endpoint (D273); a channel the bot was never added to, an id the
// post's pattern refuses and a credential that pins no tenant are unread,
// never internal (HR-160).
// Covers: T-226, HR-524
func TestT226_TheGatewayReadsWhetherATeamsChannelIsExternal(t *testing.T) {
	s := teams.New(sim.TeamsChannels(), teams.Faults{}, slog.New(slog.DiscardHandler))
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	plain, err := credentials.OAuthClient{
		V: 1, TokenURL: srv.URL + "/" + teams.TenantID + "/oauth2/v2.0/token", ClientID: teams.AppID, Scope: teams.Scope, ClientSecret: []byte("bot~secret"),
	}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	p, err := manifest.Decode(pcteams.Package)
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{
		broker: &plainOpener{plain: plain}, allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		clients: map[string]clientEntry{}, tokenClients: map[string]clientEntry{}, log: pclog.Discard(),
	}
	conn := &control.Connection{
		GatewayConnection: &pb.GatewayConnection{Id: "c", Kind: "http", BaseUrl: srv.URL + "/teams"}, Package: p,
		Credential: &pb.SealedCredential{Kind: credentials.KindOAuthClient, AllowedHosts: []string{u.Host}, Header: "Authorization", Scheme: "Bearer"},
	}
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
	if s.Issued() != 3 || s.Calls()["conversation.members"] != 3 {
		t.Fatalf("issued %d, member reads %d", s.Issued(), s.Calls()["conversation.members"])
	}

	// A channel wholly in tenant B, with the agent naming B: external,
	// without a read, because the pin is the home tenant (D273).
	partnerOnly := "19:partneronly000000000000000000000@thread.tacv2"
	s.SetChannel(teams.Channel{ID: partnerOnly, Name: "partner", Installed: true, Members: []teams.Member{
		{ID: "29:p", Name: "P", TenantID: teams.OtherTenantID, UserRole: "user"},
	}})
	v := e.readTeamsChannel(context.Background(), conn, def, actionir.Target{Type: "teams_channel", ID: partnerOnly, Account: teams.OtherTenantID})
	if v["external"] != true || v["home_tenant"] != false {
		t.Fatalf("a channel of tenant B named as B: %v", v)
	}

	// One token serves every page of a read.
	var many []teams.Member
	for range 1200 {
		many = append(many, teams.Member{ID: "29:o", Name: "O", TenantID: teams.TenantID, UserRole: "user"})
	}
	big := "19:bigchannel0000000000000000000000@thread.tacv2"
	s.SetChannel(teams.Channel{ID: big, Name: "big", Installed: true, Members: many})
	issued := s.Issued()
	if v := read(big); v["external"] != false || v["members"] != 1200 {
		t.Fatalf("big channel: %v", v)
	}
	if s.Issued() != issued+1 {
		t.Fatalf("%d tokens for one three-page read", s.Issued()-issued)
	}

	// A credential that pins no tenant (the multi-tenant endpoint) reads
	// nothing: the fact is unread, never internal.
	multi, err := credentials.OAuthClient{
		V: 1, TokenURL: srv.URL + "/botframework.com/oauth2/v2.0/token", ClientID: teams.AppID, Scope: teams.Scope, ClientSecret: []byte("bot~secret"),
	}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	e.broker = &plainOpener{plain: multi}
	if v := read(sim.TeamsGeneral); v["unread"] == nil {
		t.Fatalf("no pinned tenant: %v", v)
	}
}
