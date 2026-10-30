// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	credentials "github.com/katocxl/pantherclaw/internal/credentials/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/sim/teams"
)

// plainOpener opens every credential to one plaintext, recording the kind
// it was asked to open.
type plainOpener struct {
	plain []byte
	kinds []string
}

func (o *plainOpener) Open(_, _ string, _ []string, s broker.Sealed) ([]byte, error) {
	o.kinds = append(o.kinds, s.Kind)
	return append([]byte(nil), o.plain...), nil
}

// TestHR524_TheDispatchPlacesAMintedTokenNeverTheSecret: an oauth_client
// connection's request gets "Bearer <a token minted for it>", never the
// client secret; each dispatch mints its own; the token is cleared on
// release; the secret is never opened as a static credential or placed,
// and a definition's credential pattern refuses the kind.
// Covers: HR-524
func TestHR524_TheDispatchPlacesAMintedTokenNeverTheSecret(t *testing.T) {
	sim := teams.New([]teams.Channel{{ID: teams.TeamID, Name: "General", Installed: true}}, teams.Faults{}, slog.New(slog.DiscardHandler)).
		WithRequire(teams.Require{ClientID: teams.AppID, ClientSecret: "client~secret"})
	srv := httptest.NewServer(sim.Handler())
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	plain, err := credentials.OAuthClient{
		V: 1, TokenURL: srv.URL + "/" + teams.TenantID + "/oauth2/v2.0/token", ClientID: teams.AppID, Scope: teams.Scope,
		ClientSecret: []byte("client~secret"),
	}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	opener := &plainOpener{plain: plain}
	e := &Engine{broker: opener, allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, tokenClients: map[string]clientEntry{}, log: pclog.Discard()}
	conn := &control.Connection{GatewayConnection: &pb.GatewayConnection{Id: "c", BaseUrl: srv.URL + "/teams"}, Credential: &pb.SealedCredential{
		Kind: credentials.KindOAuthClient, AllowedHosts: []string{u.Host}, Header: "Authorization", Scheme: "Bearer",
	}}
	def := &defs.Definition{Operation: "teams.channel.read", Access: defs.AccessRead}
	var tokens []string
	for range 2 {
		req := httptest.NewRequest(http.MethodGet, srv.URL+"/teams/v3/teams/x/conversations", nil)
		secret, release, _, err := e.credential(context.Background(), conn, def, actionir.Target{}, req, nil, "")
		if err != nil {
			t.Fatal(err)
		}
		got := req.Header.Get("Authorization")
		if !strings.HasPrefix(got, "Bearer simtok-") || strings.Contains(got, "client~secret") || got != "Bearer "+string(secret) {
			t.Fatalf("placed %q", got)
		}
		tokens = append(tokens, got)
		release()
		if strings.Trim(string(secret), "\x00") != "" {
			t.Fatal("token not cleared on release")
		}
	}
	if tokens[0] == tokens[1] || sim.Issued() != 2 {
		t.Fatalf("tokens %v, issued %d: want one per dispatch", tokens, sim.Issued())
	}
	if _, err := e.openStatic(context.Background(), conn); !errors.Is(err, errKind) {
		t.Fatalf("the client secret was opened as a static credential: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, srv.URL+"/teams/v3/conversations", nil)
	if err := placeCredential(conn, req, []byte("client~secret")); !errors.Is(err, errKind) || req.Header.Get("Authorization") != "" {
		t.Fatalf("the client secret was placed: %v", err)
	}
	patterned := &defs.Definition{Operation: "x.y", Dispatch: &defs.Dispatch{CredentialPattern: "^.*$"}}
	if _, _, _, err := e.credential(context.Background(), conn, patterned, actionir.Target{}, req, nil, ""); !errors.Is(err, ErrCredentialPattern) {
		t.Fatalf("a credential pattern accepted an oauth_client: %v", err)
	}
	for _, k := range opener.kinds {
		if k != credentials.KindOAuthClient {
			t.Fatalf("opened as %q", k)
		}
	}
	sim.SetFaults(teams.Faults{InvalidClient: true})
	req = httptest.NewRequest(http.MethodGet, srv.URL+"/teams/v3/conversations", nil)
	if _, _, _, err := e.credential(context.Background(), conn, def, actionir.Target{}, req, nil, ""); !errors.Is(err, broker.ErrClientToken) ||
		req.Header.Get("Authorization") != "" {
		t.Fatalf("a refused client: %v", err)
	}
}
