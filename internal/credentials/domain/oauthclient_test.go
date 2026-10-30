// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"strings"
	"testing"
)

func validOAuthClient() OAuthClient {
	return OAuthClient{
		V: 1, TokenURL: "https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token",
		ClientID: "00000000-0000-4000-8000-0000000000b0", Scope: "https://api.botframework.com/.default", ClientSecret: []byte("abc~DEF.123"),
	}
}

func TestOAuthClientRoundTrip(t *testing.T) {
	plain, err := validOAuthClient().Encode()
	if err != nil {
		t.Fatal(err)
	}
	o, err := DecodeOAuthClient(plain)
	if err != nil || string(o.ClientSecret) != "abc~DEF.123" {
		t.Fatalf("%+v %v", o, err)
	}
	o.Clear()
	if strings.Trim(string(o.ClientSecret), "\x00") != "" {
		t.Fatal("secret not cleared")
	}
}

// TestHR524_AnOAuthClientCredentialIsCheckedWhole: every field is
// checked, and an unknown member is refused.
// Covers: HR-524
func TestHR524_AnOAuthClientCredentialIsCheckedWhole(t *testing.T) {
	for name, mut := range map[string]func(*OAuthClient){
		"version":      func(o *OAuthClient) { o.V = 2 },
		"scheme":       func(o *OAuthClient) { o.TokenURL = "ftp://login.microsoftonline.com/token" },
		"userinfo":     func(o *OAuthClient) { o.TokenURL = "https://u:p@login.microsoftonline.com/token" },
		"query":        func(o *OAuthClient) { o.TokenURL = "https://login.microsoftonline.com/token?x=1" },
		"no host":      func(o *OAuthClient) { o.TokenURL = "https:///token" },
		"client id":    func(o *OAuthClient) { o.ClientID = "a b" },
		"scope space":  func(o *OAuthClient) { o.Scope = "a b" },
		"empty secret": func(o *OAuthClient) { o.ClientSecret = nil },
		"secret space": func(o *OAuthClient) { o.ClientSecret = []byte("a b") },
	} {
		o := validOAuthClient()
		mut(&o)
		if _, err := o.Encode(); !errors.Is(err, ErrOAuthClient) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := DecodeOAuthClient([]byte(`{"v":1,"token_url":"https://h/t","client_id":"a","scope":"s","client_secret":"YQ==","extra":1}`)); err == nil {
		t.Error("unknown member accepted")
	}
	if !ValidKind(KindOAuthClient) || !Minted(KindOAuthClient) || Minted(KindStatic) {
		t.Error("kind")
	}
}

func TestOAuthClientBindsItsKind(t *testing.T) {
	b := Binding{Org: "o", Connection: "c", Version: 1, AllowedHosts: []string{"h"}, BrokerKey: "k", Header: "Authorization", Scheme: "Bearer"}
	static := string(b.Info())
	b.Kind = KindOAuthClient
	if got := string(b.Info()); got == static || !strings.Contains(got, "kind=oauth_client\n") {
		t.Fatalf("info %q", got)
	}
}

// TestHR524_TheHomeTenantIsPinnedByTheTokenEndpoint: the home tenant is the
// tenant of a single-tenant token endpoint, and none for the multi-tenant
// one or any other path (D273).
// Covers: HR-524
func TestHR524_TheHomeTenantIsPinnedByTheTokenEndpoint(t *testing.T) {
	for url, want := range map[string]string{
		"https://login.microsoftonline.com/5a1e0000-0000-4000-8000-000000000001/oauth2/v2.0/token": "5a1e0000-0000-4000-8000-000000000001",
		"https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token":                     "",
		"https://login.microsoftonline.com/5A1E0000-0000-4000-8000-000000000001/oauth2/v2.0/token": "",
		"https://login.microsoftonline.com/token":                                                  "",
	} {
		o := validOAuthClient()
		o.TokenURL = url
		if got := o.Tenant(); got != want {
			t.Errorf("%s: %q", url, got)
		}
	}
}
