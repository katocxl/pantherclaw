// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/json/v2"
	"errors"
	"testing"
)

// TestHR722_AnOAuthClientTokenEndpointIsAKnownProvidersOrALoopback: the
// provider is derived from the token URL: Microsoft's and Salesforce's
// endpoints, and a loopback simulator's, seal and open.
//
// Covers: HR-722
func TestHR722_AnOAuthClientTokenEndpointIsAKnownProvidersOrALoopback(t *testing.T) {
	for url, want := range map[string]string{
		"https://login.microsoftonline.com/5a1e0000-0000-4000-8000-000000000001/oauth2/v2.0/token": ProviderMicrosoft,
		"https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token":              ProviderMicrosoft,
		"https://acme-dev.my.salesforce.com/services/oauth2/token":                                 ProviderSalesforce,
		"http://127.0.0.1:9106/services/oauth2/token":                                              ProviderLoopback,
	} {
		o := validOAuthClient()
		o.Scope, o.TokenURL = "api", url
		if got, err := o.Provider(); err != nil || got != want {
			t.Errorf("%s: %q %v", url, got, err)
		}
		plain, err := o.Encode()
		if err != nil {
			t.Errorf("%s: seal: %v", url, err)
			continue
		}
		if _, err := DecodeOAuthClient(plain); err != nil {
			t.Errorf("%s: open: %v", url, err)
		}
	}
}

// TestHR722_AnOAuthClientWithAnotherTokenEndpointIsRefused: an endpoint
// outside the provider list (a look-alike host, another path, plain http
// to a public host) is refused when sealed, and a credential that holds
// one (sealed before D951, or forged) is refused again when the gateway
// opens it, so nothing is sent to it (T-331).
//
// Covers: HR-722, T-331
func TestHR722_AnOAuthClientWithAnotherTokenEndpointIsRefused(t *testing.T) {
	for _, url := range []string{
		"https://auth.example.com/token",
		"https://login.microsoftonline.com.attacker.example/x/oauth2/v2.0/token",
		"https://login.microsoftonline.com/x/oauth2/token",
		"https://acme.my.salesforce.com.attacker.example/services/oauth2/token",
		"https://acme.my.salesforce.com/services/oauth2/authorize",
		"http://acme.my.salesforce.com/services/oauth2/token",
	} {
		o := validOAuthClient()
		o.Scope, o.TokenURL = "api", url
		if _, err := o.Encode(); !errors.Is(err, ErrOAuthProvider) && !errors.Is(err, ErrOAuthClient) {
			t.Errorf("%s: sealed: %v", url, err)
		}
		forged, err := json.Marshal(o)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeOAuthClient(forged); !errors.Is(err, ErrOAuthClient) {
			t.Errorf("%s: opened: %v", url, err)
		}
	}
}

// TestHR721_AServiceAccountCredentialIsCheckedWhole: Google's endpoint
// and a loopback simulator's are the only token endpoints; one to eight
// distinct Google scopes; and an unknown member is refused when opened.
//
// Covers: HR-721
func TestHR721_AServiceAccountCredentialIsCheckedWhole(t *testing.T) {
	for _, uri := range []string{GoogleTokenURI, "http://127.0.0.1:9104/token"} {
		g := GoogleServiceAccount{TokenURI: uri}
		if _, err := g.Token(); err != nil {
			t.Errorf("%s: %v", uri, err)
		}
	}
	for _, uri := range []string{"https://oauth2.googleapis.com/token?x=1", "https://accounts.google.com/o/oauth2/token", "http://oauth2.googleapis.com/token"} {
		g := GoogleServiceAccount{TokenURI: uri}
		if _, err := g.Token(); !errors.Is(err, ErrGoogleServiceAccount) {
			t.Errorf("%s: %v", uri, err)
		}
	}
	scope := "https://www.googleapis.com/auth/drive"
	for name, scopes := range map[string][]string{
		"none":       nil,
		"twice":      {scope, scope},
		"nine":       {scope + "1", scope + "2", scope + "3", scope + "4", scope + "5", scope + "6", scope + "7", scope + "8", scope + "9"},
		"not google": {"https://example.com/auth/drive"},
	} {
		g := GoogleServiceAccount{V: 1, ClientEmail: "a@p.iam.gserviceaccount.com", TokenURI: GoogleTokenURI, Scopes: scopes}
		if err := g.Validate(); !errors.Is(err, ErrGoogleServiceAccount) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := DecodeGoogleServiceAccount([]byte(`{"v":1,"client_email":"a@p.iam.gserviceaccount.com","private_key":"","token_uri":"` +
		GoogleTokenURI + `","scopes":["` + scope + `"],"extra":1}`)); !errors.Is(err, ErrGoogleServiceAccount) {
		t.Errorf("unknown member: %v", err)
	}
	if !ValidKind(KindGoogleServiceAccount) || !ValidKind(KindSnowflakeKeypair) {
		t.Error("kind")
	}
}
