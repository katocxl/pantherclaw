// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package oidcrp

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

func orgConfig(issuer string) Config {
	return Config{Name: "acme", Issuer: issuer, ClientID: "c", ClientSecret: pclog.NewSecret([]byte("s")), Org: true}
}

// TestHR483_OrgIssuerHTTPSOnly: an organization's provider takes only an
// HTTPS issuer on a host the egress guard allows: http, loopback, private,
// link-local and metadata issuers are refused in every spelling, as are
// an insecure loopback issuer and subject tokens (G0 M18 D155).
//
// Covers: PN-012.7
func TestHR483_OrgIssuerHTTPSOnly(t *testing.T) {
	for _, iss := range []string{
		"http://idp.example.com",
		"http://127.0.0.1:8080",
		"https://127.0.0.1",
		"https://[::1]",
		"https://localhost",
		"https://LOCALHOST.",
		"https://login.localhost",
		"https://10.1.2.3",
		"https://192.168.0.10",
		"https://169.254.169.254",
		"https://2852039166", // 169.254.169.254
		"https://0x7f000001", // 127.0.0.1
		"https://[fd00:ec2::254]",
		"https://metadata.google.internal",
		"https://user@idp.example.com",
		"https://idp.example.com?x=1",
	} {
		if _, err := New(orgConfig(iss)); err == nil {
			t.Errorf("%s: accepted", iss)
		}
		if err := CheckOrgURL(iss); err == nil {
			t.Errorf("CheckOrgURL(%s): accepted", iss)
		}
	}
	if _, err := New(orgConfig("https://idp.example.com/realms/acme")); err != nil {
		t.Fatalf("a public https issuer: %v", err)
	}
	c := orgConfig("https://idp.example.com")
	c.AllowInsecureLoopback = true
	if _, err := New(c); err == nil {
		t.Error("an insecure loopback org provider was accepted")
	}
	c = orgConfig("https://idp.example.com")
	c.SubjectTokenAudience = "pantherclaw"
	if _, err := New(c); err == nil {
		t.Error("an org provider with subject tokens was accepted")
	}
}

// TestHR483_OrgDiscoveryThroughEgressGuard: an organization's provider
// talks through the egress client, which refuses a loopback address at
// dial time (DNS rebinding included), and discovered endpoints on private
// or metadata hosts are refused (G0 M18 D155).
//
// Covers: PN-012.7
func TestHR483_OrgDiscoveryThroughEgressGuard(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	p, err := New(orgConfig("https://idp.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := p.client.Get(srv.URL)
	if err == nil {
		_ = res.Body.Close()
	}
	if !errors.Is(err, httpx.ErrDestinationDenied) {
		t.Fatalf("the org provider's client reached a loopback server: %v", err)
	}
	if err := p.Discover(context.Background()); err == nil {
		t.Fatal("discovery succeeded without a reachable issuer")
	}

	// A provider whose name resolves to a public issuer but whose document
	// points its endpoints at private or metadata hosts.
	for _, bad := range []string{"https://10.0.0.1/token", "https://169.254.169.254/token", "http://idp.example.com/token"} {
		doc := map[string]any{
			"issuer": "https://idp.example.com", "authorization_endpoint": "https://idp.example.com/auth",
			"token_endpoint": bad, "jwks_uri": "https://idp.example.com/jwks",
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.MarshalWrite(w, doc)
		}))
		client := idp.Client()
		tr := client.Transport.(*http.Transport).Clone()
		addr := idp.Listener.Addr().String()
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
		tr.TLSClientConfig.InsecureSkipVerify = true // the test server stands in for idp.example.com
		client.Transport = tr
		c := orgConfig("https://idp.example.com")
		c.HTTPClient = client
		p, err := New(c)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "endpoint") {
			t.Errorf("token endpoint %s: %v", bad, err)
		}
		idp.Close()
	}
}
