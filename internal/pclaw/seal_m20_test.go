// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
)

const (
	sealTenant   = "5a1e0000-0000-4000-8000-000000000001"
	sealTokenURL = "https://login.microsoftonline.com/" + sealTenant + "/oauth2/v2.0/token"
	sealClientID = "00000000-0000-4000-8000-0000000000b0"
	sealConn     = "0192aaaa-bbbb-7ccc-8ddd-000000000002"
)

func newSealServer(t *testing.T) (*sealServer, Env) {
	t.Helper()
	key, err := pccrypto.GenerateSealKey()
	if err != nil {
		t.Fatal(err)
	}
	srv := &sealServer{key: key, fingerprint: fingerprintOf(key)}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterConnectionServiceHandler(cs, srv)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return srv, envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})
}

func secretFile(t *testing.T, secret string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(file, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

// TestHR524_SealTakesAnOAuthClientAndRefusesWhatTheDomainRefuses: pclaw seal
// binds an OAuth client's kind and uploads only sealed bytes, reading the
// secret from a file or stdin; a Teams bot with no pinned tenant, a token
// host the connection does not bind, the wrong header and a bad field are
// each refused with nothing sealed (D279, D280).
// Covers: HR-524, HR-060
func TestHR524_SealTakesAnOAuthClientAndRefusesWhatTheDomainRefuses(t *testing.T) {
	const secret = "client~secret.not-real"
	srv, env := newSealServer(t)
	srv.hosts, srv.header, srv.scheme = []string{"login.microsoftonline.com", "smba.trafficmanager.net"}, "Authorization", "Bearer"
	args := func(tokenURL, scope, from string) []string {
		return []string{
			"seal", "--connection", sealConn, "--from-file", from,
			"--oauth-token-url", tokenURL, "--oauth-client-id", sealClientID, "--oauth-scope", scope,
		}
	}
	file := secretFile(t, secret)

	code, out, errs := run(t, env, args(sealTokenURL, domain.BotFrameworkScope, file)...)
	if code != 0 || srv.put == nil || srv.put.GetKind() != domain.KindOAuthClient {
		t.Fatalf("seal = %d %q %q", code, out, errs)
	}
	if strings.Contains(out+errs, secret) || bytes.Contains(srv.put.GetSealed(), []byte(secret)) {
		t.Fatal("the client secret left the machine in plaintext")
	}
	b := domain.Binding{
		Org: "0192aaaa-bbbb-7ccc-8ddd-000000000001", Connection: sealConn, Version: 2, AllowedHosts: srv.hosts,
		BrokerKey: "0192aaaa-bbbb-7ccc-8ddd-000000000003", Header: "Authorization", Scheme: "Bearer", Kind: domain.KindOAuthClient,
	}
	plain, err := pccrypto.Open(srv.key, b.Info(), domain.AAD, srv.put.GetSealed())
	if err != nil {
		t.Fatal(err)
	}
	o, err := domain.DecodeOAuthClient(plain)
	if err != nil || string(o.ClientSecret) != secret || o.Tenant() != sealTenant {
		t.Fatalf("%+v %v", o, err)
	}

	// The secret may come from stdin.
	srv.put = nil
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), args(sealTokenURL, domain.BotFrameworkScope, "-"), &stdout, &stderr, env,
		Options{Stdin: strings.NewReader(secret + "\n")}); code != 0 || srv.put == nil {
		t.Fatalf("stdin = %d %q", code, stderr.String())
	}

	for name, c := range map[string]struct {
		tokenURL, scope, want string
	}{
		"no pinned tenant": {"https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token", domain.BotFrameworkScope, "home tenant"},
		"unbound host":     {"https://login.evil.example/" + sealTenant + "/oauth2/v2.0/token", domain.BotFrameworkScope, "allowed hosts"},
		"bad scope":        {sealTokenURL, "two scopes", "--oauth-token-url needs"},
	} {
		srv.put = nil
		code, _, errs := run(t, env, args(c.tokenURL, c.scope, file)...)
		if code == 0 || srv.put != nil || !strings.Contains(errs, c.want) || !strings.Contains(errs, "nothing was sealed") || strings.Contains(errs, secret) {
			t.Errorf("%s = %d %q", name, code, errs)
		}
	}

	srv.put, srv.scheme = nil, "token"
	if code, _, errs := run(t, env, args(sealTokenURL, domain.BotFrameworkScope, file)...); code == 0 || srv.put != nil || !strings.Contains(errs, "Authorization: Bearer") {
		t.Fatalf("the wrong scheme = %d %q", code, errs)
	}
}

// TestHR525_SealTakesAnAWSKeyAndRefusesWhatTheDomainRefuses: pclaw seal binds
// an AWS credential's kind and uploads only sealed bytes; an STS host the
// connection does not bind, the wrong scheme and a bad role are each refused
// with nothing sealed (D280).
// Covers: HR-525, HR-060
func TestHR525_SealTakesAnAWSKeyAndRefusesWhatTheDomainRefuses(t *testing.T) {
	const (
		secret = "simulated/base+secret0123456789"
		role   = "arn:aws:iam::111122223333:role/pantherclaw-deploy"
		sts    = "https://sts.us-east-1.amazonaws.com"
	)
	srv, env := newSealServer(t)
	srv.hosts, srv.header, srv.scheme = []string{"sts.us-east-1.amazonaws.com", "iam.amazonaws.com"}, "Authorization", domain.AWSSigV4Scheme
	file := secretFile(t, secret)
	args := func(roleARN, stsURL string) []string {
		return []string{
			"seal", "--connection", sealConn, "--from-file", file, "--aws-access-key-id", "AKIASIMULATEDBASE001", "--aws-role-arn", roleARN,
			"--aws-external-id", "pc-ext-1", "--aws-sts-url", stsURL, "--aws-sts-region", "us-east-1", "--aws-region", "us-east-1", "--aws-service", "iam",
		}
	}
	code, out, errs := run(t, env, args(role, sts)...)
	if code != 0 || srv.put == nil || srv.put.GetKind() != domain.KindAWSSigV4 {
		t.Fatalf("seal = %d %q %q", code, out, errs)
	}
	if strings.Contains(out+errs, secret) || bytes.Contains(srv.put.GetSealed(), []byte(secret)) {
		t.Fatal("the secret key left the machine in plaintext")
	}
	b := domain.Binding{
		Org: "0192aaaa-bbbb-7ccc-8ddd-000000000001", Connection: sealConn, Version: 2, AllowedHosts: srv.hosts,
		BrokerKey: "0192aaaa-bbbb-7ccc-8ddd-000000000003", Header: "Authorization", Scheme: domain.AWSSigV4Scheme, Kind: domain.KindAWSSigV4,
	}
	plain, err := pccrypto.Open(srv.key, b.Info(), domain.AAD, srv.put.GetSealed())
	if err != nil {
		t.Fatal(err)
	}
	c, err := domain.DecodeAWSSigV4(plain)
	if err != nil || string(c.SecretAccessKey) != secret || c.ExternalID != "pc-ext-1" || c.Account() != "111122223333" {
		t.Fatalf("%+v %v", c, err)
	}

	for name, in := range map[string]struct{ role, sts, want string }{
		"bad role":     {"arn:aws:iam::1:role/x", sts, "--aws-access-key-id needs"},
		"unbound host": {role, "https://sts.evil.example", "allowed hosts"},
	} {
		srv.put = nil
		code, _, errs := run(t, env, args(in.role, in.sts)...)
		if code == 0 || srv.put != nil || !strings.Contains(errs, in.want) || !strings.Contains(errs, "nothing was sealed") || strings.Contains(errs, secret) {
			t.Errorf("%s = %d %q", name, code, errs)
		}
	}
	srv.put, srv.scheme = nil, "Bearer"
	if code, _, errs := run(t, env, args(role, sts)...); code == 0 || srv.put != nil || !strings.Contains(errs, domain.AWSSigV4Scheme) {
		t.Fatalf("the wrong scheme = %d %q", code, errs)
	}
}

// TestSealTakesOneKindAtATime: flags of two kinds are a usage error, and a
// private key is never sealed as an OAuth client's secret.
func TestSealTakesOneKindAtATime(t *testing.T) {
	srv, env := newSealServer(t)
	file := secretFile(t, "not-real-secret-value")
	for name, extra := range map[string][]string{
		"oauth and aws":    {"--oauth-client-id", "a", "--aws-region", "us-east-1"},
		"github and aws":   {"--github-app", "1", "--installation", "2", "--account", "a", "--aws-region", "us-east-1"},
		"github and oauth": {"--github-app", "1", "--installation", "2", "--account", "a", "--oauth-scope", "s"},
	} {
		args := append([]string{"seal", "--connection", sealConn, "--from-file", file}, extra...)
		if code, _, _ := run(t, env, args...); code == 0 || srv.put != nil {
			t.Errorf("%s = %d", name, code)
		}
	}
	pem := secretFile(t, "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----")
	srv.hosts, srv.header, srv.scheme = []string{"login.microsoftonline.com"}, "Authorization", "Bearer"
	if code, _, errs := run(t, env, "seal", "--connection", sealConn, "--from-file", pem, "--oauth-token-url", sealTokenURL,
		"--oauth-client-id", sealClientID, "--oauth-scope", domain.BotFrameworkScope); code == 0 || srv.put != nil || !strings.Contains(errs, "private key") {
		t.Fatalf("a private key = %d %q", code, errs)
	}
}
