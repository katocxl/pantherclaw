// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/config"
)

func noEnv(string) (string, bool) { return "", false }

func TestConfigValidation(t *testing.T) {
	c := DefaultConfig()
	if err := c.Validate(); err == nil {
		t.Fatal("defaults without secrets validated")
	}
	c.DB.AppPasswordFile = "pw"
	c.KEKFiles = []string{"kek"}
	if err := c.Validate(); err != nil {
		t.Fatalf("minimal config invalid: %v", err)
	}
	// The M1.5 budget name is ignored since M4, so it may be left out.
	noBudget := c
	noBudget.Authority.BudgetName = ""
	if err := noBudget.Validate(); err != nil {
		t.Fatalf("config without authority.budget_name invalid: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"role":         func(c *Config) { c.Role = "admin" },
		"log level":    func(c *Config) { c.Log.Level = "verbose" },
		"half tls":     func(c *Config) { c.HTTP.TLSCertFile = "cert.pem" },
		"app as owner": func(c *Config) { c.DB.AppUser = "postgres" },
		"app as mig":   func(c *Config) { c.DB.AppUser = "pc_migrator" },
		"no kek":       func(c *Config) { c.KEKFiles = nil },
		"workers":      func(c *Config) { c.WorkerConcurrency = 0 },
		"grant amount": func(c *Config) { c.Authority.GrantMaxPerAction = "-1" },
		"grant ccy":    func(c *Config) { c.Authority.GrantCurrency = "XYZ" },
		"permit ttl":   func(c *Config) { c.Authority.PermitTTL = 0 },
		"long ttl":     func(c *Config) { c.Authority.PermitTTL = config.Duration(time.Hour) },
		"stale":        func(c *Config) { c.Authority.StaleDispatch = config.Duration(5 * time.Second) },
		"no lock wait": func(c *Config) { c.Authority.BudgetLockTimeout = 0 },
		"long lock":    func(c *Config) { c.Authority.BudgetLockTimeout = config.Duration(2 * time.Second) },
		"gateway api without names": func(c *Config) {
			c.GatewayAPI = GatewayAPIConfig{Addr: "127.0.0.1:8443", URL: "https://127.0.0.1:8443"}
		},
		"public url http":     func(c *Config) { c.Auth.PublicURL = "http://pantherclaw.example.com" },
		"public url path":     func(c *Config) { c.Auth.PublicURL = "https://pc.example.com/api" },
		"public url slash":    func(c *Config) { c.Auth.PublicURL = "https://pc.example.com/" },
		"public url query":    func(c *Config) { c.Auth.PublicURL = "https://pc.example.com?x=1" },
		"public url userinfo": func(c *Config) { c.Auth.PublicURL = "https://u:p@pc.example.com" },
		"public url relative": func(c *Config) { c.Auth.PublicURL = "pc.example.com" },
		"api key env":         func(c *Config) { c.Auth.APIKeyEnv = "prod" },
		"trusted proxy":       func(c *Config) { c.HTTP.TrustedProxies = []string{"10.0.0.0/8", "proxy.internal"} },
		"oidc http issuer": func(c *Config) {
			c.Auth.OIDCProviders = []OIDCProviderConfig{{Name: "kc", Issuer: "http://idp.example.com", ClientID: "pc", ClientSecretFile: "s"}}
		},
		"oidc http not loopback": func(c *Config) {
			c.Auth.OIDCProviders = []OIDCProviderConfig{{Name: "kc", Issuer: "http://idp.example.com", ClientID: "pc", ClientSecretFile: "s", AllowInsecureLoopback: true}}
		},
		"oidc no secret": func(c *Config) {
			c.Auth.OIDCProviders = []OIDCProviderConfig{{Name: "kc", Issuer: "https://idp.example.com", ClientID: "pc"}}
		},
		"oidc bad name": func(c *Config) {
			c.Auth.OIDCProviders = []OIDCProviderConfig{{Name: "Key Cloak", Issuer: "https://idp.example.com", ClientID: "pc", ClientSecretFile: "s"}}
		},
		"oidc duplicate": func(c *Config) {
			p := OIDCProviderConfig{Name: "kc", Issuer: "https://idp.example.com", ClientID: "pc", ClientSecretFile: "s"}
			c.Auth.OIDCProviders = []OIDCProviderConfig{p, p}
		},
	} {
		cc := c
		mutate(&cc)
		if err := cc.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, u := range []string{"https://pc.example.com", "https://pc.example.com:8443", "http://127.0.0.1:8080", "http://localhost:8080", "http://[::1]:9000"} {
		cc := c
		cc.Auth.PublicURL = u
		if err := cc.Validate(); err != nil {
			t.Errorf("public url %s refused: %v", u, err)
		}
	}
	gw := c
	gw.GatewayAPI = GatewayAPIConfig{Addr: "127.0.0.1:8443", Hostnames: []string{"127.0.0.1"}, URL: "https://127.0.0.1:8443"}
	if err := gw.Validate(); err != nil {
		t.Errorf("a gateway listener refused: %v", err)
	}
}

const devOrg = "01920000-0000-7000-8000-0000000000a1"

func TestDevSeedUsage(t *testing.T) {
	var out, errb bytes.Buffer
	for _, args := range [][]string{
		{"dev"},
		{"dev", "drop"},
		{"dev", "seed", "extra"},
		{"dev", "seed", "--max-count", "-1"},
		{"dev", "gateway"},
		{"dev", "gateway", "--org", "nope", "--out", "f"},
		{"dev", "gateway", "--org", devOrg},
	} {
		if code := Run(context.Background(), args, &out, &errb, noEnv); code != 2 {
			t.Errorf("%v: %d, want 2", args, code)
		}
	}
}

func TestRunUsageAndVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Run(context.Background(), nil, &out, &errb, noEnv); code != 2 {
		t.Fatalf("no args: %d", code)
	}
	if code := Run(context.Background(), []string{"bogus"}, &out, &errb, noEnv); code != 2 {
		t.Fatalf("unknown command: %d", code)
	}
	out.Reset()
	if code := Run(context.Background(), []string{"version"}, &out, &errb, noEnv); code != 0 || !strings.HasPrefix(out.String(), "pantherclaw-server ") {
		t.Fatalf("version: %d %q", code, out.String())
	}
}

func TestKeysGenKEK(t *testing.T) {
	p := filepath.Join(t.TempDir(), "kek")
	var out, errb bytes.Buffer
	if code := Run(context.Background(), []string{"keys", "gen-kek", "--out", p}, &out, &errb, noEnv); code != 0 {
		t.Fatalf("gen-kek: %d %s", code, errb.String())
	}
	if b, err := os.ReadFile(p); err != nil || len(bytes.TrimSpace(b)) != 44 {
		t.Fatalf("KEK file = %q, %v", b, err)
	}
	if code := Run(context.Background(), []string{"keys", "gen-kek", "--out", p}, &out, &errb, noEnv); code == 0 {
		t.Fatal("gen-kek overwrote an existing KEK")
	}
}

func TestServeRefusesInvalidConfigWithoutTouchingTheDatabase(t *testing.T) {
	var errb bytes.Buffer
	env := func(k string) (string, bool) {
		if k == "PC_ROLE" {
			return "superuser", true
		}
		return "", false
	}
	if code := Run(context.Background(), []string{"serve"}, &bytes.Buffer{}, &errb, env); code != 1 || !strings.Contains(errb.String(), "role must be") {
		t.Fatalf("serve with bad role: %d %s", code, errb.String())
	}
}

func TestOIDCProviderConfigAccepted(t *testing.T) {
	c := DefaultConfig()
	c.DB.AppPasswordFile, c.KEKFiles = "pw", []string{"kek"}
	c.Auth.OIDCProviders = []OIDCProviderConfig{
		{Name: "okta", Issuer: "https://acme.okta.com", ClientID: "pc", ClientSecretFile: "s"},
		{Name: "keycloak", Issuer: "http://127.0.0.1:8180/realms/pantherclaw", ClientID: "pc", ClientSecretFile: "s", AllowInsecureLoopback: true},
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestTrustedProxiesParse(t *testing.T) {
	c := DefaultConfig()
	c.HTTP.TrustedProxies = []string{"10.0.0.0/8", "192.168.1.5", "::ffff:172.16.0.9", "fd00::/8"}
	got, err := c.trustedProxies()
	if err != nil || len(got) != 4 || got[1].String() != "192.168.1.5/32" || got[2].String() != "172.16.0.9/32" {
		t.Fatalf("trustedProxies = %v, %v", got, err)
	}
}
