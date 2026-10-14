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

	"github.com/katocxl/pantherclaw/internal/platform/celenv"
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
		"cel max cost":        func(c *Config) { c.CEL.MaxCost = 0 },
		"cel nesting":         func(c *Config) { c.CEL.MaxComprehensionNesting = -1 },
		"cel above ceiling":   func(c *Config) { c.CEL.MaxCost = celenv.Ceiling.MaxCost + 1 },
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

// TestHR163_DevSeedOnlyLocal: dev seed refuses a configuration that is not
// local-only before it touches the database.
func TestHR163_DevSeedOnlyLocal(t *testing.T) {
	for name, cfg := range map[string]string{
		"live api keys":  `{"database": {"app_password_file": "pw"}, "kek_files": ["kek"]}`,
		"all interfaces": `{"database": {"app_password_file": "pw"}, "kek_files": ["kek"], "http": {"addr": "0.0.0.0:8080"}, "auth": {"api_key_env": "test"}}`,
		"public url":     `{"database": {"app_password_file": "pw"}, "kek_files": ["kek"], "auth": {"public_url": "https://pantherclaw.example.com", "api_key_env": "test"}}`,
	} {
		path := filepath.Join(t.TempDir(), "server.json")
		if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		code := Run(context.Background(), []string{"dev", "seed", "--config", path}, &out, &errb, noEnv)
		if code == 0 || !strings.Contains(errb.String(), "dev seed is development-only (HR-163)") {
			t.Errorf("%s: code %d, stderr %q", name, code, errb.String())
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

// TestCELLimitsAreConfiguration: the CEL limits default to the recommended
// numbers and a configuration file can change them (G0 M4 decision 4).
func TestCELLimitsAreConfiguration(t *testing.T) {
	if c := DefaultConfig(); c.CEL != celenv.DefaultLimits {
		t.Fatalf("default CEL limits %+v, want %+v", c.CEL, celenv.DefaultLimits)
	}
	path := filepath.Join(t.TempDir(), "server.json")
	if err := os.WriteFile(path, []byte(`{"database": {"app_password_file": "pw"}, "kek_files": ["kek"],
		"cel": {"max_expression_bytes": 2048, "max_cost": 5000, "max_comprehension_nesting": 1, "estimated_collection_size": 256}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c := DefaultConfig()
	if err := config.Load(&c, path, noEnv); err != nil {
		t.Fatal(err)
	}
	if want := (celenv.Limits{MaxExpressionBytes: 2048, MaxCost: 5000, MaxComprehensionNesting: 1, EstimatedCollectionSize: 256}); c.CEL != want {
		t.Fatalf("loaded CEL limits %+v, want %+v", c.CEL, want)
	}
}
