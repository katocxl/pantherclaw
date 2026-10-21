// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/katocxl/pantherclaw/internal/gateway"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/config"
	"github.com/katocxl/pantherclaw/internal/server"
)

func noEnvNode(string) (string, bool) { return "", false }

// testNode returns a node in a temporary directory with docker replaced.
func testNode(t *testing.T, docker nodeDocker) (*node, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var out, errb bytes.Buffer
	dir := t.TempDir()
	cfgDir := t.TempDir()
	a := &app{stdout: &out, stderr: &errb, env: func(k string) (string, bool) {
		if k == "PANTHERCLAW_CONFIG_DIR" {
			return cfgDir, true
		}
		return "", false
	}, http: http.DefaultClient}
	prev := nodeDockerHook
	nodeDockerHook = docker
	t.Cleanup(func() { nodeDockerHook = prev })
	n, err := newNode(a, dir)
	if err != nil {
		t.Fatal(err)
	}
	n.readyTimeout = 10 * time.Second
	return n, &out, &errb
}

func prodState() nodeState {
	return nodeState{Deployment: nodeDeploymentProd, APIPort: 8080, GatewayPort: 8090, OrgName: "local"}
}

type composeDoc struct {
	Name     string `yaml:"name"`
	Services map[string]struct {
		Image       string   `yaml:"image"`
		User        string   `yaml:"user"`
		ReadOnly    bool     `yaml:"read_only"`
		CapDrop     []string `yaml:"cap_drop"`
		SecurityOpt []string `yaml:"security_opt"`
		Ports       []string `yaml:"ports"`
		Volumes     []string `yaml:"volumes"`
		Profiles    []string `yaml:"profiles"`
		Entrypoint  []string `yaml:"entrypoint"`
		NetworkMode string   `yaml:"network_mode"`
	} `yaml:"services"`
}

// TestNodeFiles_ConfigsLoadAndValidate: the generated server.json and
// gateway.json load into the real configurations and pass their
// validation, in production and development, with and without sign-in;
// production keeps the defaults D39 names.
func TestNodeFiles_ConfigsLoadAndValidate(t *testing.T) {
	for name, st := range map[string]nodeState{
		"production": prodState(),
		"production with sign-in": func() nodeState {
			s := prodState()
			s.OIDC = &nodeOIDC{Name: "sso", Issuer: "https://idp.example.com", ClientID: "pantherclaw"}
			s.GitHub = &nodeGitHub{ClientID: "Iv23liExample"}
			return s
		}(),
		"development": {Deployment: nodeDeploymentDev, APIPort: 18080, GatewayPort: 18090},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			sb, err := nodeServerConfigJSON(st)
			if err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(dir, "server.json")
			if err := os.WriteFile(p, sb, 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := server.DefaultConfig()
			if err := config.Load(&cfg, p, noEnvNode); err != nil {
				t.Fatalf("server.json does not load: %v\n%s", err, sb)
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("server.json invalid: %v\n%s", err, sb)
			}
			if cfg.Deployment != st.Deployment || cfg.Role != server.RoleAll || !cfg.HTTP.PlaintextBehindProxy ||
				cfg.DB.SSLMode != "verify-full" || cfg.DB.Host != "postgres" || cfg.GatewayAPI.URL != "https://server:8443" ||
				cfg.Auth.PublicURL != "http://localhost:"+strconv.Itoa(st.APIPort) || cfg.Maintenance.Hold {
				t.Errorf("server.json: %s", sb)
			}
			if wantKeys := map[string]string{nodeDeploymentProd: "live", nodeDeploymentDev: "dev"}[st.Deployment]; cfg.Auth.APIKeyEnv != wantKeys {
				t.Errorf("api_key_env %q, want %q", cfg.Auth.APIKeyEnv, wantKeys)
			}
			if (st.OIDC != nil) != (len(cfg.Auth.OIDCProviders) == 1) || (st.GitHub != nil) != (cfg.GitHub.ClientID != "") {
				t.Errorf("sign-in not as chosen: %s", sb)
			}

			gb, err := nodeGatewayConfigJSON(st)
			if err != nil {
				t.Fatal(err)
			}
			gp := filepath.Join(dir, "gateway.json")
			if err := os.WriteFile(gp, gb, 0o600); err != nil {
				t.Fatal(err)
			}
			gcfg := gateway.DefaultConfig()
			if err := config.Load(&gcfg, gp, noEnvNode); err != nil {
				t.Fatalf("gateway.json does not load: %v\n%s", err, gb)
			}
			if err := gcfg.Validate(); err != nil {
				t.Fatalf("gateway.json invalid: %v\n%s", err, gb)
			}
			if !gcfg.PlaintextPublishedLoopback || gcfg.PublicURL != "http://localhost:"+strconv.Itoa(st.GatewayPort) || gcfg.TLS.CertFile != "" {
				t.Errorf("gateway.json: %s", gb)
			}
		})
	}
	// The enrollment file is what the gateway reads.
	eb, err := nodeEnrollJSON("pcg_x", "sha256:"+strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	ep := filepath.Join(t.TempDir(), "enroll.json")
	if err := os.WriteFile(ep, eb, 0o600); err != nil {
		t.Fatal(err)
	}
	if f, err := gateway.ReadEnrollFile(ep); err != nil || f.APIURL != "http://server:8080" || f.Token != "pcg_x" {
		t.Errorf("enrollment file = %+v, %v", f, err)
	}
}

// TestNodeFiles_ComposeHardened: compose.yaml publishes ports on
// 127.0.0.1 only; every PantherClaw container is read-only, drops every
// capability, cannot gain privileges and runs as the image's nonroot user;
// only secrets-init and PostgreSQL see the node's secret files, and each
// PantherClaw service gets its own secrets volume: the migrator's password
// only for bootstrap and migrate, the owner's URL only for bootstrap;
// PostgreSQL is the image deploy/compose pins.
func TestNodeFiles_ComposeHardened(t *testing.T) {
	b, err := nodeComposeYAML(nodeComposeData{
		Project: "pantherclaw-node", ServerImage: "ghcr.io/katocxl/pantherclaw-server@sha256:" + strings.Repeat("1", 64),
		GatewayImage: "ghcr.io/katocxl/pantherclaw-gateway@sha256:" + strings.Repeat("2", 64), PostgresImage: nodePostgresImage,
		APIPort: 8080, GatewayPort: 8090,
	})
	if err != nil {
		t.Fatal(err)
	}
	var doc composeDoc
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("compose.yaml: %v\n%s", err, b)
	}
	if doc.Name != "pantherclaw-node" {
		t.Errorf("project %q", doc.Name)
	}
	secretsVolume := map[string]string{
		"bootstrap": "sec-bootstrap:/node/secrets:ro", "migrate": "sec-migrate:/node/secrets:ro", "server": "sec-server:/node/secrets:ro",
		"gateway": "sec-gateway:/node/secrets:ro", "gateway-tools": "sec-gateway:/node/secrets:ro",
	}
	want := []string{"bootstrap", "gateway", "gateway-tools", "migrate", "postgres", "secrets-init", "server"}
	got := make([]string, 0, len(doc.Services))
	for name, s := range doc.Services {
		got = append(got, name)
		for _, p := range s.Ports {
			if !strings.HasPrefix(p, "127.0.0.1:") {
				t.Errorf("%s publishes %s beyond loopback", name, p)
			}
		}
		if !slices.Contains(s.SecurityOpt, "no-new-privileges:true") {
			t.Errorf("%s may gain privileges", name)
		}
		for _, v := range s.Volumes {
			if strings.HasPrefix(v, "./secrets") && name != "secrets-init" && name != "postgres" {
				t.Errorf("%s bind-mounts the node's secrets: %s", name, v)
			}
		}
		switch name {
		case "postgres":
			if s.Image != nodePostgresImage || len(s.Ports) != 0 {
				t.Errorf("postgres: image %s, ports %v", s.Image, s.Ports)
			}
			continue
		case "secrets-init":
			if s.Image != nodePostgresImage || s.NetworkMode != "none" || !slices.Equal(s.CapDrop, []string{"ALL"}) {
				t.Errorf("secrets-init: image %s, network %q, cap_drop %v", s.Image, s.NetworkMode, s.CapDrop)
			}
			continue
		}
		if !s.ReadOnly || !slices.Equal(s.CapDrop, []string{"ALL"}) || s.User != "" {
			t.Errorf("%s: read_only %v, cap_drop %v, user %q", name, s.ReadOnly, s.CapDrop, s.User)
		}
		if !strings.Contains(s.Image, "@sha256:") {
			t.Errorf("%s image %s is not by digest", name, s.Image)
		}
		if !slices.Contains(s.Volumes, secretsVolume[name]) {
			t.Errorf("%s volumes %v lack %s", name, s.Volumes, secretsVolume[name])
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("services %v, want %v", got, want)
	}
	if p := doc.Services["server"].Ports; !slices.Equal(p, []string{"127.0.0.1:8080:8080"}) {
		t.Errorf("server ports %v", p)
	}
	if p := doc.Services["gateway"].Ports; !slices.Equal(p, []string{"127.0.0.1:8090:8090"}) {
		t.Errorf("gateway ports %v", p)
	}
	// What secrets-init puts in each volume.
	script := strings.Join(doc.Services["secrets-init"].Entrypoint, "\n")
	puts := map[string][]string{}
	for _, l := range strings.Split(script, "\n") {
		if f := strings.Fields(l); len(f) > 1 && f[0] == "put" {
			puts[f[1]] = f[2:]
		}
	}
	wantPuts := map[string][]string{
		"bootstrap": {"admin.url", "pc_app.pw", "pc_migrator.pw", "pc_audit_ro.pw", "pc_retention.pw"},
		"migrate":   {"pc_migrator.pw"},
		"server":    {"pc_app.pw", "pc_retention.pw", "kek", "oidc-client.secret", "github-client.secret"},
		"gateway":   {"gateway-kek", "gateway-enroll.json"},
	}
	for vol, files := range wantPuts {
		if !slices.Equal(puts[vol], files) {
			t.Errorf("secrets-init puts %v in %s, want %v", puts[vol], vol, files)
		}
	}
	if len(puts) != len(wantPuts) {
		t.Errorf("secrets-init fills %v", puts)
	}
	if !strings.Contains(script, "-m 0400 -o 65532 -g 65532") {
		t.Errorf("secrets are not 0400 for nonroot:\n%s", script)
	}
	// The same PostgreSQL as the development stack.
	dev, err := os.ReadFile(filepath.Join("..", "..", "deploy", "compose", "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(dev, []byte("image: "+nodePostgresImage)) {
		t.Errorf("deploy/compose/compose.yaml no longer pins %s", nodePostgresImage)
	}
}

// TestNodeFiles_SecretsAndTLS: secrets are created once, owner-only, and
// never replaced; the owner's URL verifies PostgreSQL's certificate, which
// the node CA signs for "postgres" and which is renewed only near expiry.
func TestNodeFiles_SecretsAndTLS(t *testing.T) {
	dir := t.TempDir()
	if err := writeNodeSecrets(dir); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(filepath.Join(dir, "secrets", "pc_app.pw"))
	if err != nil || len(first) != 48 {
		t.Fatalf("pc_app.pw = %q, %v", first, err)
	}
	kek, err := os.ReadFile(filepath.Join(dir, "secrets", "kek"))
	if err != nil || len(kek) == 0 {
		t.Fatalf("kek: %v", err)
	}
	if err := writeNodeSecrets(dir); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(filepath.Join(dir, "secrets", "pc_app.pw"))
	kek2, _ := os.ReadFile(filepath.Join(dir, "secrets", "kek"))
	if !bytes.Equal(first, again) || !bytes.Equal(kek, kek2) {
		t.Error("a second run replaced a secret")
	}
	admin, _ := os.ReadFile(filepath.Join(dir, "secrets", "admin.url"))
	if !strings.HasPrefix(string(admin), "postgres://pc_owner:") || !strings.Contains(string(admin), "@postgres:5432/pantherclaw?sslmode=verify-full&sslrootcert=/node/secrets/ca.crt") {
		t.Errorf("admin.url %q", admin)
	}
	if runtime.GOOS != "windows" {
		for _, f := range append(slices.Clone(nodePasswordFiles), "admin.url", "kek", "gateway-kek") {
			fi, err := os.Stat(filepath.Join(dir, "secrets", f))
			if err != nil || fi.Mode().Perm() != 0o600 {
				t.Errorf("%s: %v %v", f, fi.Mode(), err)
			}
		}
	}

	now := time.Now()
	if err := writeNodeTLS(dir, now); err != nil {
		t.Fatal(err)
	}
	leaf := func() *x509.Certificate {
		b, err := os.ReadFile(filepath.Join(dir, "tls", "postgres.crt"))
		if err != nil {
			t.Fatal(err)
		}
		blk, _ := pem.Decode(b)
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	caB, _ := os.ReadFile(filepath.Join(dir, "tls", "ca.crt"))
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caB) {
		t.Fatal("ca.crt")
	}
	l1 := leaf()
	if _, err := l1.Verify(x509.VerifyOptions{DNSName: "postgres", Roots: pool, CurrentTime: now}); err != nil {
		t.Fatalf("postgres.crt does not verify for postgres: %v", err)
	}
	if err := writeNodeTLS(dir, now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if l2 := leaf(); l2.SerialNumber.Cmp(l1.SerialNumber) != 0 {
		t.Error("a valid certificate was replaced")
	}
	later := l1.NotAfter.Add(-10 * 24 * time.Hour)
	if err := writeNodeTLS(dir, later); err != nil {
		t.Fatal(err)
	}
	l3 := leaf()
	if l3.SerialNumber.Cmp(l1.SerialNumber) == 0 {
		t.Error("a certificate expiring within 30 days was kept")
	}
	if _, err := l3.Verify(x509.VerifyOptions{DNSName: "postgres", Roots: pool, CurrentTime: later}); err != nil {
		t.Errorf("the renewed certificate is not from the same CA: %v", err)
	}
}

func TestNodeImages_DigestFromBuildElseLocal(t *testing.T) {
	prevS, prevG := nodeServerImage, nodeGatewayImage
	t.Cleanup(func() { nodeServerImage, nodeGatewayImage = prevS, prevG })
	nodeServerImage, nodeGatewayImage = "", ""
	if s, g, dev := nodeImages(); s != nodeDevServerImage || g != nodeDevGatewayImage || !dev {
		t.Errorf("development build: %s %s %v", s, g, dev)
	}
	nodeServerImage = "ghcr.io/katocxl/pantherclaw-server@sha256:" + strings.Repeat("a", 64)
	nodeGatewayImage = "ghcr.io/katocxl/pantherclaw-gateway@sha256:" + strings.Repeat("b", 64)
	if s, g, dev := nodeImages(); s != nodeServerImage || g != nodeGatewayImage || dev {
		t.Errorf("release build: %s %s %v", s, g, dev)
	}
}

func TestNodeUp_FlagRules(t *testing.T) {
	base := upFlags{orgName: "local", oidcNm: "sso"}
	st, err := mergeUpFlags(nodeState{}, false, base)
	if err != nil || st.Deployment != nodeDeploymentProd || st.APIPort != 8080 || st.GatewayPort != 8090 {
		t.Fatalf("defaults: %+v %v", st, err)
	}
	dev := base
	dev.dev = true
	if _, err := mergeUpFlags(st, true, dev); err == nil {
		t.Error("a production node turned into development")
	}
	for name, f := range map[string]upFlags{
		"half an OIDC provider": {oidcIssuer: "https://idp.example.com", oidcNm: "sso"},
		"issuer not a URL":      {oidcIssuer: "idp", oidcClientID: "c", oidcSecret: "f", oidcNm: "sso"},
		"bad provider name":     {oidcIssuer: "https://idp.example.com", oidcClientID: "c", oidcSecret: "f", oidcNm: "SSO!"},
		"half a GitHub App":     {ghClientID: "Iv23li", oidcNm: "sso"},
		"same ports":            {port: 9000, gatewayPort: 9000, oidcNm: "sso"},
		"port out of range":     {port: 70000, oidcNm: "sso"},
	} {
		if _, err := mergeUpFlags(nodeState{}, false, f); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Sign-in given once stays.
	f := base
	f.oidcIssuer, f.oidcClientID, f.oidcSecret = "https://idp.example.com", "c", "secret-file"
	st, err = mergeUpFlags(st, true, f)
	if err != nil || st.OIDC == nil {
		t.Fatal(err)
	}
	if st, err = mergeUpFlags(st, true, base); err != nil || st.OIDC == nil || st.OIDC.Issuer != "https://idp.example.com" {
		t.Errorf("a rerun without flags dropped the provider: %+v %v", st, err)
	}
}

// TestNodeUp_RefusesWithoutDocker: no Docker (or no Compose v2), no node:
// nothing is written.
func TestNodeUp_RefusesWithoutDocker(t *testing.T) {
	for name, docker := range map[string]nodeDocker{
		"no docker": func(context.Context, string, io.Writer, io.Writer, ...string) error { return errNoDocker },
		"engine down": func(_ context.Context, _ string, _, _ io.Writer, args ...string) error {
			return errors.New("Cannot connect to the Docker daemon")
		},
		"no compose": func(_ context.Context, _ string, stdout, _ io.Writer, args ...string) error {
			if args[0] == "version" {
				_, _ = io.WriteString(stdout, "28.0.0\n")
				return nil
			}
			return errors.New("docker: 'compose' is not a docker command")
		},
	} {
		t.Run(name, func(t *testing.T) {
			n, _, _ := testNode(t, docker)
			err := n.up(context.Background(), upFlags{orgName: "local", oidcNm: "sso"})
			if !errors.Is(err, errNoDocker) {
				t.Fatalf("up = %v, want the Docker refusal", err)
			}
			if es, _ := os.ReadDir(n.dir); len(es) != 0 {
				t.Errorf("files written without Docker: %v", es)
			}
		})
	}
}

// fakeDocker records docker calls and answers org create.
type fakeDocker struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeDocker) run(_ context.Context, _ string, stdout, _ io.Writer, args ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := strings.Join(args, " ")
	if i := strings.Index(line, " --project-directory "); i >= 0 {
		// Drop the file and directory arguments.
		rest := line[i+len(" --project-directory "):]
		line = "compose " + rest[strings.Index(rest, " ")+1:]
	}
	f.calls = append(f.calls, line)
	switch {
	case args[0] == "version":
		_, _ = io.WriteString(stdout, "28.3.0\n")
	case len(args) > 1 && args[0] == "compose" && args[1] == "version":
		_, _ = io.WriteString(stdout, "2.39.1\n")
	case strings.Contains(line, " org create "):
		_, _ = io.WriteString(stdout, "created organization 01920000-0000-7000-8000-0000000000a1 (\"local\")\n\n"+
			"bootstrap admin token (shown only now; single use; valid 24 hours):\n  pci_test-token\n")
	}
	return nil
}

func (f *fakeDocker) has(sub string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.ContainsFunc(f.calls, func(c string) bool { return strings.Contains(c, sub) })
}

type fakeGatewayAdmin struct{ created, tokens int }

func (f *fakeGatewayAdmin) CreateGateway(_ context.Context, r *pantherclawv1.CreateGatewayRequest) (*pantherclawv1.CreateGatewayResponse, error) {
	f.created++
	return &pantherclawv1.CreateGatewayResponse{Gateway: &pantherclawv1.Gateway{Id: "01920000-0000-7000-8000-0000000000b1", Name: r.GetName()}}, nil
}

func (f *fakeGatewayAdmin) ListGateways(context.Context, *pantherclawv1.ListGatewaysRequest) (*pantherclawv1.ListGatewaysResponse, error) {
	if f.created == 0 {
		return &pantherclawv1.ListGatewaysResponse{}, nil
	}
	return &pantherclawv1.ListGatewaysResponse{Gateways: []*pantherclawv1.Gateway{{Id: "01920000-0000-7000-8000-0000000000b1", Name: "local"}}}, nil
}

func (f *fakeGatewayAdmin) CreateGatewayEnrollmentToken(context.Context, *pantherclawv1.CreateGatewayEnrollmentTokenRequest) (*pantherclawv1.CreateGatewayEnrollmentTokenResponse, error) {
	f.tokens++
	return &pantherclawv1.CreateGatewayEnrollmentTokenResponse{Token: "pcg_" + strconv.Itoa(f.tokens), CaSha256: "sha256:" + strings.Repeat("c", 64)}, nil
}

// TestNodeUp_FirstRunThenGatewayAfterLogin: the first pclaw up starts
// PostgreSQL, bootstraps, migrates, creates the org, starts the server,
// waits for /readyz and prints the login line, leaving the gateway for
// later; a second run after sign-in bootstraps and creates nothing again,
// creates gateway "local", writes its enrollment (0600) and starts it.
func TestNodeUp_FirstRunThenGatewayAfterLogin(t *testing.T) {
	ready := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"ready":true}`)
	}))
	defer ready.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(ready.URL, "http://"))
	p, _ := strconv.Atoi(port)

	fd := &fakeDocker{}
	n, out, _ := testNode(t, fd.run)
	if err := n.up(context.Background(), upFlags{orgName: "local", oidcNm: "sso", port: p}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"compose up --detach --wait postgres",
		"compose --profile tools run --rm secrets-init",
		"compose --profile tools run --rm bootstrap db bootstrap --admin-url-file /node/secrets/admin.url",
		"compose --profile tools run --rm migrate migrate up --config /node/server.json",
		"compose --profile tools run --rm gateway-tools broker-key generate --out /node/gateway/broker.json",
		"compose run --rm --no-deps -T server org create --name local --config /node/server.json",
		"compose up --detach server",
	} {
		if !fd.has(want) {
			t.Errorf("no %q in %q", want, fd.calls)
		}
	}
	if fd.has("--profile gateway up") {
		t.Error("the gateway started before anyone signed in")
	}
	o := out.String()
	for _, want := range []string{
		"PantherClaw is up: http://localhost:" + port + " (deployment production, organization 01920000-0000-7000-8000-0000000000a1)",
		"pclaw login --server http://localhost:" + port + " --org 01920000-0000-7000-8000-0000000000a1 --invitation pci_test-token",
		"Nobody can sign in yet", "gateway: not enrolled yet",
	} {
		if !strings.Contains(o, want) {
			t.Errorf("output lacks %q:\n%s", want, o)
		}
	}
	st, _, err := loadNodeState(n.dir)
	if err != nil || !st.Bootstrapped || st.Org != "01920000-0000-7000-8000-0000000000a1" {
		t.Fatalf("state %+v %v", st, err)
	}
	if b, _ := os.ReadFile(filepath.Join(n.dir, nodeStateFile)); bytes.Contains(b, []byte("pci_")) {
		t.Error("the admin token was stored")
	}

	// Second run, signed in.
	admin := &fakeGatewayAdmin{}
	nodeGatewayAdminHook = admin
	t.Cleanup(func() { nodeGatewayAdminHook = nil })
	fd.calls = nil
	out.Reset()
	if err := n.up(context.Background(), upFlags{orgName: "local", oidcNm: "sso"}); err != nil {
		t.Fatal(err)
	}
	if fd.has("bootstrap db bootstrap") || fd.has("org create") || fd.has("broker-key generate") {
		t.Errorf("a second run repeated one-time steps: %q", fd.calls)
	}
	if !fd.has("compose --profile gateway up --detach gateway") || admin.created != 1 {
		t.Errorf("gateway not created and started: %q, created %d", fd.calls, admin.created)
	}
	eb, err := os.ReadFile(filepath.Join(n.dir, nodeSecretsDir, nodeEnrollFile))
	if err != nil {
		t.Fatal(err)
	}
	var enroll map[string]string
	if err := json.Unmarshal(eb, &enroll); err != nil || enroll["token"] != "pcg_1" || enroll["api_url"] != "http://server:8080" {
		t.Errorf("enrollment %s", eb)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(filepath.Join(n.dir, nodeSecretsDir, nodeEnrollFile)); fi.Mode().Perm() != 0o600 {
			t.Errorf("enrollment file mode %v", fi.Mode())
		}
	}
	if !strings.Contains(out.String(), `gateway: http://localhost:8090 (gateway "local")`) {
		t.Errorf("output:\n%s", out.String())
	}
	// A third run starts the enrolled gateway: no new gateway, no new token.
	if err := n.up(context.Background(), upFlags{orgName: "local", oidcNm: "sso"}); err != nil {
		t.Fatal(err)
	}
	if admin.created != 1 || admin.tokens != 1 {
		t.Errorf("an enrolled gateway was enrolled again: created %d, tokens %d", admin.created, admin.tokens)
	}
}

// TestNodeUp_NotReadyIsAnError: a server that never becomes ready fails
// pclaw up with where to look.
func TestNodeUp_NotReadyIsAnError(t *testing.T) {
	notReady := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"ready":false}`)
	}))
	defer notReady.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(notReady.URL, "http://"))
	p, _ := strconv.Atoi(port)
	fd := &fakeDocker{}
	n, _, _ := testNode(t, fd.run)
	n.readyTimeout = 2 * time.Second
	err := n.up(context.Background(), upFlags{orgName: "local", oidcNm: "sso", port: p})
	if err == nil || !regexp.MustCompile(`not ready within .*logs server`).MatchString(err.Error()) {
		t.Fatalf("up = %v", err)
	}
}

func TestNodeProject_PerDirectory(t *testing.T) {
	def := filepath.Join(t.TempDir(), "node")
	if p := nodeProject(def, def); p != "pantherclaw-node" {
		t.Errorf("default dir: %s", p)
	}
	a, b := nodeProject(filepath.Join(def, "a"), def), nodeProject(filepath.Join(def, "b"), def)
	if a == b || !strings.HasPrefix(a, "pantherclaw-node-") {
		t.Errorf("projects %s %s", a, b)
	}
}
