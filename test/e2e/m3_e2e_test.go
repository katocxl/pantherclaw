// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/oidctest"
	"github.com/katocxl/pantherclaw/internal/gateway"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/pclaw"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/server"
	"github.com/katocxl/pantherclaw/internal/sim/payments"
)

const subjectAudience = "pantherclaw-e2e"

// m3Stack is the server (with the development gateway and an OIDC provider
// that also signs subject tokens), the gateway and the simulated payments
// target, for one org created with the bootstrap token.
type m3Stack struct {
	*m2Stack
	db        *dbtest.DB
	idp       *oidctest.Provider
	org       string
	bootstrap string
	gateway   string
	// sim is the simulated payments API's URL.
	sim string
}

// connect creates the development "payments" connection to the simulator
// (once the org has the package) and waits until the gateway serves it.
func (s *m3Stack) connect(t *testing.T) {
	t.Helper()
	var out, errb bytes.Buffer
	if code := server.Run(context.Background(), []string{"dev", "connection", "--config", s.cfg, "--org", s.org, "--target-url", s.sim},
		&out, &errb, noEnv); code != 0 {
		t.Fatalf("dev connection: %d %s", code, errb.String())
	}
	deadline := time.Now().Add(90 * time.Second)
	for {
		// Without credentials the gateway answers 401 for a connection it
		// serves and 404 for one it does not know yet.
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, s.gateway+"/payments/v1/refunds", nil)
		resp, err := (&http.Client{}).Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the gateway did not load the new connection")
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func startM3(t *testing.T) *m3Stack {
	t.Helper()
	p := oidctest.New(t)
	d := dbtest.New(t)
	dir := t.TempDir()
	kek := filepath.Join(dir, "kek")
	if err := keys.GenerateKEKFile(kek); err != nil {
		t.Fatal(err)
	}
	apiAddr := freeAddr(t)
	public := "http://" + apiAddr
	cfg := map[string]any{
		"role": "all", "log": map[string]any{"level": "warn"}, "http": map[string]any{"addr": apiAddr},
		"database": map[string]any{
			"host": d.App.Host, "port": d.App.Port, "name": d.Name, "sslmode": "disable",
			"app_password_file":      writeFile(t, dir, "app-pw", d.App.Password.Reveal()),
			"migrator_password_file": writeFile(t, dir, "mig-pw", d.Migrator.Password.Reveal()),
			"max_conns":              10,
		},
		"kek_files": []string{kek}, "worker_concurrency": 2,
		"auth": map[string]any{
			"public_url": public, "api_key_env": "test",
			"oidc_providers": []map[string]any{{
				"name": "test", "issuer": p.Issuer(), "client_id": p.ClientID, "allow_insecure_loopback": true,
				"client_secret_file": writeFile(t, dir, "idp-secret", []byte(p.ClientSecret)), "subject_token_audience": subjectAudience,
			}},
		},
	}
	write := func(name string) string {
		b, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return writeFile(t, dir, name, b)
	}
	// The org exists before the server starts: the development gateway is
	// configured for it.
	var out, errb bytes.Buffer
	if code := server.Run(context.Background(), []string{"org", "create", "--config", write("bootstrap.json"), "--name", "Acme"}, &out, &errb, noEnv); code != 0 {
		t.Fatalf("org create: %d %s", code, errb.String())
	}
	s := &m3Stack{db: d, idp: p, org: orgCreated.FindStringSubmatch(out.String())[1], bootstrap: pciToken.FindString(out.String())}
	// The gateway reaches the Authority over mTLS with a certificate from
	// the internal CA (M6): a development enrollment file for this org.
	gwAPIAddr := freeAddr(t)
	cfg["gateway_api"] = map[string]any{"addr": gwAPIAddr, "hostnames": []string{"127.0.0.1"}, "url": "https://" + gwAPIAddr}
	serverCfg := write("server.json")
	enrollFile := filepath.Join(dir, "gateway.json")
	if code := server.Run(context.Background(), []string{"dev", "gateway", "--config", serverCfg, "--org", s.org, "--out", enrollFile}, &out, &errb, noEnv); code != 0 {
		t.Fatalf("dev gateway: %d %s", code, errb.String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var logs syncBuffer
	go func() {
		defer close(done)
		if err := runServer(ctx, serverCfg, &logs); err != nil {
			t.Errorf("%v\n%s", err, logs.String())
		}
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("server did not stop")
		}
	})
	waitReady(t, public, &logs)
	s.m2Stack = &m2Stack{url: public, cfg: serverCfg, idp: idp{
		issuer: p.Issuer(), clientID: p.ClientID, secret: p.ClientSecret,
		signIn: func(t *testing.T, b *http.Client, authURL, subject, email string) string {
			t.Helper()
			p.SignIn(oidctest.User{Subject: subject, Email: email, EmailVerified: true, Name: subject})
			return get(t, b, authURL).Location
		},
	}}

	sim := httptest.NewServer(payments.New(payments.Faults{}, pclog.Discard()).Handler())
	t.Cleanup(sim.Close)
	gs := httptest.NewUnstartedServer(nil)
	gc := gateway.DefaultConfig()
	gc.PublicURL = "http://" + gs.Listener.Addr().String()
	gc.Control.IdentityDir = filepath.Join(dir, "gateway-identity")
	gc.Egress.AllowedPrefixes = []string{"127.0.0.1/32"}
	gst := &stack{gatewayCfg: gc, gatewayEnroll: enrollFile}
	g := gst.startGateway(t)
	gs.Config.Handler = g.Handler()
	gs.Start()
	t.Cleanup(gs.Close)
	s.gateway, s.sim = gs.URL, sim.URL
	return s
}

// recorder keeps the last request a workload sent, body included.
type recorder struct {
	header http.Header
	body   []byte
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	b, _ := io.ReadAll(req.Body)
	r.header, r.body = req.Header.Clone(), b
	req.Body = io.NopCloser(bytes.NewReader(b))
	return http.DefaultTransport.RoundTrip(req)
}

// refund sends a refund to the gateway as a workload: key, token (empty
// for a key-only proof) and run.
func (s *m3Stack) refund(t *testing.T, key ed25519.PrivateKey, token, run string, base http.RoundTripper) (int, http.Header, string) {
	t.Helper()
	body := `{"charge":"ch_1","amount":"30.00","currency":"USD","reason":"duplicate"}`
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, s.gateway+"/payments/v1/refunds", strings.NewReader(body))
	req.Header.Set(gateway.HeaderRunID, run)
	req.Header.Set(gateway.HeaderActionID, ids.NewV7().String())
	if base == nil {
		base = http.DefaultTransport
	}
	c := &http.Client{Timeout: 30 * time.Second, Transport: &workloadclient.Transport{Key: key, Token: func() string { return token }, Base: base}}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

func (s *m3Stack) raw(t *testing.T, header http.Header, body []byte) (int, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, s.gateway+"/payments/v1/refunds", bytes.NewReader(body))
	req.Header = header.Clone()
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode, resp.Header.Get(gateway.HeaderError)
}

var (
	enrolledInstance = regexp.MustCompile(`instance ([0-9a-f-]{36}) is waiting`)
	enrolledPrint    = regexp.MustCompile(`Fingerprint: (\S+)`)
)

// TestE2E_M3_EnrollAdmitRunRefund is the M3 exit scenario: an owner
// creates an agent and an enrollment token; the workload enrolls with
// pclaw and the owner admits it by fingerprint; the owner starts a run and
// a refund goes through the gateway with PAP/1. Then a service account
// starts a run for a user with a subject token, and the refusals: a
// replayed proof, a stolen token without its key, an unknown key (which
// becomes a discovered agent) and a stale subject token.
func TestE2E_M3_EnrollAdmitRunRefund(t *testing.T) {
	s := startM3(t)
	alice := s.user(t, "alice", "alice@example.test")
	alice.login(t, s.org, s.bootstrap)
	must := func(args ...string) string {
		t.Helper()
		code, o, e := alice.pclaw(t, args...)
		if code != 0 {
			t.Fatalf("pclaw %s: %d %s %s", strings.Join(args, " "), code, o, e)
		}
		return o
	}
	team := field(t, must("team", "create", "--slug", "payments", "--name", "Payments"), "id")
	env := field(t, must("env", "create", "--team", team, "--slug", "prod", "--name", "Production", "--kind", "prod"), "id")
	var users struct {
		Users []struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"users"`
	}
	_ = json.Unmarshal([]byte(must("user", "list")), &users)
	aliceID := users.Users[0].ID
	for _, role := range []string{"agent_owner", "agent_admitter", "run_launcher"} {
		must("role", "bind", "--role", role, "--user", aliceID)
	}
	agent := field(t, must("agent", "create", "--name", "refunder", "--team", team, "--env", env, "--owner", aliceID, "--context", "service"), "id")
	work := t.TempDir()
	enrollFile, keyFile := filepath.Join(work, "enroll.token"), filepath.Join(work, "workload.json")
	must("agent", "enroll-token", agent, "--out", enrollFile)

	// The workload enrolls with its own key; the owner admits it by fingerprint.
	must("workload", "init", "--key-file", keyFile)
	o := must("workload", "enroll", "--key-file", keyFile, "--server", s.url, "--enrollment-token-file", enrollFile)
	inst, fp := enrolledInstance.FindStringSubmatch(o), enrolledPrint.FindStringSubmatch(o)
	if inst == nil || fp == nil {
		t.Fatalf("enroll output %q", o)
	}
	if code, _, _ := alice.pclaw(t, "workload", "enroll", "--key-file", keyFile, "--server", s.url, "--enrollment-token-file", enrollFile); code == 0 {
		t.Fatal("an enrollment token worked twice")
	}
	wrong := "A" + fp[1][1:]
	if fp[1][0] == 'A' {
		wrong = "B" + fp[1][1:]
	}
	if code, _, e := alice.pclaw(t, "instance", "admit", inst[1], "--fingerprint", wrong); code != 1 || !strings.Contains(e, "fingerprint") {
		t.Fatalf("wrong fingerprint: %d %s", code, e)
	}
	must("instance", "admit", inst[1], "--fingerprint", fp[1])
	// Since M4 a run uses only the grant it is bound to: the package, a
	// refundable fact and a grant for alice are seeded, and the run names the
	// grant.
	agentID, _ := ids.ParseUUID(agent)
	aliceUUID, _ := ids.ParseUUID(aliceID)
	grant := seedAuthority(t, s.db.AppPool(t), ids.MustParse[ids.Org](s.org), agentID, aliceUUID, "ch_1")
	s.connect(t)
	run := field(t, must("run", "start", agent, "--instance", inst[1], "--grant", grant, "--task", "refund ch_1"), "id")
	token := strings.TrimSpace(must("workload", "token", "--key-file", keyFile))
	kf, err := workloadclient.ReadKeyFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := kf.Key()

	rec := &recorder{}
	code, hdr, body := s.refund(t, key, token, run, rec)
	if code != http.StatusOK || hdr.Get("PC-Outcome") != "ACCEPTED" || hdr.Get(gateway.HeaderNonce) == "" {
		t.Fatalf("refund: %d %s", code, body)
	}

	// Refusals, each with its PAP-Error code.
	if code, e := s.raw(t, rec.header, rec.body); code != http.StatusUnauthorized || e != "proof_replay" {
		t.Errorf("replayed proof: %d %q", code, e)
	}
	_, thief, _ := ed25519.GenerateKey(nil)
	if code, hdr, _ := s.refund(t, thief, token, run, nil); code != http.StatusUnauthorized || hdr.Get(gateway.HeaderError) != "key_mismatch" {
		t.Errorf("stolen token: %d %q", code, hdr.Get(gateway.HeaderError))
	}
	_, stranger, _ := ed25519.GenerateKey(nil)
	if code, hdr, _ := s.refund(t, stranger, "", run, nil); code != http.StatusUnauthorized || hdr.Get(gateway.HeaderError) != "instance_not_admitted" {
		t.Errorf("unknown key: %d %q", code, hdr.Get(gateway.HeaderError))
	}
	if o := must("agent", "list", "--state", "discovered"); strings.Count(o, `"AGENT_STATE_DISCOVERED"`) != 1 {
		t.Errorf("the unknown key is not one discovered agent: %s", o)
	}

	// A service account starts a run for alice with her provider token.
	sa := field(t, must("sa", "create", "--name", "portal"), "id")
	must("role", "bind", "--role", "run_launcher", "--sa", sa)
	secret := field(t, must("apikey", "create", "--sa", sa, "--name", "portal", "--scope", "run.start", "--scope", "run.represent"), "secret")
	portal := s.user(t, "portal", "")
	asPortal := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := pclaw.Run(context.Background(), args, &out, &errb, portal.env("PANTHERCLAW_SERVER", s.url, "PANTHERCLAW_API_KEY", secret), pclaw.Options{})
		return code, out.String(), errb.String()
	}
	subject := func(age time.Duration) string {
		now := time.Now().Add(-age)
		f := filepath.Join(work, "subject-"+age.String())
		tok := s.idp.Token(map[string]any{
			"iss": s.idp.Issuer(), "sub": "alice", "aud": subjectAudience, "jti": ids.NewV7().String(),
			"iat": now.Unix(), "exp": now.Add(30 * time.Minute).Unix(),
		}, "")
		if err := os.WriteFile(f, []byte(tok), 0o600); err != nil {
			t.Fatal(err)
		}
		return f
	}
	code, o, e := asPortal("run", "start", agent, "--subject-token-file", subject(0))
	if code != 0 || !strings.Contains(o, "PRINCIPAL_SOURCE_SUBJECT_TOKEN") || !strings.Contains(o, aliceID) || !strings.Contains(o, sa) {
		t.Fatalf("represented run: %d %s %s", code, o, e)
	}
	if code, _, e := asPortal("run", "start", agent, "--subject-token-file", subject(10*time.Minute)); code != 1 || !strings.Contains(e, "subject token") {
		t.Fatalf("stale subject token: %d %s", code, e)
	}
}
