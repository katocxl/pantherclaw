// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

// Package e2e runs the M1.5 walking skeleton end to end: pantherclaw-server
// (API + workers, dev gateway), pantherclaw-sim payments and the gateway,
// against a throwaway database. Scenario ids follow BUILD_GUIDE §8 (M6 exit
// table); M1.5 covers the subset that needs no policies or approvals.
package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/gateway"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/notifications/smtptest"
	"github.com/katocxl/pantherclaw/internal/platform/config"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/server"
	"github.com/katocxl/pantherclaw/internal/sim/payments"
)

func noEnv(string) (string, bool) { return "", false }

// stack is one running skeleton bound to one seeded org.
type stack struct {
	db       *dbtest.DB
	pool     *db.Pool // the app role's pool, for the test's own queries
	org      ids.OrgID
	gateway  string
	sim      *payments.Server
	simURL   string
	simCalls *atomic.Int64 // dispatches (non-GET requests) the target received
	stop     context.CancelFunc
	done     chan struct{} // closed when the server has stopped
	apiURL   string
	// kek is the server's key-encryption key file: a test loads the
	// server's signing keys with it to sign as the server does.
	kek string
	// serverCfg is the server's configuration file and logs its output, for
	// a restart (serve).
	serverCfg string
	logs      syncBuffer

	// The gateway's configuration and its enrollment file (mTLS, M6), the
	// running gateway and the seeded payments connection.
	gatewayCfg    gateway.Config
	gatewayEnroll string
	gw            *gateway.Gateway
	conn          ids.UUID
	// approverKeys is the gateway's approver keys file (HR-038): dev seed
	// writes it next to the enrollment file, and approver exports it again
	// once a person has a key.
	approverKeys string

	// The seeded PAP/1 workload: its key file and key, its workload token
	// and its run.
	keyFile string
	key     ed25519.PrivateKey
	token   string
	run     string
}

type options struct {
	budget   string
	maxCount int
	faults   payments.Faults
	timeout  time.Duration
	// access is the payments connection's access mode (dev seed
	// --access-mode); empty is none.
	access string
	// token is the bearer token the target requires, and the credential a
	// pantherclaw_held connection gets sealed (HR-061).
	token string
	// actionTokens makes the target require an action token for the
	// payments connection (target_enforced, PAP-1 §10).
	actionTokens bool
	// shell also seeds pc.shell and the hook connection "shell" (dev seed
	// --shell).
	shell bool
	// people serves the API at http://localhost (security keys need a
	// name) with this OIDC provider and, with relay, email (M5 part 2).
	people *idp
	relay  *smtptest.Server
}

func freeAddr(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().String()
}

func writeFile(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

var (
	seededOrg        = regexp.MustCompile(`seeded org ([0-9a-f-]{36}) `)
	seededConnection = regexp.MustCompile(`seeded connection ([0-9a-f-]{36}) `)
)

func start(t *testing.T, o options) *stack {
	t.Helper()
	s := &stack{db: dbtest.New(t), simCalls: &atomic.Int64{}}
	dir := t.TempDir()
	kek := filepath.Join(dir, "kek")
	s.kek = kek
	if err := keys.GenerateKEKFile(kek); err != nil {
		t.Fatal(err)
	}
	apiAddr, gwAPIAddr := freeAddr(t), freeAddr(t)
	cfg := map[string]any{
		"role": "all", "log": map[string]any{"level": "warn"}, "http": map[string]any{"addr": apiAddr},
		"database": map[string]any{
			"host": s.db.App.Host, "port": s.db.App.Port, "name": s.db.Name, "sslmode": "disable",
			"app_password_file":      writeFile(t, dir, "app-pw", s.db.App.Password.Reveal()),
			"migrator_password_file": writeFile(t, dir, "mig-pw", s.db.Migrator.Password.Reveal()),
			"max_conns":              10,
		},
		"kek_files": []string{kek}, "worker_concurrency": 2,
	}
	// Workload proofs name the address they are sent to.
	cfg["auth"] = map[string]any{"public_url": "http://" + apiAddr}
	public := "http://" + apiAddr
	if o.people != nil {
		public = withPeople(t, cfg, dir, apiAddr, *o.people, o.relay)
	}
	// The gateway reaches the Authority only over mTLS (HR-181).
	cfg["gateway_api"] = map[string]any{"addr": gwAPIAddr, "hostnames": []string{"127.0.0.1"}, "url": "https://" + gwAPIAddr}
	write := func(name string) string {
		b, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return writeFile(t, dir, name, b)
	}

	// dev seed points the "payments" connection at the simulator's address;
	// the simulator starts once the connection exists, because a
	// target-enforced target checks that its action tokens name it.
	simSrv := httptest.NewUnstartedServer(nil)
	t.Cleanup(simSrv.Close)
	s.simURL, s.apiURL = "http://"+simSrv.Listener.Addr().String(), public

	enrollFile, keyFile, factsFile := filepath.Join(dir, "gateway.json"), filepath.Join(dir, "workload.json"), filepath.Join(dir, "facts.key")
	args := []string{
		"dev", "seed", "--config", write("seed.json"), "--org-name", "e2e", "--budget-limit", o.budget, "--gateway-out", enrollFile,
		"--target-url", s.simURL, "--workload-out", keyFile, "--facts-key-out", factsFile,
	}
	if o.maxCount > 0 {
		args = append(args, "--max-count", fmt.Sprint(o.maxCount))
	}
	if o.access != "" {
		args = append(args, "--access-mode", o.access)
	}
	if o.shell {
		args = append(args, "--shell")
	}
	var out, errb bytes.Buffer
	if code := server.Run(context.Background(), args, &out, &errb, noEnv); code != 0 {
		t.Fatalf("dev seed: %d %s", code, errb.String())
	}
	m, c := seededOrg.FindStringSubmatch(out.String()), seededConnection.FindStringSubmatch(out.String())
	if m == nil || c == nil {
		t.Fatalf("dev seed output %q", out.String())
	}
	s.org, s.conn = ids.MustParse[ids.Org](m[1]), mustUUID(t, c[1])
	s.pool = s.db.AppPool(t)

	require := payments.Require{Token: o.token}
	if o.actionTokens {
		require.ActionTokens = &payments.ActionVerifier{JWKSURL: s.apiURL + "/.well-known/pantherclaw/jwks.json", Audience: s.conn.String()}
	}
	s.sim = payments.New(o.faults, pclog.Discard()).WithRequire(require)
	simSrv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// simCalls counts dispatches (writes). The reads the gateway makes
		// to verify effects and list the target log (G0 M7) are not
		// dispatches, and never retry one.
		if r.Method != http.MethodGet {
			s.simCalls.Add(1)
		}
		s.sim.Handler().ServeHTTP(w, r)
	})
	simSrv.Start()
	if o.timeout > 0 {
		// The connection's dispatch timeout; the gateway reads it with its
		// first configuration.
		err := s.db.AppPool(t).InTenantTx(context.Background(), s.org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, "UPDATE pc.connections SET timeout_ms = $1", o.timeout.Milliseconds())
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	s.serverCfg = write("server.json")
	s.serve(t)
	s.keyFile = keyFile
	s.workload(t, keyFile)
	refundable(t, "http://"+apiAddr, factsFile, "ch_1")

	gs := httptest.NewUnstartedServer(nil)
	gc := gateway.DefaultConfig()
	gc.PublicURL = "http://" + gs.Listener.Addr().String()
	gc.Control.IdentityDir = filepath.Join(dir, "gateway-identity")
	// The operator lets the gateway reach the local simulator (HR-077).
	gc.Egress.AllowedPrefixes = []string{"127.0.0.1/32"}
	// Several sessions' suites share one test database on a laptop; a slow
	// Authorize there is not the Authority being down (S09 stops it).
	gc.Control.Timeout = config.Duration(10 * time.Second)
	// Verification tasks are claimed every second rather than every ten
	// (G0 M7), so effects are verified within a test's patience.
	gc.Control.VerifyEvery = config.Duration(time.Second)
	// The approver keys file dev seed wrote next to the enrollment file
	// (HR-038), as deploy/dev/gateway.example.json pins it.
	s.approverKeys = filepath.Join(dir, "approver-keys.json")
	gc.Approvals.ApproverKeysFile = s.approverKeys
	if o.access == "pantherclaw_held" {
		// The gateway's broker key, which only it can open credentials with
		// (HR-061); it registers the public half when it starts.
		gc.Broker.KEKFiles = []string{filepath.Join(dir, "gateway-kek")}
		gc.Broker.KeyFile = filepath.Join(dir, "broker.json")
		if err := keys.GenerateKEKFile(gc.Broker.KEKFiles[0]); err != nil {
			t.Fatal(err)
		}
		if _, err := broker.Generate(context.Background(), gc.Broker.KeyFile, gc.Broker.KEKFiles); err != nil {
			t.Fatal(err)
		}
	}
	s.gatewayCfg = gc
	s.gatewayEnroll = enrollFile
	s.gw = s.startGateway(t)
	gs.Config.Handler = s.gw.Handler()
	gs.Start()
	t.Cleanup(gs.Close)
	s.gateway = gs.URL
	if o.access == "pantherclaw_held" {
		s.waitConfig(t, s.sealCredential(t, o.token))
	}
	return s
}

// startGateway enrolls the gateway from the dev enrollment file on first
// use (it then reloads the saved identity) and runs its background work
// (certificate renewal) until the test ends.
func (s *stack) startGateway(t *testing.T) *gateway.Gateway {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	id, err := gateway.LoadOrEnroll(ctx, &s.gatewayCfg, s.gatewayEnroll, pclog.Discard())
	if err != nil {
		t.Fatal(err)
	}
	g, err := gateway.New(ctx, &s.gatewayCfg, id, pclog.Discard())
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = g.Run(ctx) }()
	// Like `serve`, take no request before the first containment snapshot.
	if err := g.WaitReady(ctx, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	return g
}

// serve starts the server (again, after stopServer). It stops when the test
// ends or s.stop is called; s.done closes once it has.
func (s *stack) serve(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s.stop, s.done = cancel, done
	go func() {
		defer close(done)
		if err := runServer(ctx, s.serverCfg, &s.logs); err != nil {
			t.Errorf("%v\n%s", err, s.logs.String())
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
	waitReady(t, s.apiURL, &s.logs)
}

// stopServer stops the server and waits until it has.
func (s *stack) stopServer(t *testing.T) {
	t.Helper()
	s.stop()
	select {
	case <-s.done:
	case <-time.After(30 * time.Second):
		t.Fatal("server did not stop")
	}
}

func runServer(ctx context.Context, cfgPath string, logs io.Writer) error {
	if code := server.Run(ctx, []string{"serve", "--config", cfgPath}, io.Discard, logs, noEnv); code != 0 {
		return fmt.Errorf("serve exited %d", code)
	}
	return nil
}

func waitReady(t *testing.T, base string, logs *syncBuffer) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, base+"/readyz", nil)
		if resp, err := http.DefaultTransport.RoundTrip(req); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("server not ready:\n%s", logs.String())
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// reply is the gateway's answer: on success the target's body with
// PantherClaw's facts in PC-* headers, otherwise a typed refusal (F642).
type reply struct {
	ErrorClass    string   `json:"error_class"`
	Error         string   `json:"error"`
	Decision      string   `json:"decision"`
	Reasons       []string `json:"reasons"`
	TransactionID string   `json:"transaction_id"`
	Outcome       string   `json:"outcome"`
	Receipt       string   `json:"receipt"`
}

func (s *stack) refund(t *testing.T, act ids.UUID, amount string) (int, reply) {
	t.Helper()
	code, r, err := s.tryRefund(act, amount)
	if err != nil {
		t.Fatal(err)
	}
	return code, r
}

// tryRefund sends a refund through the payments connection as the seeded
// workload, in its run, signed with PAP/1. It is safe to call from any
// goroutine.
func (s *stack) tryRefund(act ids.UUID, amount string) (int, reply, error) {
	return s.tryRefundVia("payments", act, amount)
}

// tryRefundVia is tryRefund through the connection named conn.
func (s *stack) tryRefundVia(conn string, act ids.UUID, amount string) (int, reply, error) {
	body := `{"charge":"ch_1","amount":"` + amount + `","currency":"USD","reason":"duplicate"}`
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, s.gateway+"/"+conn+"/v1/refunds", strings.NewReader(body))
	req.Header.Set(gateway.HeaderRunID, s.run)
	req.Header.Set(gateway.HeaderActionID, act.String())
	client := &http.Client{Timeout: 30 * time.Second, Transport: &workloadclient.Transport{
		Key: s.key, Token: func() string { return s.token }, Base: http.DefaultTransport,
	}}
	resp, err := client.Do(req)
	if err != nil {
		return 0, reply{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	var r reply
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		if err := json.Unmarshal(b, &r); err != nil {
			return 0, reply{}, fmt.Errorf("gateway refusal %q: %w", b, err)
		}
		return resp.StatusCode, r, nil
	}
	r.TransactionID, r.Outcome, r.Receipt = resp.Header.Get("PC-Transaction-Id"), resp.Header.Get("PC-Outcome"), resp.Header.Get("PC-Receipt")
	return resp.StatusCode, r, nil
}

// budget returns the reserved and spent amounts of the seeded grant's task
// budget and the state of txn's permit.
func (s *stack) budget(t *testing.T, txn string) (reserved, spent, permit string) {
	t.Helper()
	err := s.db.AppPool(t).InTenantTx(context.Background(), s.org, func(ctx context.Context, tx db.TenantTx) error {
		// The account exists from the first reservation; before it, both are
		// 0. Outcomes recorded but not yet applied to the row by the
		// settlement job count as settled (ADR-0015).
		if err := tx.QueryRow(ctx, `SELECT
			((SELECT coalesce(sum(reserved), 0) FROM pc.budget_accounts)
			 - (SELECT coalesce(sum(amount), 0) FROM pc.reservations WHERE pending AND account_id IS NOT NULL))::float8::text,
			((SELECT coalesce(sum(spent), 0) FROM pc.budget_accounts)
			 + (SELECT coalesce(sum(amount), 0) FROM pc.reservations WHERE pending AND state = 'COMMITTED' AND account_id IS NOT NULL))::float8::text`).
			Scan(&reserved, &spent); err != nil {
			return err
		}
		if txn == "" {
			return nil
		}
		return tx.QueryRow(ctx, "SELECT state FROM pc.permits WHERE transaction_id = $1", txn).Scan(&permit)
	})
	if err != nil {
		t.Fatal(err)
	}
	return reserved, spent, permit
}

// waitSettled waits until the worker's settlement job has applied every
// recorded outcome to the budget rows (ADR-0015): nothing is pending and
// the rows' spent total is spent.
func (s *stack) waitSettled(t *testing.T, spent string) {
	t.Helper()
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		var pending int
		var rows string
		if err := s.pool.InTenantTx(context.Background(), s.org, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM pc.reservations WHERE pending)::integer,
				(SELECT coalesce(sum(spent), 0) FROM pc.budget_accounts)::float8::text`).Scan(&pending, &rows)
		}); err != nil {
			t.Fatal(err)
		}
		if pending == 0 && rows == spent {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("after 30s: %d reservations pending, rows spent %s, want %s", pending, rows, spent)
		}
	}
}

// S01: $30 within the grant is accepted, with exactly one effect when the
// agent retries.
func TestS01_ARefundWithinTheGrantIsAcceptedOnce(t *testing.T) {
	s := start(t, options{budget: "1000.00"})
	act := ids.NewV7()
	code, r := s.refund(t, act, "30.00")
	if code != http.StatusOK || r.Outcome != "ACCEPTED" || r.Receipt == "" {
		t.Fatalf("S01: %d %+v", code, r)
	}
	if reserved, spent, permit := s.budget(t, r.TransactionID); reserved != "0" || spent != "30" || permit != "DISPATCHED" {
		t.Fatalf("S01 budget reserved=%s spent=%s permit=%s", reserved, spent, permit)
	}
	// The worker applies the commit to the budget row itself (ADR-0015).
	s.waitSettled(t, "30")
	// The agent retries the same action: no second permit, no second refund.
	if code, r2 := s.refund(t, act, "30.00"); code != http.StatusConflict || r2.TransactionID != r.TransactionID {
		t.Fatalf("S01 retry: %d %+v", code, r2)
	}
	if st := s.sim.Stats(); st.Refunds != 1 || st.Replays != 0 {
		t.Fatalf("S01 target stats %+v", st)
	}
}

// S03: $125 is over the grant's $100 per refund: DENY, with nothing
// reserved or sent. "Even if a manager tries to approve" needs M5 part 2's
// approvals (M6 slice 23).
func TestS03_ARefundOverTheGrantIsDenied(t *testing.T) {
	s := start(t, options{budget: "1000.00"})
	code, r := s.refund(t, ids.NewV7(), "125.00")
	if code != http.StatusForbidden || r.Decision != "DENY" || len(r.Reasons) == 0 || r.Reasons[0] != "GRANT_LIMIT_EXCEEDED" {
		t.Fatalf("S03: %d %+v", code, r)
	}
	if reserved, spent, _ := s.budget(t, ""); reserved != "0" || spent != "0" || s.simCalls.Load() != 0 {
		t.Fatalf("S03 reserved=%s spent=%s target calls=%d", reserved, spent, s.simCalls.Load())
	}
}

// S06: two concurrent refunds against a one-refund budget: exactly one.
func TestS06_ConcurrentRefundsAgainstOneRefundBudget(t *testing.T) {
	s := start(t, options{budget: "1000.00", maxCount: 1})
	var wg sync.WaitGroup
	codes := make([]int, 8)
	errs := make([]error, len(codes))
	for i := range codes {
		wg.Go(func() { codes[i], _, errs[i] = s.tryRefund(ids.NewV7(), "30.00") })
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		t.Fatal(err)
	}
	ok := 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusForbidden:
		default:
			t.Errorf("unexpected status %d", c)
		}
	}
	if ok != 1 || s.sim.Stats().Refunds != 1 {
		t.Fatalf("S06: %d succeeded (%v), target refunds %d", ok, codes, s.sim.Stats().Refunds)
	}
}

// S07: the target never answers: UNKNOWN, reservation held, no retry.
func TestS07_TargetTimeoutIsUnknownAndHeld(t *testing.T) {
	s := start(t, options{budget: "1000.00", faults: payments.Faults{HangRate: 1, HangFor: time.Minute}, timeout: 500 * time.Millisecond})
	code, r := s.refund(t, ids.NewV7(), "30.00")
	if code != http.StatusGatewayTimeout || r.Outcome != "UNKNOWN" {
		t.Fatalf("S07: %d %+v", code, r)
	}
	if reserved, spent, permit := s.budget(t, r.TransactionID); reserved != "30" || spent != "0" || permit != "UNKNOWN" {
		t.Fatalf("S07 reserved=%s spent=%s permit=%s, want held", reserved, spent, permit)
	}
	time.Sleep(2 * time.Second) // a sweep or two: the reservation stays held
	if reserved, _, permit := s.budget(t, r.TransactionID); reserved != "30" || permit != "UNKNOWN" || s.simCalls.Load() != 1 {
		t.Fatalf("S07 after sweeps reserved=%s permit=%s target calls=%d", reserved, permit, s.simCalls.Load())
	}
}

// S09: the Authority is down: fail closed, nothing dispatched.
func TestS09_AuthorityUnavailableDispatchesNothing(t *testing.T) {
	s := start(t, options{budget: "1000.00"})
	s.stopServer(t)
	code, r := s.refund(t, ids.NewV7(), "30.00")
	if code != http.StatusServiceUnavailable || r.Error != "authority_unavailable" || s.simCalls.Load() != 0 {
		t.Fatalf("S09: %d %+v, target calls %d", code, r, s.simCalls.Load())
	}
}

// workload loads the seeded workload and gets its token from the server.
func (s *stack) workload(t *testing.T, keyFile string) {
	t.Helper()
	kf, err := workloadclient.ReadKeyFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if s.key, err = kf.Key(); err != nil {
		t.Fatal(err)
	}
	wc := pantherclawv1connect.NewWorkloadServiceClient(connect.NewClient(connecthttp.NewTransport(
		&http.Client{Timeout: 10 * time.Second, Transport: &workloadclient.Transport{Key: s.key}}, kf.Server)))
	res, err := wc.IssueToken(context.Background(), &pantherclawv1.IssueTokenRequest{Identifier: kf.Identifier})
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	s.token, s.run = res.GetWorkloadToken(), kf.RunID
}
