// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration && failover

package e2e

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/server"
	"github.com/katocxl/pantherclaw/test/failover"
)

// The local failover tests (G0 M19 D202, D213; `task failover`). Each runs
// in its own test process against a fresh compose profile `failover`: the
// test database is created on the primary (PC_TEST_PG_ADMIN_URL names
// 127.0.0.1:5434), the server connects with database.hosts naming the
// primary and the standby, and the test kills the primary and promotes the
// standby. Timings drift on a laptop, so the tests assert bounds only.

// reconnectBound is how soon after the promotion a sync-verified server
// serves again, and containment reaches the gateways (D202).
const reconnectBound = 2 * time.Second

// failoverStack starts the cluster for v and the e2e stack on it, then
// restarts the server with both hosts and the declared replication.
func failoverStack(t *testing.T, v failover.Variant, replication db.Replication) (*stack, *failover.Cluster) {
	t.Helper()
	c, err := failover.FromEnv(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := c.Start(ctx, v); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Stop(context.Background()) })
	s := start(t, options{budget: "1000.00", brokerKey: true})
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("server log:\n%s", s.logs.String())
		}
	})

	b, err := os.ReadFile(s.serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	hosts := []string{fmt.Sprintf("127.0.0.1:%d", failover.PrimaryPort), fmt.Sprintf("127.0.0.1:%d", failover.StandbyPort)}
	dbc := cfg["database"].(map[string]any)
	dbc["hosts"], dbc["replication"] = hosts, string(replication)
	if b, err = json.Marshal(cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.serverCfg, b, 0o600); err != nil {
		t.Fatal(err)
	}
	s.stopServer(t)
	s.serve(t)

	// The test's own queries follow the primary too.
	pc := db.Defaults()
	pc.Host, pc.Port, pc.Database, pc.SSLMode = strings.Join(hosts, ","), failover.PrimaryPort, s.db.Name, "disable"
	pc.User, pc.Password, pc.MaxConns = s.db.App.User, s.db.App.Password, 4
	s.pool = s.db.Pool(t, pc)
	return s, c
}

// refundAt sends one refund through the gateway at gw: a cent above $1
// more than the one before, so no two are the same action (an identical
// refund that recently succeeded asks for reconciliation).
func (s *stack) refundAt(gw string) (int, reply, error) {
	cents := 100 + refundSeq.Add(1)
	body := fmt.Sprintf(`{"charge":"ch_1","amount":"%d.%02d","currency":"USD","reason":"duplicate"}`, cents/100, cents%100)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, gw+"/payments/v1/refunds", strings.NewReader(body))
	req.Header.Set(gateway.HeaderRunID, s.run)
	req.Header.Set(gateway.HeaderActionID, ids.NewV7().String())
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
		_ = json.Unmarshal(b, &r)
		return resp.StatusCode, r, nil
	}
	r.Outcome = resp.Header.Get("PC-Outcome")
	if r.Outcome == "ACCEPTED" {
		acceptedCents.Add(cents)
	}
	return resp.StatusCode, r, nil
}

// refundSeq numbers the refunds; acceptedCents sums the accepted ones.
var refundSeq, acceptedCents atomic.Int64

// spent is the accepted total as the budget queries print it (float8).
func spent() string { return strconv.FormatFloat(float64(acceptedCents.Load())/100, 'f', -1, 64) }

// health returns the status of the server's /livez and /readyz.
func (s *stack) health() (live, ready int) {
	get := func(path string) int {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, s.apiURL+path, nil)
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			return 0
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	return get("/livez"), get("/readyz")
}

// waitHealth polls until the server's /livez and /readyz answer live and
// ready, and returns how long that took.
func (s *stack) waitHealth(t *testing.T, live, ready int, within time.Duration) time.Duration {
	t.Helper()
	since := time.Now()
	for {
		l, r := s.health()
		if l == live && r == ready {
			return time.Since(since)
		}
		if time.Since(since) > within {
			t.Fatalf("after %s: /livez %d /readyz %d, want %d %d\n%s", within, l, r, live, ready, s.logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// serveUnready starts the server like serve, without waiting for /readyz:
// it is expected to start in the maintenance hold.
func (s *stack) serveUnready(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s.stop, s.done = cancel, done
	go func() {
		defer close(done)
		_ = runServer(ctx, s.serverCfg, &s.logs)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

// refused checks that n refunds through every gateway are all refused and
// reach no target.
func (s *stack) refused(t *testing.T, step string, n int, gws ...string) {
	t.Helper()
	before := s.simCalls.Load()
	for i := range n {
		for _, gw := range gws {
			if code, r, err := s.refundAt(gw); err == nil && code < 300 {
				t.Fatalf("%s: refund %d through %s answered %d %+v, want refused", step, i, gw, code, r)
			}
		}
	}
	if got := s.simCalls.Load(); got != before {
		t.Fatalf("%s: %d dispatches reached the target", step, got-before)
	}
}

// accepted sends n refunds through each gateway, all accepted, and
// returns how many.
func (s *stack) accepted(t *testing.T, step string, n int, gws ...string) int {
	t.Helper()
	ok := 0
	for i := range n {
		for _, gw := range gws {
			code, r, err := s.refundAt(gw)
			if err != nil || code != http.StatusOK || r.Outcome != "ACCEPTED" {
				t.Fatalf("%s: refund %d through %s: %d %+v %v\n%s", step, i, gw, code, r, err, s.logs.String())
			}
			ok++
		}
	}
	return ok
}

// TestFailover_SyncPromotion: steady refunds through two gateway replicas;
// the primary killed; no refund accepted or sent while no read-write
// primary answers (a standby is never used); the sync standby promoted;
// the server ready again within 2 s, containment reaching both gateways
// within 2 s, the worker settling again, and every accepted refund sent
// once and spent once (G0 M19 D202, D213; map §5 steps 1-5).
// Covers: PN-010.7
func TestFailover_SyncPromotion(t *testing.T) {
	s, c := failoverStack(t, failover.Sync, db.ReplicationSync)
	ctx := context.Background()
	gw2, _ := s.replica(t)
	watch := s.watchingGateway(t)
	gws := []string{s.gateway, gw2}

	total := s.accepted(t, "steady", 5, gws...)
	s.waitSettled(t, spent())

	if err := c.KillPrimary(ctx); err != nil {
		t.Fatal(err)
	}
	s.refused(t, "no primary", 3, gws...)
	if _, ready := s.health(); ready == http.StatusOK {
		t.Fatal("/readyz is ready without a read-write primary")
	}

	if err := c.Promote(ctx); err != nil {
		t.Fatal(err)
	}
	promoted := time.Now()
	ready := s.waitHealth(t, http.StatusOK, http.StatusOK, reconnectBound)
	contained := s.suspensions(t, []*gateway.Gateway{s.gw, watch}, 1)[0]
	t.Logf("ready %s after the promotion; a suspension reached both gateways in %s (%s after the promotion)",
		ready, contained, time.Since(promoted))
	if contained > reconnectBound {
		t.Fatalf("containment reached the gateways after %s, over %s", contained, reconnectBound)
	}
	total += s.accepted(t, "after the promotion", 5, gws...)
	// The worker runs on the new primary: it settles every refund, and
	// nothing was dispatched or spent twice.
	s.waitSettled(t, spent())
	if got := s.simCalls.Load(); got != int64(total) {
		t.Fatalf("%d dispatches for %d accepted refunds", got, total)
	}
	// The promotion was verified at both ends, so its timeline is the
	// acknowledged one and a restart does not hold.
	var tl int64
	if err := s.pool.InGlobalTx(ctx, db.GlobalFailover, func(ctx context.Context, tx db.GlobalTx) error {
		return tx.QueryRow(ctx, "SELECT timeline FROM pc.db_primary_timeline").Scan(&tl)
	}); err != nil || tl != 2 {
		t.Fatalf("acknowledged timeline %d, %v, want 2", tl, err)
	}
}

// TestT215_AsyncPromotionHoldsUntilTheEpochBump: behind an asynchronous
// standby a promotion may lose committed revocations or reservations, so
// the running server refuses the new primary (not ready, not live, nothing
// decided); restarted, it starts in the maintenance hold; `keys
// bump-epochs` raises every epoch and acknowledges the timeline, and the
// next start serves again (G0 M19 D202, D213, HR-496; map §5 step 6).
// Covers: PN-010.7
func TestT215_AsyncPromotionHoldsUntilTheEpochBump(t *testing.T) {
	s, c := failoverStack(t, failover.Async, db.ReplicationAsync)
	ctx := context.Background()
	s.accepted(t, "steady", 3, s.gateway)
	var epoch int64
	s.query(t, "SELECT epoch FROM pc.org_containment", nil, &epoch)

	if err := c.KillPrimary(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Promote(ctx); err != nil {
		t.Fatal(err)
	}
	s.waitHealth(t, http.StatusServiceUnavailable, http.StatusServiceUnavailable, 30*time.Second)
	s.refused(t, "async promotion while running", 3, s.gateway)

	s.stopServer(t)
	s.serveUnready(t)
	s.waitHealth(t, http.StatusOK, http.StatusServiceUnavailable, 60*time.Second)
	s.refused(t, "the start-up hold", 3, s.gateway)

	var out, errb bytes.Buffer
	if code := server.Run(ctx, []string{"keys", "bump-epochs", "--all", "--confirm", "--config", s.serverCfg}, &out, &errb, noEnv); code != 0 {
		t.Fatalf("bump-epochs: %d %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "acknowledged database timeline 2") {
		t.Fatalf("bump-epochs output %q", out.String())
	}
	var bumped int64
	s.query(t, "SELECT epoch FROM pc.org_containment", nil, &bumped)
	if bumped <= epoch {
		t.Fatalf("epoch %d after the bump, was %d", bumped, epoch)
	}

	s.stopServer(t)
	s.serve(t)
	// The gateway takes the raised epoch from its next snapshot.
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		code, r, err := s.refundAt(s.gateway)
		if err == nil && code == http.StatusOK && r.Outcome == "ACCEPTED" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the bump: %d %+v %v\n%s", code, r, err, s.logs.String())
		}
	}
}

// TestFailover_SyncToAnUnverifiedPrimaryIsRefused: the server verified
// sync on the old primary, but the promoted standby waits for no standby
// of its own, so a commit there could be lost again: the running server
// refuses it like an asynchronous promotion (G0 M19 D213).
// Covers: PN-010.7
func TestFailover_SyncToAnUnverifiedPrimaryIsRefused(t *testing.T) {
	s, c := failoverStack(t, failover.SyncToUnverified, db.ReplicationSync)
	ctx := context.Background()
	s.accepted(t, "steady", 2, s.gateway)
	if err := c.KillPrimary(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Promote(ctx); err != nil {
		t.Fatal(err)
	}
	s.waitHealth(t, http.StatusServiceUnavailable, http.StatusServiceUnavailable, 30*time.Second)
	s.refused(t, "unverified sync promotion", 3, s.gateway)
}
