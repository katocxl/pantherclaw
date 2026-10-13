// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

type watchEnv struct {
	pool *db.Pool
	org  ids.OrgID
	gw   ids.UUID
}

func newWatchEnv(t *testing.T) watchEnv {
	t.Helper()
	d := dbtest.New(t)
	e := watchEnv{pool: d.AppPool(t), org: ids.New[ids.Org](), gw: ids.NewV7()}
	e.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'watch')", e.org)
	e.exec(t, "INSERT INTO pc.org_containment (org_id) VALUES ($1)", e.org)
	e.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", e.org, e.gw)
	return e
}

func (e watchEnv) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// waitFor waits for the subscription to show cond, or fails after limit.
func waitFor(t *testing.T, s *Subscription, limit time.Duration, cond func(Containment) bool) time.Duration {
	t.Helper()
	start := time.Now()
	deadline := time.After(limit)
	for {
		if c, fresh := s.State(); fresh && cond(c) {
			return time.Since(start)
		}
		select {
		case <-s.Changed():
		case <-deadline:
			c, fresh := s.State()
			t.Fatalf("no matching state within %s: %+v fresh=%v", limit, c, fresh)
		}
	}
}

// TestHR010_ContainmentChangesReachTheStreamWithinASecond: with LISTEN
// running, an epoch bump, the kill switch and a configuration change made
// by any use case reach a subscription well within a second.
func TestHR010_ContainmentChangesReachTheStreamWithinASecond(t *testing.T) {
	e := newWatchEnv(t)
	h := NewHub(e.pool, pclog.Discard())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.Run(ctx) }()
	s, err := h.Subscribe(Identity{Org: e.org, Gateway: e.gw, Cert: ids.NewV7()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	waitFor(t, s, 5*time.Second, func(c Containment) bool { return c.Epoch == 1 && c.GatewayActive })

	e.exec(t, "UPDATE pc.org_containment SET epoch = epoch + 1 WHERE org_id = $1", e.org)
	if d := waitFor(t, s, time.Second, func(c Containment) bool { return c.Epoch == 2 }); d > time.Second {
		t.Fatalf("epoch took %s", d)
	}
	e.exec(t, `UPDATE pc.org_containment SET kill_switch = true, epoch = epoch + 1, engaged_by = 'x', engaged_at = now(),
		engage_reason = 'x' WHERE org_id = $1`, e.org)
	waitFor(t, s, time.Second, func(c Containment) bool { return c.KillSwitch && c.Epoch == 3 })
	e.exec(t, "UPDATE pc.gateways SET config_version = config_version + 1 WHERE id = $1", e.gw)
	waitFor(t, s, time.Second, func(c Containment) bool { return c.ConfigVersion == 2 })
	e.exec(t, "UPDATE pc.gateways SET state = 'REVOKED', revoked_by = 'x', revoked_at = now() WHERE id = $1", e.gw)
	waitFor(t, s, time.Second, func(c Containment) bool { return !c.GatewayActive })
}

// TestHR010_WithoutNotificationsThePollStillCatchesChanges: with no LISTEN
// connection (Run not running), a change still arrives within the poll.
func TestHR010_WithoutNotificationsThePollStillCatchesChanges(t *testing.T) {
	e := newWatchEnv(t)
	h := NewHub(e.pool, pclog.Discard())
	s, err := h.Subscribe(Identity{Org: e.org, Gateway: e.gw, Cert: ids.NewV7()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	waitFor(t, s, 5*time.Second, func(c Containment) bool { return c.Epoch == 1 })
	e.exec(t, "UPDATE pc.org_containment SET epoch = epoch + 1 WHERE org_id = $1", e.org)
	waitFor(t, s, 2*PollEvery+time.Second, func(c Containment) bool { return c.Epoch == 2 })
}

// TestHR010_TheServerSendsOnlyWhatItConfirmed: a view the server has not
// confirmed from the database within a second is not fresh, so streams go
// quiet and gateways fail closed.
func TestHR010_TheServerSendsOnlyWhatItConfirmed(t *testing.T) {
	e := newWatchEnv(t)
	h := NewHub(e.pool, pclog.Discard())
	var mu sync.Mutex
	shift := time.Duration(0)
	h.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return time.Now().Add(shift)
	}
	s, err := h.Subscribe(Identity{Org: e.org, Gateway: e.gw, Cert: ids.NewV7()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	waitFor(t, s, 5*time.Second, func(Containment) bool { return true })
	// The server stops reading containment (as when the database is
	// unreachable), and time passes.
	s.w.stop()
	time.Sleep(2 * PollEvery)
	mu.Lock()
	shift = ConfirmedWithin + time.Second
	mu.Unlock()
	if _, fresh := s.State(); fresh {
		t.Fatal("a view the server has not confirmed for over a second is fresh")
	}
}

// TestHR190_TheStreamHintsThatVerificationsAreWaiting: a gateway's view
// says verifications are waiting exactly while a task is due on one of its
// active connections and the kill switch is off, as ClaimVerifications
// would lease it; the hint is not containment, so it never makes two
// views unequal (G0 M7 design decision 1).
func TestHR190_TheStreamHintsThatVerificationsAreWaiting(t *testing.T) {
	e := newWatchEnv(t)
	other := ids.NewV7()
	e.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'other', 'test')", e.org, other)
	mine, theirs := ids.NewV7(), ids.NewV7()
	for _, c := range []struct {
		id, gw ids.UUID
		name   string
	}{{mine, e.gw, "mine"}, {theirs, other, "theirs"}} {
		e.exec(t, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, created_by, updated_by)
			VALUES ($1, $2, $3, 'http', $4, 'pc.mock-payments', 'https://payments.example.test', 'none', 'test', 'test')`, e.org, c.id, c.name, c.gw)
	}
	task := func(conn ids.UUID, due string) ids.UUID {
		id := ids.NewV7()
		e.exec(t, `INSERT INTO pc.verifications (org_id, id, purpose, connection_id, operation, request, next_at, deadline_at, window_start, window_end)
			VALUES ($1, $2, 'target_log', $3, 'payments.refund.recent', '{}', now() + $4::interval, now() + interval '15 minutes',
			        now() - interval '1 hour', now())`, e.org, id, conn, due)
		return id
	}
	h := NewHub(e.pool, pclog.Discard())
	s, err := h.Subscribe(Identity{Org: e.org, Gateway: e.gw, Cert: ids.NewV7()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	limit := 2*PollEvery + 5*time.Second
	waitFor(t, s, limit, func(c Containment) bool { return c.GatewayActive && !c.VerificationsWaiting })

	task(theirs, "0 seconds")
	later := task(mine, "1 hour")
	// A read that sees the new epoch sees the tasks too.
	e.exec(t, "UPDATE pc.org_containment SET epoch = epoch + 1 WHERE org_id = $1", e.org)
	waitFor(t, s, limit, func(c Containment) bool { return c.Epoch == 2 && len(c.Connections) == 1 })
	if c, _ := s.State(); c.VerificationsWaiting {
		t.Fatal("another gateway's task, or one not yet due, set the hint")
	}

	e.exec(t, "UPDATE pc.verifications SET next_at = now() WHERE id = $1", later)
	waitFor(t, s, limit, func(c Containment) bool { return c.VerificationsWaiting })
	if c, _ := s.State(); !c.Equal(Containment{
		Epoch: c.Epoch, KillSwitch: c.KillSwitch, ConfigVersion: c.ConfigVersion, GatewayActive: c.GatewayActive, Connections: c.Connections,
	}) {
		t.Fatal("the hint made the containment view change")
	}

	e.exec(t, `UPDATE pc.org_containment SET kill_switch = true, epoch = epoch + 1, engaged_by = 'x', engaged_at = now(),
		engage_reason = 'x' WHERE org_id = $1`, e.org)
	waitFor(t, s, limit, func(c Containment) bool { return c.KillSwitch && !c.VerificationsWaiting })
	e.exec(t, "UPDATE pc.org_containment SET kill_switch = false, engaged_by = NULL, engaged_at = NULL, engage_reason = NULL WHERE org_id = $1", e.org)
	waitFor(t, s, limit, func(c Containment) bool { return !c.KillSwitch && c.VerificationsWaiting })

	e.exec(t, "UPDATE pc.connections SET state = 'QUARANTINED', quarantine_reason = 'test' WHERE id = $1", mine)
	waitFor(t, s, limit, func(c Containment) bool { return c.Connections[mine] == "QUARANTINED" && !c.VerificationsWaiting })
	e.exec(t, "UPDATE pc.connections SET state = 'ACTIVE', quarantine_reason = NULL WHERE id = $1", mine)
	waitFor(t, s, limit, func(c Containment) bool { return c.VerificationsWaiting })

	e.exec(t, "UPDATE pc.verifications SET state = 'DONE', finished_at = now() WHERE id = $1", later)
	waitFor(t, s, limit, func(c Containment) bool { return !c.VerificationsWaiting })
}

// TestHR010_StreamsArePerCertificateCapped: at most MaxStreamsPerCert
// streams per certificate; closing one frees a slot.
func TestHR010_StreamsArePerCertificateCapped(t *testing.T) {
	e := newWatchEnv(t)
	h := NewHub(e.pool, pclog.Discard())
	id := Identity{Org: e.org, Gateway: e.gw, Cert: ids.NewV7()}
	var subs []*Subscription
	for range MaxStreamsPerCert {
		s, err := h.Subscribe(id)
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, s)
	}
	if _, err := h.Subscribe(id); !errors.Is(err, ErrTooManyStreams) {
		t.Fatalf("stream %d: %v", MaxStreamsPerCert+1, err)
	}
	subs[0].Close()
	s, err := h.Subscribe(id)
	if err != nil {
		t.Fatalf("after a close: %v", err)
	}
	s.Close()
	for _, s := range subs[1:] {
		s.Close()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.orgs) != 0 || len(h.streams) != 0 {
		t.Fatalf("the hub kept %d orgs and %d certificates after every stream closed", len(h.orgs), len(h.streams))
	}
}
