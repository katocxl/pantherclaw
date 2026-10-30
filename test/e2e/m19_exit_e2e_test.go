// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	gwapp "github.com/katocxl/pantherclaw/internal/gateways/app"
	"github.com/katocxl/pantherclaw/internal/gateways/ca"
	hostingapp "github.com/katocxl/pantherclaw/internal/hosting/app"
	hostingdomain "github.com/katocxl/pantherclaw/internal/hosting/domain"
	"github.com/katocxl/pantherclaw/internal/hosting/profile"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/ratelimit"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestE2E_M19_Exit is M19's exit journey (G0 M19 exit criteria, D225), one
// path per feature on one stack. The held budget row goes through the
// running gateway and server. The shared limit and the stream lease run two
// in-process replicas of their services against the stack's database, which
// is what they share. The hosted gateway runs the hosting service in the
// test against that database, with its own CA and a Team edition; no host
// process starts. Failover has its own run (`task failover`), since CI does
// not run it.
//
// Covers: PN-010.4, PN-010.7, PN-011.1
func TestE2E_M19_Exit(t *testing.T) {
	s := start(t, options{budget: "1000.00"})
	t.Run("a held budget row is retried, not refused", func(t *testing.T) {
		if code, r := s.refund(t, ids.NewV7(), "5.01"); code != http.StatusOK || r.Outcome != "ACCEPTED" {
			t.Fatalf("the first refund prepares the row: %d %+v", code, r)
		}
		s.waitSettled(t, "5.01") // so only the next refund waits on the row
		release := holdBudgetRows(t, s)
		type answer struct {
			code int
			r    reply
			err  error
		}
		done := make(chan answer, 1)
		go func() {
			code, r, err := s.tryRefund(ids.NewV7(), "5.02")
			done <- answer{code, r, err}
		}()
		// Held past the 100 ms budget lock timeout from the moment the
		// refund waits, so its first attempt is busy: only the one retry
		// can accept it (T-219).
		waitBudgetLock(t, s)
		time.Sleep(110 * time.Millisecond)
		release()
		a := <-done
		if a.err != nil || a.code != http.StatusOK || a.r.Outcome != "ACCEPTED" {
			t.Fatalf("held 110 ms past the wait: %d %+v %v, want accepted by the retry", a.code, a.r, a.err)
		}
	})

	t.Run("shared limits hold across two replicas", func(t *testing.T) {
		ctx := context.Background()
		const replicas, limit = 2, 160
		const window = 30 * time.Second
		// Windows are aligned to the epoch: start well inside one, so the
		// whole count falls in it.
		if left := window - time.Duration(time.Now().UnixNano())%window; left < 10*time.Second {
			time.Sleep(left + 200*time.Millisecond)
		}
		key := ids.NewV7().String() // a scope and key no real traffic shares
		store := ratelimit.NewStore(s.pool)
		rs := [replicas]*ratelimit.Leased{ratelimit.NewLeased(store, clock.System{}), ratelimit.NewLeased(store, clock.System{})}
		allowed := 0
		for i := range 2 * limit {
			d, err := rs[i%replicas].Take(ctx, "e2e.m19_exit", key, window, 1, limit)
			if err != nil {
				t.Fatal(err)
			}
			if d.Allowed {
				allowed++
			}
		}
		if k := ratelimit.ChunkSize(limit); allowed > limit || allowed < limit-(replicas-1)*k {
			t.Fatalf("%d allowed across %d replicas with a limit of %d (chunk %d)", allowed, replicas, limit, k)
		}
	})

	t.Run("a stream lease is enforced across replicas", func(t *testing.T) {
		a, b := gwapp.NewHub(s.pool, nil), gwapp.NewHub(s.pool, nil)
		id := gwapp.Identity{Org: s.org, Gateway: ids.NewV7(), Cert: ids.NewV7()}
		var open []*gwapp.Subscription
		defer func() {
			for _, sub := range open {
				sub.Close()
			}
		}()
		for i := range gwapp.MaxStreamsPerCert {
			hub := a
			if i%2 == 1 {
				hub = b
			}
			sub, err := hub.Subscribe(id)
			if err != nil {
				t.Fatalf("stream %d: %v", i, err)
			}
			open = append(open, sub)
		}
		for _, hub := range []*gwapp.Hub{a, b} {
			if _, err := hub.Subscribe(id); !errors.Is(err, gwapp.ErrTooManyStreams) {
				t.Fatalf("past the cap: %v, want refused on either replica", err)
			}
		}
		open[0].Close() // on a; its slot frees on b
		sub, err := b.Subscribe(id)
		if err != nil {
			t.Fatalf("after a close on the other replica: %v", err)
		}
		open[0] = sub
	})

	t.Run("a hosted gateway serves one org", func(t *testing.T) {
		ctx := context.Background()
		reg := keys.NewRegistry()
		k, err := keys.GenerateSigningKey(keys.PurposeGatewayCA)
		if err != nil {
			t.Fatal(err)
		}
		if err := reg.Put(k); err != nil {
			t.Fatal(err)
		}
		authority, err := ca.New(reg)
		if err != nil {
			t.Fatal(err)
		}
		kp, err := keys.NewFileProvider([]string{s.kek})
		if err != nil {
			t.Fatal(err)
		}
		const api = "https://gw-api.example.test:8443"
		hosting := hostingapp.New(s.pool, authority, pccrypto.NewEnvelope(keystore.NewDEKStore(s.pool, kp)), teamEdition{}, api, clock.System{})
		gateways := gwapp.New(s.pool, authority, api, nil)

		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		added, err := hosting.AddHost(ctx, "h1", "h1.example.test", 10, 4000, 8192, pub)
		if err != nil {
			t.Fatal(err)
		}
		admin := func(org ids.OrgID) context.Context {
			return tapp.WithCaller(ctx, tapp.Caller{Subject: td.Subject{
				Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
				Bindings: []td.Binding{{Role: td.RoleGatewayAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}},
			}, Credential: tapp.CredAccessToken})
		}
		other := ids.New[ids.Org]()
		s.db.AdminExec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'other')", other)

		h, err := hosting.Request(admin(s.org), "exit", profile.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		if n, err := hosting.ProvisionOrg(ctx, s.org); err != nil || n != 1 {
			t.Fatalf("provision: %d %v", n, err)
		}
		if _, err := hosting.Request(admin(s.org), "exit-two", profile.Limits{}); !errors.Is(err, hostingdomain.ErrOneOnly) {
			t.Fatalf("a second hosted gateway: %v", err)
		}
		if _, err := hosting.Request(admin(other), "exit", profile.Limits{}); !errors.Is(err, hostingdomain.ErrSlugTaken) {
			t.Fatalf("another org on this slug: %v", err)
		}
		tok, err := hosting.PullToken(ctx, added.Identity, s.org, h.ID)
		if err != nil {
			t.Fatal(err)
		}
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, priv)
		if err != nil {
			t.Fatal(err)
		}
		enrolled, err := gateways.Enroll(ctx, tok.Secret.Reveal(), csr)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(enrolled.Certificate)
		if err != nil {
			t.Fatal(err)
		}
		if id, err := ca.ParseIdentity(cert); err != nil || id.Org != s.org {
			t.Fatalf("the certificate names %+v %v, want only org %s", id, err, s.org)
		}
	})
}

// gatewayLog is where a gateway of the stack logs.
func (s *stack) gatewayLog() *slog.Logger {
	if !s.logGateways {
		return pclog.Discard()
	}
	return slog.New(slog.NewJSONHandler(&s.gatewayLogs, nil))
}

// waitBudgetLock returns once a statement on pc.budget_accounts is waiting
// for a lock, the moment its lock timeout starts.
func waitBudgetLock(t *testing.T, s *stack) {
	t.Helper()
	s.db.AdminDo(t, func(conn *pgx.Conn) error {
		ctx := context.Background()
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Millisecond) {
			var waiting int
			if err := conn.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()
				AND wait_event_type = 'Lock' AND query LIKE '%budget_accounts%'`).Scan(&waiting); err != nil {
				return err
			}
			if waiting > 0 {
				return nil
			}
		}
		return errors.New("no statement waited for a budget row")
	})
}

// holdBudgetRows locks the org's budget rows until the returned func runs.
func holdBudgetRows(t *testing.T, s *stack) func() {
	t.Helper()
	locked, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- s.pool.InTenantTx(context.Background(), s.org, func(ctx context.Context, tx db.TenantTx) error {
			if _, err := tx.Exec(ctx, "UPDATE pc.budget_accounts SET reserved = reserved"); err != nil {
				return err
			}
			close(locked)
			<-release
			return nil
		})
	}()
	select {
	case <-locked:
	case err := <-done:
		t.Fatalf("hold the budget rows: %v", err)
	}
	return func() {
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}
