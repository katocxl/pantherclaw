// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateways/ca"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// replicaEnv is two server replicas (two pools, two Services) on one
// database. Replica b's clock stands still, so its certificate cache never
// expires by itself: only a notification can make it forget.
type replicaEnv struct {
	d      *dbtest.DB
	a, b   *Service
	pa, pb *db.Pool
	clkB   *clock.Fake
	org    ids.OrgID
	admin  context.Context
	// gateways counts the gateways enrolled, for unique names.
	gateways int
}

func newReplicaEnv(t *testing.T) *replicaEnv {
	t.Helper()
	d := dbtest.New(t)
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
	e := &replicaEnv{d: d, pa: d.AppPool(t), pb: d.AppPool(t), clkB: clock.NewFake(time.Now()), org: ids.New[ids.Org]()}
	e.a = New(e.pa, authority, "https://gw-api.example.test:8443", nil)
	e.b = New(e.pb, authority, "https://gw-api.example.test:8443", e.clkB)
	if err := e.pa.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'replicas')", e.org)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	e.admin = tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: e.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RoleGatewayAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}}},
	}, Credential: tapp.CredAccessToken})
	return e
}

// enroll enrolls a gateway through replica a.
func (e *replicaEnv) enroll(t *testing.T) Identity {
	t.Helper()
	e.gateways++
	g, err := e.a.CreateGateway(e.admin, "edge-"+strconv.Itoa(e.gateways))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := e.a.CreateEnrollmentToken(e.admin, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	req, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, priv)
	if err != nil {
		t.Fatal(err)
	}
	en, err := e.a.Enroll(context.Background(), tok.Secret.Reveal(), req)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(en.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	id, err := ca.ParseIdentity(cert)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (c *authCache) has(cert ids.UUID) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.entries[cert]
	return ok
}

// listening runs replica b's hub and waits until its LISTEN is up: a
// notification sent through replica a makes b forget a cached entry.
func (e *replicaEnv) listening(t *testing.T, id Identity) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h := NewHub(e.pb, nil).ForgetOnNotify(e.b)
	go func() { _ = h.Run(ctx) }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if err := e.b.Authenticate(context.Background(), id); err != nil {
			t.Fatal(err)
		}
		if err := e.pa.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, "SELECT pg_notify('pc_containment', $1::text)", e.org.String())
			return err
		}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
		if !e.b.auth.has(id.Cert) {
			return
		}
	}
	t.Fatal("replica b's hub never listened")
}

// refusedWithin polls replica b until it refuses id, or fails after limit.
func (e *replicaEnv) refusedWithin(t *testing.T, id Identity, limit time.Duration) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for {
		err := e.b.Authenticate(context.Background(), id)
		if errors.Is(err, ErrGatewayCredentials) {
			return
		} else if err != nil {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("replica b still accepts the revoked certificate after %s", limit)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestHR492_RevocationReachesEveryReplicaThroughListen: a certificate
// revoked, and a gateway revoked, on replica a are refused on replica b
// as soon as b's hub hears pc_containment, although b's own cache would
// still hold the old answer (its clock stands still).
// Covers: HR-492, T-214
func TestHR492_RevocationReachesEveryReplicaThroughListen(t *testing.T) {
	e := newReplicaEnv(t)
	id := e.enroll(t)
	e.listening(t, id)

	if err := e.b.Authenticate(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if !e.b.auth.has(id.Cert) {
		t.Fatal("replica b did not cache the check")
	}
	if err := e.a.RevokeCertificate(e.admin, id.Gateway, id.Cert); err != nil {
		t.Fatal(err)
	}
	e.refusedWithin(t, id, 2*time.Second)

	// A whole gateway revoked on a.
	id2 := e.enroll(t)
	if err := e.b.Authenticate(context.Background(), id2); err != nil {
		t.Fatal(err)
	}
	if _, err := e.a.RevokeGateway(e.admin, id2.Gateway, "test"); err != nil {
		t.Fatal(err)
	}
	e.refusedWithin(t, id2, 2*time.Second)
}

// TestHR492_AReconnectForgetsTheWholeCache: a certificate revoked on
// replica a while b's LISTEN is down notifies nobody, and b watches no org,
// yet the reconnect drops every cached check, so b refuses it (b's own
// clock stands still) (G0 M19 D224).
// Covers: HR-492, T-214
func TestHR492_AReconnectForgetsTheWholeCache(t *testing.T) {
	e := newReplicaEnv(t)
	id := e.enroll(t)
	if err := e.b.Authenticate(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	h := NewHub(e.pb, nil).ForgetOnNotify(e.b)
	missed := make(chan error, 1)
	var once sync.Once
	h.listenDown = func() {
		once.Do(func() { missed <- e.a.RevokeCertificate(e.admin, id.Gateway, id.Cert) })
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.Run(ctx) }()

	// Drop the LISTEN connection once it is up; then the check is cached
	// again, so only the reconnect can remove it.
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		var n int
		if err := e.pb.InTenantTx(ctx, e.org, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
				WHERE datname = current_database() AND query = 'LISTEN pc_containment'`).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d LISTEN connections", n)
		}
	}
	if err := e.b.Authenticate(ctx, id); err != nil {
		t.Fatal(err)
	}
	if !e.b.auth.has(id.Cert) {
		t.Fatal("replica b did not cache the check")
	}
	if err := e.pb.InTenantTx(ctx, e.org, func(ctx context.Context, tx db.TenantTx) error {
		var n int
		return tx.QueryRow(ctx, `SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity
			WHERE datname = current_database() AND query = 'LISTEN pc_containment'`).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-missed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the hub did not see LISTEN go down")
	}
	e.refusedWithin(t, id, 2*time.Second)
}

// TestHR492_WithoutListenTheCacheLifetimeBoundsIt: with no hub on replica
// b, a revocation on a is refused on b once b's one-second cache lifetime
// passes, and not before.
// Covers: HR-492
func TestHR492_WithoutListenTheCacheLifetimeBoundsIt(t *testing.T) {
	e := newReplicaEnv(t)
	id := e.enroll(t)
	if err := e.b.Authenticate(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if err := e.a.RevokeCertificate(e.admin, id.Gateway, id.Cert); err != nil {
		t.Fatal(err)
	}
	if err := e.b.Authenticate(context.Background(), id); err != nil {
		t.Fatalf("within the cache lifetime: %v", err)
	}
	e.clkB.Advance(authTTL)
	if err := e.b.Authenticate(context.Background(), id); !errors.Is(err, ErrGatewayCredentials) {
		t.Fatalf("after the cache lifetime: %v", err)
	}
}
