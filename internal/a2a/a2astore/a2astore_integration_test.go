// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package a2astore_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	wire "github.com/katocxl/pantherclaw/internal/a2a"
	"github.com/katocxl/pantherclaw/internal/a2a/a2astore"
	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	a2asim "github.com/katocxl/pantherclaw/internal/sim/a2a"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type world struct {
	pool          *db.Pool
	org           ids.OrgID
	conn, gateway ids.UUID
	user, key     ids.UUID
}

func newWorld(t *testing.T, pool *db.Pool, iface string) world {
	t.Helper()
	w := world{pool: pool, org: ids.New[ids.Org](), conn: ids.NewV7(), gateway: ids.NewV7(), user: ids.NewV7(), key: ids.NewV7()}
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	w.tx(t, func(ctx context.Context, _ *dbq.Queries, tx db.TenantTx) error {
		for _, s := range []struct {
			sql  string
			args []any
		}{
			{"INSERT INTO pc.orgs (id, name) VALUES ($1, 'a2a')", []any{w.org}},
			{"INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", []any{w.org, w.gateway}},
			{`INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, simulated, created_by, updated_by)
				VALUES ($1, $2, 'peer', 'a2a', $3, 'pc.a2a', $4, 'pantherclaw_held', true, 'test', 'user:proposer')`, []any{w.org, w.conn, w.gateway, iface}},
			{"INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'admin')", []any{w.org, w.user}},
			{
				`INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
				backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
				[]any{w.org, w.key, w.user, secret[:16], secret},
			},
		} {
			if _, err := tx.Exec(ctx, s.sql, s.args...); err != nil {
				return err
			}
		}
		return nil
	})
	return w
}

func (w world) tx(t *testing.T, fn func(ctx context.Context, q *dbq.Queries, tx db.TenantTx) error) {
	t.Helper()
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return fn(ctx, dbq.New(tx), tx)
	}); err != nil {
		t.Fatal(err)
	}
}

// admin is a Gateway Admin (connection.manage) of the world's org.
func (w world) admin(kind td.PrincipalKind) context.Context {
	return tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: w.org, Principal: td.PrincipalRef{Kind: kind, ID: w.user},
		Bindings: []td.Binding{{Role: td.RoleGatewayAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}}},
	}, Credential: tenancy.CredBrowserSession})
}

func pinned(card string) *pb.A2AConfig {
	d := sha256.Sum256([]byte(card))
	return &pb.A2AConfig{
		CardUrl: "https://peer.example/.well-known/agent-card.json", PinnedCard: []byte(card), CardDigest: d[:],
		Interface: &pb.A2AInterface{Protocol: "JSONRPC", Url: "https://peer.example/a2a"}, Skills: []string{"refunds"},
		MaxAnswerBytes: 1 << 20, MaxStreamSeconds: 300,
	}
}

// TestHR322_PinsServeOnlyOnceConfirmed (G0 M14 D30, D85): a saved
// configuration is a proposal the gateway does not get; confirming it with
// a fresh step-up makes it serve, supersedes the previous pin and bumps
// the gateway's configuration; a re-pin is proposed while the confirmed
// one keeps serving; a card that changed since it was proposed, a missing
// step-up or a non-person are refused; another org sees nothing (RLS).
func TestHR322_PinsServeOnlyOnceConfirmed(t *testing.T) {
	sim := a2asim.New(a2asim.Options{}, a2asim.Faults{}, nil)
	ts := httptest.NewServer(sim.Handler())
	t.Cleanup(ts.Close)
	pool := dbtest.New(t).AppPool(t)
	iface := ts.URL + a2asim.JSONRPCPath
	w := newWorld(t, pool, iface)
	adapter := &a2astore.Adapter{Pinner: a2astore.NewPinner()}
	pins := &a2astore.Pins{Pool: pool, Pinner: adapter.Pinner}
	cfg := &capp.A2AConfig{
		CardURL: ts.URL + wire.CardPath, Interface: capp.A2AInterface{Protocol: wire.BindingJSONRPC, URL: iface},
		Skills: []string{"refunds"}, MaxAnswerBytes: 1 << 20, MaxStreamSeconds: 300,
	}
	served := func() *pb.A2AConfig {
		var got *pb.A2AConfig
		w.tx(t, func(ctx context.Context, _ *dbq.Queries, tx db.TenantTx) error {
			m, err := adapter.Load(ctx, tx, w.org, w.conn)
			if m != nil {
				got, _ = m.(*pb.A2AConfig)
			}
			return err
		})
		return got
	}
	version := func() int64 {
		var v int64
		w.tx(t, func(ctx context.Context, _ *dbq.Queries, tx db.TenantTx) error {
			return tx.QueryRow(ctx, "SELECT config_version FROM pc.gateways WHERE id = $1", w.gateway).Scan(&v)
		})
		return v
	}
	w.tx(t, func(ctx context.Context, _ *dbq.Queries, tx db.TenantTx) error {
		base, err := adapter.Save(ctx, tx, w.org, w.conn, 1, cfg)
		if err == nil && base != iface {
			t.Errorf("derived base URL %q", base)
		}
		return err
	})
	if served() != nil {
		t.Fatal("an unconfirmed proposal serves")
	}
	got, err := pins.Get(w.admin(td.KindUser), w.conn)
	if err != nil || got.Active != nil || got.Proposed == nil || got.Name != "peer" || got.Proposed.ProposedBy != "user:proposer" {
		t.Fatalf("pins: %+v %v", got, err)
	}
	first := got.Proposed
	su := &stepup.StepUp{Credential: w.key, At: time.Now()}
	if _, err := pins.Confirm(w.admin(td.KindUser), w.conn, first.ID, nil); !errors.Is(err, stepup.ErrStepUp) {
		t.Fatalf("no step-up: %v", err)
	}
	if _, err := pins.Confirm(w.admin(td.KindServiceAccount), w.conn, first.ID, su); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("a service account: %v", err)
	}
	if _, err := pins.Confirm(w.admin(td.KindUser), w.conn, first.ID, &stepup.StepUp{Credential: ids.NewV7(), At: time.Now()}); !errors.Is(err, stepup.ErrStepUp) {
		t.Fatalf("another key: %v", err)
	}
	before := version()
	active, err := pins.Confirm(w.admin(td.KindUser), w.conn, first.ID, su)
	if err != nil || active.State != a2astore.StateActive || *active.ConfirmedBy != w.user || *active.ConfirmedKey != w.key {
		t.Fatalf("confirm: %+v %v", active, err)
	}
	if s := served(); s == nil || !bytes.Equal(s.GetCardDigest(), first.Config.GetCardDigest()) || version() != before+1 {
		t.Fatalf("after confirm the gateway gets %v (version %d → %d)", s, before, version())
	}
	// A re-pin after the card changed: proposed, while the first serves.
	sim.SetFaults(a2asim.Faults{Description: "version two"})
	w.tx(t, func(ctx context.Context, _ *dbq.Queries, tx db.TenantTx) error {
		// The base URL stays the serving interface's (D96 L3).
		base, err := adapter.Save(ctx, tx, w.org, w.conn, 2, cfg)
		if err == nil && base != iface {
			t.Errorf("re-pin base URL %q", base)
		}
		return err
	})
	// A re-pin to another origin is refused: a new peer is a new connection.
	w.tx(t, func(ctx context.Context, _ *dbq.Queries, tx db.TenantTx) error {
		moved := *cfg
		moved.Interface.URL = "http://127.0.0.2:1" + a2asim.JSONRPCPath
		if _, err := adapter.Save(ctx, tx, w.org, w.conn, 3, &moved); !errors.Is(err, a2astore.ErrInterfaceOrigin) {
			t.Errorf("re-pin to another origin: %v", err)
		}
		return nil
	})
	got, _ = pins.Get(w.admin(td.KindUser), w.conn)
	if got.Proposed == nil || bytes.Equal(got.Proposed.Config.GetCardDigest(), first.Config.GetCardDigest()) ||
		!bytes.Equal(served().GetCardDigest(), first.Config.GetCardDigest()) {
		t.Fatalf("re-pin: %+v", got)
	}
	// The card changes again before anyone confirms: refused.
	sim.SetFaults(a2asim.Faults{Description: "version three"})
	if _, err := pins.Confirm(w.admin(td.KindUser), w.conn, got.Proposed.ID, su); !errors.Is(err, a2astore.ErrCardChanged) {
		t.Fatalf("changed card: %v", err)
	}
	sim.SetFaults(a2asim.Faults{Description: "version two"})
	if _, err := pins.Confirm(w.admin(td.KindUser), w.conn, first.ID, su); !errors.Is(err, a2astore.ErrNoProposal) {
		t.Fatalf("confirming the active pin again: %v", err)
	}
	second, err := pins.Confirm(w.admin(td.KindUser), w.conn, got.Proposed.ID, su)
	if err != nil || !bytes.Equal(served().GetCardDigest(), second.Config.GetCardDigest()) {
		t.Fatalf("second confirm: %v", err)
	}
	// Drift is recorded once, on the active pin's digest only.
	w.tx(t, func(ctx context.Context, q *dbq.Queries, _ db.TenantTx) error {
		observed := sha256.Sum256([]byte("other"))
		if ok, err := a2astore.MarkDrift(ctx, q, w.org, w.conn, second.Config.GetCardDigest(), observed[:]); err != nil || !ok {
			t.Fatalf("drift: %v %v", ok, err)
		}
		if ok, _ := a2astore.MarkDrift(ctx, q, w.org, w.conn, second.Config.GetCardDigest(), observed[:]); ok {
			t.Fatal("drift recorded twice")
		}
		if ok, _ := a2astore.MarkDrift(ctx, q, w.org, w.conn, first.Config.GetCardDigest(), observed[:]); ok {
			t.Fatal("drift against a superseded pin")
		}
		return nil
	})
	// A drifted pin is not served (D96 L1).
	if served() != nil {
		t.Fatal("a drifted pin is served")
	}
	other := newWorld(t, pool, iface)
	other.tx(t, func(ctx context.Context, q *dbq.Queries, _ db.TenantTx) error {
		if _, err := a2astore.Get(ctx, q, other.org, w.conn, a2astore.StateActive); !errors.Is(err, a2astore.ErrNotFound) {
			t.Fatalf("another org reads the pin: %v", err)
		}
		if _, err := a2astore.Get(ctx, q, w.org, w.conn, a2astore.StateActive); !errors.Is(err, a2astore.ErrNotFound) {
			t.Fatalf("RLS lets another org's transaction read the pin: %v", err)
		}
		return nil
	})
}

// TestHR322_PinRowsNeverChange: the guard keeps what a pin is, and its
// state moves only forward.
func TestHR322_PinRowsNeverChange(t *testing.T) {
	pool := dbtest.New(t).AppPool(t)
	w := newWorld(t, pool, "https://peer.example/a2a")
	var id ids.UUID
	w.tx(t, func(ctx context.Context, q *dbq.Queries, _ db.TenantTx) error {
		var err error
		id, err = a2astore.Propose(ctx, q, w.org, w.conn, pinned(`{"name":"peer"}`), "user:x")
		return err
	})
	for _, bad := range []string{
		"UPDATE pc.a2a_pins SET pinned_card = '\\x7b7d' WHERE id = $1",
		"UPDATE pc.a2a_pins SET state = 'SUPERSEDED' WHERE id = $1",
		"UPDATE pc.a2a_pins SET skills = '{transfers}' WHERE id = $1",
	} {
		err := pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, bad, id)
			return err
		})
		if err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
	w.tx(t, func(ctx context.Context, q *dbq.Queries, tx db.TenantTx) error {
		if _, err := a2astore.Propose(ctx, q, w.org, w.conn, pinned(`{"name":"peer2"}`), "user:x"); err != nil {
			return err
		}
		// A newer proposal voided the older one.
		var state string
		if err := tx.QueryRow(ctx, "SELECT state FROM pc.a2a_pins WHERE id = $1", id).Scan(&state); err != nil {
			return err
		}
		if state != a2astore.StateVoided {
			t.Fatalf("older proposal is %s", state)
		}
		return nil
	})
}
