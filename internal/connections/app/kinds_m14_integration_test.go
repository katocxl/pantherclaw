// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/connections/ports"
	gwapp "github.com/katocxl/pantherclaw/internal/gateways/app"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// m14Kinds is a package with a structured read (served natively on the
// MCP face) and a peer agent message (on the a2a channel).
const m14Kinds = `format: 1
name: test.m14-kinds
version: 1.0.0
publisher: test
summary: M14 kinds
definitions:
  - operation: shop.rows.read
    summary: Read rows
    access: read
    target: {type: pg.table, id_pattern: '^[a-z_]+\.[a-z_]+$', account: none}
    params: {}
    effects: [{kind: none, description: Reads only}]
    reversibility: reversible
    retry: {safe: true, on_unknown: fail}
    assurance: {basis: declared, reviewed_by: [tests], valid_until: 2027-10-08}
    dispatch: {sql: {operation: rows}}
    mappings:
      - channel: mcp
        tool: query_rows
        route: rows
        extract: {target_id: input.table, params: {}}
  - operation: peer.message.send
    summary: Ask a peer agent
    access: write
    target: {type: a2a.agent, id_pattern: '^[a-z]+$', account: none}
    params: {}
    effects: [{kind: request.send, description: Sends a request}]
    reversibility: irreversible
    dedupe_key: [target.id]
    retry: {safe: false, on_unknown: reconcile}
    approval: {title: 'Ask {target.id}', fields: [target.id]}
    assurance: {basis: declared, reviewed_by: [tests], valid_until: 2027-10-08}
    dispatch: {a2a: {method: SendMessage}}
    mappings:
      - channel: a2a
        method: SendMessage
        route: peer-send
        extract: {target_id: '"peer"', params: {}}
`

// fakeKind records what it is asked to save and loads a fixed message.
type fakeKind struct {
	saved []any
	revs  []int32
	load  proto.Message
}

func (f *fakeKind) Save(_ context.Context, _ db.TenantTx, _ ids.OrgID, _ ids.UUID, rev int32, cfg any) (string, error) {
	f.saved, f.revs = append(f.saved, cfg), append(f.revs, rev)
	if a, ok := cfg.(*app.A2AConfig); ok {
		return a.Interface.URL, nil // the interface URL is the base URL (D85)
	}
	return "", nil
}

func (f *fakeKind) Load(context.Context, db.TenantTx, ids.OrgID, ids.UUID) (proto.Message, error) {
	return f.load, nil
}

// TestM14_KindConfigsAreSavedWithTheConnection (G0 M14 D64): a postgres
// or a2a connection is refused while its kind has no configuration store;
// with one, its validated configuration is saved in the transaction that
// creates or updates the connection, at its revision; it serves only the
// routes its kind dispatches (sql reads on the native faces, a2a methods);
// and the gateway's configuration carries what the store loads.
func TestM14_KindConfigsAreSavedWithTheConnection(t *testing.T) {
	e := newEnv(t)
	e.pin(t, "test.m14-kinds", "1.0.0", []byte(m14Kinds))
	pg := pgConfig()
	pgIn := app.CreateInput{Name: "shop-db", Kind: app.KindPostgres, Package: "test.m14-kinds", Gateway: e.gateway, AccessMode: app.AccessHeld, Postgres: &pg}
	if _, err := e.svc.Create(e.admin, pgIn); !is(err, app.ErrKindNotImplemented) {
		t.Fatalf("no store: %v", err)
	}

	kinds := &ports.KindConfigs{}
	pgStore := &fakeKind{load: &pb.PostgresConfig{Database: "shop"}}
	peerStore := &fakeKind{load: &pb.A2AConfig{CardUrl: "https://peer.example.test/card"}}
	kinds.Register(app.KindPostgres, pgStore)
	kinds.Register(app.KindA2A, peerStore)
	e.svc.WithKindConfigs(kinds)

	c, err := e.svc.Create(e.admin, pgIn)
	if err != nil {
		t.Fatal(err)
	}
	if c.BaseUrl != nil || len(c.Routes) != 1 || c.Routes[0].Route != "rows" || len(pgStore.saved) != 1 || pgStore.revs[0] != c.Revision {
		t.Fatalf("postgres: base %v routes %v saved %v", c.BaseUrl, c.Routes, pgStore.revs)
	}
	if got, ok := pgStore.saved[0].(*app.PostgresConfig); !ok || got.MaxRows != app.DefaultPostgresMaxRows {
		t.Fatalf("saved %#v", pgStore.saved[0])
	}
	headed := pgIn
	headed.Name, headed.CredentialHeader = "shop-db-2", "Authorization"
	if _, err := e.svc.Create(e.admin, headed); !is(err, app.ErrShape) {
		t.Fatalf("a postgres credential header: %v", err)
	}

	peer := a2aConfig()
	p, err := e.svc.Create(e.admin, app.CreateInput{
		Name: "peer", Kind: app.KindA2A, Package: "test.m14-kinds", Gateway: e.gateway, AccessMode: app.AccessHeld, A2A: &peer,
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.BaseUrl == nil || *p.BaseUrl != "https://peer.example.test/a2a" || len(p.Routes) != 1 || p.Routes[0].Route != "peer-send" ||
		!slices.Equal(p.AllowedHosts, []string{"peer.example.test"}) {
		t.Fatalf("a2a: base %v hosts %v routes %v", p.BaseUrl, p.AllowedHosts, p.Routes)
	}
	next := a2aConfig()
	next.Skills = []string{"reports"}
	next.Interface.URL = "https://agents.example.test/peer/a2a"
	u, err := e.svc.Update(e.admin, app.UpdateInput{ID: p.ID, Revision: p.Revision, A2A: &next})
	if err != nil {
		t.Fatal(err)
	}
	if len(peerStore.saved) != 2 || peerStore.revs[1] != u.Revision || u.Revision != p.Revision+1 {
		t.Fatalf("update saved %v at %v (connection %d)", len(peerStore.saved), peerStore.revs, u.Revision)
	}
	if u.BaseUrl == nil || *u.BaseUrl != "https://agents.example.test/peer/a2a" || !slices.Equal(u.AllowedHosts, []string{"agents.example.test"}) {
		t.Fatalf("an interface change moves the base URL (D85): %v %v", u.BaseUrl, u.AllowedHosts)
	}
	if _, err := e.svc.Update(e.admin, app.UpdateInput{ID: u.ID, Revision: u.Revision, Postgres: &pg}); !is(err, app.ErrShape) {
		t.Fatalf("a postgres configuration on an a2a connection: %v", err)
	}

	gws := gwapp.New(e.pool, nil, gatewayURL, nil).WithKindConfigs(kinds)
	cfg, err := gws.Configuration(context.Background(), gwapp.Identity{Org: e.org, Gateway: e.gateway}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := cfg.KindConfigs[c.ID].(*pb.PostgresConfig); !ok || got.GetDatabase() != "shop" {
		t.Fatalf("gateway postgres configuration %v", cfg.KindConfigs[c.ID])
	}
	if got, ok := cfg.KindConfigs[p.ID].(*pb.A2AConfig); !ok || got.GetCardUrl() == "" {
		t.Fatalf("gateway a2a configuration %v", cfg.KindConfigs[p.ID])
	}
}

// fakeDrift refuses a report whose expected digest is not the pin.
type fakeDrift struct {
	pin   string
	heard int
}

func (f *fakeDrift) Drift(_ context.Context, _ db.TenantTx, _ ids.OrgID, _ ids.UUID, expected, _ string) error {
	f.heard++
	if expected != f.pin {
		return app.ErrDrift
	}
	return nil
}

// TestM14_ACardDriftQuarantinesTheConnection (G0 M14 D86, HR-322): a drift
// report about an a2a connection's card (tool a2a.card) quarantines the
// connection itself with reason a2a_card_drift after the kind's drift hook
// accepts it in the same transaction; a hook that refuses (a stale pin)
// changes nothing; another gateway's or another kind's report is not found.
func TestM14_ACardDriftQuarantinesTheConnection(t *testing.T) {
	e := newEnv(t)
	e.pin(t, "test.m14-kinds", "1.0.0", []byte(m14Kinds))
	kinds := &ports.KindConfigs{}
	kinds.Register(app.KindA2A, &fakeKind{})
	pin := "sha256:" + strings.Repeat("a", 64)
	hook := &fakeDrift{pin: pin}
	kinds.RegisterDrift(app.KindA2A, hook)
	e.svc.WithKindConfigs(kinds)
	peer := a2aConfig()
	p, err := e.svc.Create(e.admin, app.CreateInput{
		Name: "peer", Kind: app.KindA2A, Package: "test.m14-kinds", Gateway: e.gateway, AccessMode: app.AccessHeld, A2A: &peer,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, observed := context.Background(), "sha256:"+strings.Repeat("b", 64)
	if _, err := e.svc.ReportDrift(ctx, e.org, e.gateway, p.ID, app.ToolA2ACard, "sha256:"+strings.Repeat("c", 64), observed); !is(err, app.ErrDrift) {
		t.Fatalf("a stale pin: %v", err)
	}
	if _, err := e.svc.ReportDrift(ctx, e.org, ids.NewV7(), p.ID, app.ToolA2ACard, pin, observed); !is(err, app.ErrNotFound) {
		t.Fatalf("another gateway: %v", err)
	}
	httpConn := e.payments(t, "payments")
	if _, err := e.svc.ReportDrift(ctx, e.org, e.gateway, httpConn.ID, app.ToolA2ACard, pin, observed); !is(err, app.ErrNotFound) {
		t.Fatalf("an http connection: %v", err)
	}
	q, err := e.svc.ReportDrift(ctx, e.org, e.gateway, p.ID, app.ToolA2ACard, pin, observed)
	if err != nil || !q {
		t.Fatalf("drift: %v %v", q, err)
	}
	got, err := e.svc.Get(e.admin, p.ID)
	if err != nil || got.State != app.StateQuarantined || got.QuarantineReason == nil || *got.QuarantineReason != app.ReasonA2ACardDrift {
		t.Fatalf("after drift: %s %v %v", got.State, got.QuarantineReason, err)
	}
	if hook.heard != 2 {
		t.Fatalf("the hook heard %d reports", hook.heard)
	}
}

// gatedKind is a kind store that validates gateway moves.
type gatedKind struct {
	fakeKind
	refuse  ids.UUID
	checked []ids.UUID
}

func (g *gatedKind) CheckGateway(_ context.Context, _ db.TenantTx, _ ids.OrgID, _, gateway ids.UUID) error {
	g.checked = append(g.checked, gateway)
	if gateway == g.refuse {
		return app.ErrShape
	}
	return nil
}

// TestM14_AMoveIsValidatedByTheKind: moving a postgres or a2a connection to
// another gateway asks its kind's store about the new gateway in the same
// transaction; a refusal leaves the connection where it was (G0 M14 D105).
func TestM14_AMoveIsValidatedByTheKind(t *testing.T) {
	e := newEnv(t)
	e.pin(t, "test.m14-kinds", "1.0.0", []byte(m14Kinds))
	bad, good := ids.NewV7(), ids.NewV7()
	e.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'bad', 'test')", e.org, bad)
	e.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'good', 'test')", e.org, good)
	store := &gatedKind{refuse: bad}
	kinds := &ports.KindConfigs{}
	kinds.Register(app.KindPostgres, store)
	e.svc.WithKindConfigs(kinds)
	pg := pgConfig()
	c, err := e.svc.Create(e.admin, app.CreateInput{
		Name: "shop-db", Kind: app.KindPostgres, Package: "test.m14-kinds", Gateway: e.gateway, AccessMode: app.AccessHeld, Postgres: &pg,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Update(e.admin, app.UpdateInput{ID: c.ID, Revision: c.Revision, Gateway: &bad}); !is(err, app.ErrShape) {
		t.Fatalf("a refused move: %v", err)
	}
	moved, err := e.svc.Update(e.admin, app.UpdateInput{ID: c.ID, Revision: c.Revision, Gateway: &good})
	if err != nil || moved.GatewayID != good || !slices.Equal(store.checked, []ids.UUID{bad, good}) {
		t.Fatalf("a move: %v %v checked %v", moved.GatewayID, err, store.checked)
	}

	// A store that cannot check a gateway refuses every move (D115).
	plain := &ports.KindConfigs{}
	plain.Register(app.KindPostgres, &fakeKind{})
	e.svc.WithKindConfigs(plain)
	if _, err := e.svc.Update(e.admin, app.UpdateInput{ID: c.ID, Revision: moved.Revision, Gateway: &bad}); !is(err, app.ErrKindGatewayUnchecked) {
		t.Fatalf("a move without a gateway check: %v", err)
	}
}
