// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package a2astore_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	wire "github.com/katocxl/pantherclaw/internal/a2a"
	"github.com/katocxl/pantherclaw/internal/a2a/a2astore"
	"github.com/katocxl/pantherclaw/internal/changes"
	"github.com/katocxl/pantherclaw/internal/connections/adapters/connectionsrpc"
	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/connections/ports"
	credapp "github.com/katocxl/pantherclaw/internal/credentials/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/protect"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	a2asim "github.com/katocxl/pantherclaw/internal/sim/a2a"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// publicURLWorld is a signed peer's connection served by the real handler.
type publicURLWorld struct {
	world
	adapter *a2astore.Adapter
	kinds   *ports.KindConfigs
	pins    *a2astore.Pins
	svc     *capp.Service
	h       *connectionsrpc.Handler
	cfg     *capp.A2AConfig
	card    []byte
	ctx     context.Context
}

const publicURLKeyID = "d97-card-key"

func newPublicURLWorld(t *testing.T) *publicURLWorld {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sim := a2asim.New(a2asim.Options{SigningKey: key, KeyID: publicURLKeyID}, a2asim.Faults{}, nil)
	ts := httptest.NewServer(sim.Handler())
	t.Cleanup(ts.Close)
	jwks, err := wire.PublicJWKS(map[string]crypto.PublicKey{publicURLKeyID: key.Public()})
	if err != nil {
		t.Fatal(err)
	}
	pool := dbtest.New(t).AppPool(t)
	iface := ts.URL + a2asim.JSONRPCPath
	w := &publicURLWorld{world: newWorld(t, pool, iface), adapter: &a2astore.Adapter{Pinner: a2astore.NewPinner()}}
	w.kinds = &ports.KindConfigs{}
	w.kinds.Register(capp.KindA2A, w.adapter)
	w.svc = capp.New(pool, nil, "https://pc.test", "https://gw.test").WithKindConfigs(w.kinds)
	w.pins = &a2astore.Pins{Pool: pool, Pinner: w.adapter.Pinner, Quarantines: w.svc}
	w.h = connectionsrpc.New(w.svc, credapp.New(pool, nil))
	w.ctx = w.admin(td.KindUser)
	w.cfg = &capp.A2AConfig{
		CardURL: ts.URL + wire.CardPath, Interface: capp.A2AInterface{Protocol: wire.BindingJSONRPC, URL: iface},
		CardKeys: jwks, Skills: []string{"refunds"}, MaxAnswerBytes: 1 << 20, MaxStreamSeconds: 300,
	}
	w.tx(t, func(ctx context.Context, _ *dbq.Queries, tx db.TenantTx) error {
		_, err := w.adapter.Save(ctx, tx, w.org, w.conn, 1, w.cfg)
		return err
	})
	w.card = w.proposed(t).GetPinnedCard()
	if len(w.card) == 0 {
		t.Fatal("no card was pinned")
	}
	return w
}

func (w *publicURLWorld) read(t *testing.T) *pb.Connection {
	t.Helper()
	r, err := w.h.GetConnection(w.ctx, &pb.GetConnectionRequest{Id: w.conn.String()})
	if err != nil {
		t.Fatal(err)
	}
	w.neverShowsTheKeys(t, r)
	return r.GetConnection()
}

func (w *publicURLWorld) confirm(t *testing.T) {
	t.Helper()
	got, err := w.pins.Get(w.ctx, w.conn)
	if err != nil || got.Proposed == nil {
		t.Fatalf("pins: %+v %v", got, err)
	}
	if _, err := w.pins.Confirm(w.ctx, w.conn, got.Proposed.ID, &stepup.StepUp{Credential: w.key, At: time.Now()}); err != nil {
		t.Fatalf("confirm: %v", err)
	}
}

func (w *publicURLWorld) set(t *testing.T, url string) (*pb.SetA2APublicUrlResponse, error) {
	t.Helper()
	r, err := w.h.SetA2APublicUrl(w.ctx, &pb.SetA2APublicUrlRequest{ConnectionId: w.conn.String(), Revision: w.read(t).GetRevision(), PublicUrl: url})
	if err == nil {
		w.neverShowsTheKeys(t, r)
	}
	return r, err
}

// neverShowsTheKeys fails on a response that carries the card keys or the card.
func (w *publicURLWorld) neverShowsTheKeys(t *testing.T, m proto.Message) {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(publicURLKeyID)) || bytes.Contains(b, w.cfg.CardKeys) {
		t.Fatalf("a response carries the card keys: %q", b)
	}
	if bytes.Contains(b, w.card) {
		t.Fatalf("a response carries the pinned card: %q", b)
	}
}

func (w *publicURLWorld) proposed(t *testing.T) *pb.A2AConfig {
	t.Helper()
	got, err := w.pins.Get(w.ctx, w.conn)
	if err != nil || got.Proposed == nil {
		t.Fatalf("pins: %+v %v", got, err)
	}
	return got.Proposed.Config
}

// TestD97_AReadShowsThePinNotItsKeys: a read names the public URL and the state
// of the proposed pin, else the confirmed one, drifted included; a list shows
// neither, and no response carries the card keys or the card.
// Covers: F882
func TestD97_AReadShowsThePinNotItsKeys(t *testing.T) {
	w := newPublicURLWorld(t)
	c := w.read(t)
	if s := c.GetA2AStatus(); s.GetPinState() != pb.A2APinState_A2A_PIN_STATE_PROPOSED || s.GetPublicUrl() != "" || c.GetA2A() != nil {
		t.Fatalf("before the confirm: %v", c)
	}
	w.confirm(t)
	if s := w.read(t).GetA2AStatus(); s.GetPinState() != pb.A2APinState_A2A_PIN_STATE_ACTIVE {
		t.Fatalf("confirmed: %v", s)
	}
	list, err := w.h.ListConnections(w.ctx, &pb.ListConnectionsRequest{})
	if err != nil || len(list.GetConnections()) != 1 || list.GetConnections()[0].GetA2AStatus() != nil {
		t.Fatalf("list: %v %v", list, err)
	}
	w.neverShowsTheKeys(t, list)
	got, err := w.pins.Get(w.ctx, w.conn)
	if err != nil || got.Active == nil {
		t.Fatalf("pins: %+v %v", got, err)
	}
	w.tx(t, func(ctx context.Context, q *dbq.Queries, _ db.TenantTx) error {
		observed := sha256.Sum256([]byte("other"))
		_, err := a2astore.MarkDrift(ctx, q, w.org, w.conn, got.Active.Config.GetCardDigest(), observed[:])
		return err
	})
	if s := w.read(t).GetA2AStatus(); s.GetPinState() != pb.A2APinState_A2A_PIN_STATE_DRIFTED {
		t.Fatalf("drifted: %v", s)
	}
}

// TestD97_SetA2APublicUrlChangesOnlyTheURL: from a confirmed pin the server
// proposes the same configuration with only the URL changed, and the confirmed
// pin keeps serving until a person confirms the proposal. A second change
// starts from the open proposal, so its edits survive.
// Covers: F882
func TestD97_SetA2APublicUrlChangesOnlyTheURL(t *testing.T) {
	w := newPublicURLWorld(t)
	w.confirm(t)
	const url = "https://gateway.example.test/a2a/peer"
	r, err := w.set(t, url)
	if err != nil {
		t.Fatal(err)
	}
	if s := r.GetConnection().GetA2AStatus(); s.GetPinState() != pb.A2APinState_A2A_PIN_STATE_PROPOSED || s.GetPublicUrl() != url {
		t.Fatalf("the response: %v", s)
	}
	got, err := w.pins.Get(w.ctx, w.conn)
	if err != nil || got.Active == nil || got.Proposed == nil {
		t.Fatalf("pins: %+v %v", got, err)
	}
	if got.Active.Config.GetPublicUrl() != "" {
		t.Fatalf("the URL serves before a confirm: %v", got.Active.Config)
	}
	want := proto.CloneOf(got.Active.Config)
	want.PublicUrl = url
	if !proto.Equal(got.Proposed.Config, want) {
		t.Fatalf("more than the URL changed:\n%v\nwant\n%v", got.Proposed.Config, want)
	}

	edited := *w.cfg
	edited.MaxAnswerBytes = 2 << 20
	updated, err := w.h.UpdateConnection(w.ctx, &pb.UpdateConnectionRequest{Id: w.conn.String(), Revision: w.read(t).GetRevision(), A2A: a2astore.ToProto(&edited)})
	if err != nil {
		t.Fatal(err)
	}
	w.neverShowsTheKeys(t, updated)
	if s := updated.GetConnection().GetA2AStatus(); s.GetPinState() != pb.A2APinState_A2A_PIN_STATE_PROPOSED || s.GetPublicUrl() != "" {
		t.Fatalf("the update response: %v", s)
	}
	const second = "https://gateway.example.test/a2a/other"
	if _, err := w.set(t, second); err != nil {
		t.Fatal(err)
	}
	// The URL already proposed is refused before any fetch: the proposal stays.
	again, err := w.pins.Get(w.ctx, w.conn)
	if err != nil || again.Proposed == nil {
		t.Fatalf("pins: %+v %v", again, err)
	}
	if _, err := w.set(t, second); !errors.Is(err, capp.ErrA2AURLUnchanged) {
		t.Fatalf("the same URL again: %v", err)
	}
	if got, _ := w.pins.Get(w.ctx, w.conn); got.Proposed == nil || got.Proposed.ID != again.Proposed.ID {
		t.Fatalf("the same URL proposed again: %+v", got.Proposed)
	}
	if p := w.proposed(t); p.GetMaxAnswerBytes() != 2<<20 || p.GetPublicUrl() != second {
		t.Fatalf("the open edit: %v", p)
	}
	w.confirm(t)
	if s := w.read(t).GetA2AStatus(); s.GetPinState() != pb.A2APinState_A2A_PIN_STATE_ACTIVE || s.GetPublicUrl() != second {
		t.Fatalf("confirmed: %v", s)
	}
}

// TestD97_SetA2APublicUrlIsRefused: a stale revision, a URL the configuration
// check refuses and a caller without the permission all change nothing
// (another kind and an unpinned connection: the connections app's TestD97).
// Covers: F882
func TestD97_SetA2APublicUrlIsRefused(t *testing.T) {
	w := newPublicURLWorld(t)
	before := w.proposed(t)
	rev := w.read(t).GetRevision()
	if _, err := w.h.SetA2APublicUrl(w.ctx, &pb.SetA2APublicUrlRequest{
		ConnectionId: w.conn.String(), Revision: rev + 1, PublicUrl: "https://gateway.example.test/a2a",
	}); !errors.Is(err, capp.ErrStale) {
		t.Fatalf("a stale revision: %v", err)
	}
	for _, url := range []string{"http://gateway.example.test/a2a", "https://user:pw@gateway.example.test/a2a", "https://gateway.example.test/a2a#x"} {
		if _, err := w.set(t, url); !errors.Is(err, capp.ErrA2AConfig) {
			t.Fatalf("%s: %v", url, err)
		}
	}
	none := tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: w.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: w.user},
	}, Credential: tenancy.CredBrowserSession})
	if _, err := w.h.SetA2APublicUrl(none, &pb.SetA2APublicUrlRequest{
		ConnectionId: w.conn.String(), Revision: rev, PublicUrl: "https://gateway.example.test/a2a",
	}); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("no permission: %v", err)
	}
	if got := w.proposed(t); !proto.Equal(got, before) {
		t.Fatalf("a refusal changed the pin: %v", got)
	}
}

// TestD97_AHeldChangeCarriesOnlyTheURL: with CUSTODY protected the change waits
// like any weakening update, nothing is proposed, the stored change holds no
// configuration, and its re-run proposes the URL.
// Covers: F882
func TestD97_AHeldChangeCarriesOnlyTheURL(t *testing.T) {
	w := newPublicURLWorld(t)
	held := capp.New(w.pool, nil, "https://pc.test", "https://gw.test").WithKindConfigs(w.kinds)
	ceremony := changes.New(w.pool, "https://pc.test")
	gate := &protect.Gate{Requests: protect.Ceremony{Changes: ceremony}}
	protect.Register(ceremony, gate, nil)
	held.WithProtect(gate)
	w.tx(t, func(ctx context.Context, _ *dbq.Queries, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO pc.protected_change_settings (org_id, category, mode, updated_by) VALUES ($1, 'CUSTODY', 'DISTINCT_PUBLISHER', $2)`, w.org, w.user)
		return err
	})
	before := w.proposed(t)
	// The URL already set is refused, not held.
	if _, err := held.SetA2APublicURL(w.ctx, w.conn, "", w.read(t).GetRevision()); !errors.Is(err, capp.ErrA2AURLUnchanged) {
		t.Fatalf("the same URL under CUSTODY: %v", err)
	}
	var stored int
	w.tx(t, func(ctx context.Context, _ *dbq.Queries, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM pc.protected_changes WHERE org_id = $1", w.org).Scan(&stored)
	})
	if stored != 0 {
		t.Fatalf("an unchanged URL was held: %d changes", stored)
	}
	const url = "https://gateway.example.test/a2a/held"
	_, err := held.SetA2APublicURL(w.ctx, w.conn, url, w.read(t).GetRevision())
	var pending *protect.PendingError
	if !errors.As(err, &pending) {
		t.Fatalf("not held: %v", err)
	}
	if got := w.proposed(t); !proto.Equal(got, before) {
		t.Fatalf("a held change proposed: %v", got)
	}
	var payload []byte
	w.tx(t, func(ctx context.Context, q *dbq.Queries, _ db.TenantTx) error {
		row, err := q.GetProtectedChange(ctx, w.org, pending.Change)
		payload = row.Payload
		return err
	})
	if !bytes.Contains(payload, []byte(url)) || bytes.Contains(payload, []byte(publicURLKeyID)) || bytes.Contains(payload, []byte(w.cfg.CardURL)) {
		t.Fatalf("the stored change: %s", payload)
	}
	caller, err := tenancy.CallerFrom(w.ctx)
	if err != nil {
		t.Fatal(err)
	}
	w.tx(t, func(ctx context.Context, _ *dbq.Queries, tx db.TenantTx) error {
		return w.svc.ApplyProtectedUpdate(ctx, tx, caller, payload)
	})
	if got := w.proposed(t); got.GetPublicUrl() != url {
		t.Fatalf("the re-run: %v", got)
	}
}

// TestD97_APinRefusesAPrivateKey: new card keys with private material are
// refused; a stored pin that holds such a key stays as it is, and saving it
// again fails with the same reason.
// Covers: F882
func TestD97_APinRefusesAPrivateKey(t *testing.T) {
	w := newPublicURLWorld(t)
	private := []byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}]}`)
	edited := *w.cfg
	edited.CardKeys = private
	if _, err := w.svc.Update(w.ctx, capp.UpdateInput{ID: w.conn, Revision: w.read(t).GetRevision(), A2A: &edited}); !errors.Is(err, capp.ErrA2AKeyPrivate) {
		t.Fatalf("a private key: %v", err)
	}
	stored := proto.CloneOf(w.proposed(t))
	stored.CardKeys = private
	w.tx(t, func(ctx context.Context, q *dbq.Queries, _ db.TenantTx) error {
		_, err := a2astore.Propose(ctx, q, w.org, w.conn, stored, "user:old")
		return err
	})
	if _, err := w.set(t, "https://gateway.example.test/a2a"); !errors.Is(err, capp.ErrA2AKeyPrivate) {
		t.Fatalf("a re-pin of a stored private key: %v", err)
	}
	if got := w.proposed(t); !bytes.Equal(got.GetCardKeys(), private) || got.GetPublicUrl() != "" {
		t.Fatalf("the stored pin changed: %v", got)
	}
}
