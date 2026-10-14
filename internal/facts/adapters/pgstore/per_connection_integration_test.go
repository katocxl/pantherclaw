// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgstore_test

import (
	"context"
	"encoding/json/jsontext"
	"strconv"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/facts/app"
	"github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// twins is an org with a real GitHub connection and its simulated twin on one
// gateway, both with a fact provider declaring the same github.pull.head.
type twins struct {
	p         *db.Pool
	org       ids.OrgID
	gw        ids.UUID
	real, sim ids.UUID
	svc       *app.Service
	human     context.Context
	store     *pgstore.Store
}

var headDecl = domain.Declaration{Name: "github.pull.head", Type: domain.TypeObject, SubjectType: "github.pull_request", MaxLag: time.Minute}

func newTwins(t *testing.T) *twins {
	t.Helper()
	w := &twins{p: dbtest.New(t).AppPool(t), org: ids.New[ids.Org](), gw: ids.NewV7(), real: ids.NewV7(), sim: ids.NewV7()}
	alice := ids.NewV7()
	w.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", w.org)
	w.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", w.org, alice)
	w.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", w.org, w.gw)
	w.exec(t, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, allowed_hosts, default_mode,
		created_by, updated_by) VALUES ($1, $2, 'github', 'http', $3, 'pc.github', 'https://api.github.com', 'pantherclaw_held',
		ARRAY['api.github.com'], 'enforce', 'test', 'test')`, w.org, w.real, w.gw)
	w.exec(t, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, allowed_hosts, default_mode,
		created_by, updated_by, simulated) VALUES ($1, $2, 'github-sim', 'http', $3, 'pc.github', 'http://127.0.0.1:9100', 'none',
		ARRAY['127.0.0.1:9100'], 'enforce', 'test', 'test', true)`, w.org, w.sim, w.gw)
	named := func(_ context.Context, _ ids.OrgID, g, c ids.UUID) (map[string][]string, error) {
		if g != w.gw || (c != w.real && c != w.sim) {
			return nil, app.ErrConnectionUnknown
		}
		return map[string][]string{"github.pull.head": {"github.pull_request"}}, nil
	}
	w.store = &pgstore.Store{Pool: w.p}
	w.svc = &app.Service{Store: w.store, Authz: allow{}, Packages: named}
	w.human = as(w.org, tdomain.KindUser, alice)
	for name, conn := range map[string]ids.UUID{"github": w.real, "github.sim": w.sim} {
		if _, err := w.svc.RegisterGatewayProvider(w.human, name, w.gw, conn, []domain.Declaration{headDecl}); err != nil {
			t.Fatalf("provider for %s: %v", name, err)
		}
	}
	return w
}

func (w *twins) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := w.p.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

const subject = "acme/payments#7"

func (w *twins) report(t *testing.T, conn ids.UUID, sha string, at time.Time) {
	t.Helper()
	v := jsontext.Value(`{"object":{"sha":"` + sha + `","base":"main","draft":false,"changed_files":1}}`)
	res, err := w.svc.PutGatewayFacts(context.Background(), w.org, w.gw, conn, []domain.Observation{
		{Name: "github.pull.head", SubjectType: "github.pull_request", SubjectID: subject, Value: v, ObservedAt: at},
	})
	if err != nil || res[0].Err != nil {
		t.Fatalf("report: %v %+v", err, res)
	}
}

// head is the sha the facts an action through conn sees say, or "".
func (w *twins) head(t *testing.T, conn ids.UUID) string {
	t.Helper()
	var facts map[string]domain.Fact
	if err := w.p.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		facts, err = w.store.SubjectOn(ctx, dbq.New(tx), w.org, conn, "github.pull_request", subject, []string{"github.pull.head"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	f, ok := facts["github.pull.head"]
	if !ok {
		return ""
	}
	s, _ := f.Value.Object["sha"].(string)
	return s
}

const (
	shaReal = "0123456789abcdef0123456789abcdef01234567"
	shaSim  = "fedcba9876543210fedcba9876543210fedcba98"
)

// TestHR222_SimulatedFactsNeverServeRealActions (D43): the twin reports a
// different, newer head for the same pull request; the real connection's
// actions still see only their own, and the twin's write did not overwrite it.
func TestHR222_SimulatedFactsNeverServeRealActions(t *testing.T) {
	w := newTwins(t)
	now := time.Now().UTC()
	w.report(t, w.real, shaReal, now.Add(-30*time.Second))
	w.report(t, w.sim, shaSim, now)
	if got := w.head(t, w.real); got != shaReal {
		t.Fatalf("a real action sees head %q, want %q", got, shaReal)
	}
	// The real connection's newer report replaces only its own row.
	w.report(t, w.real, shaSim[:20]+shaReal[20:], now)
	if got := w.head(t, w.sim); got != shaSim {
		t.Fatalf("the twin's head changed to %q after a real report", got)
	}
	var rows int
	if err := w.p.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM pc.facts WHERE org_id = $1 AND name = 'github.pull.head'", w.org).Scan(&rows)
	}); err != nil || rows != 2 {
		t.Fatalf("%d rows for the one pull request, want one per connection: %v", rows, err)
	}
}

// TestHR222_RealFactsNeverServeSimulatedActions (D43): a simulated action
// sees nothing while only the real connection has reported, and only its own
// twin's value once it has; an action through no connection sees neither.
func TestHR222_RealFactsNeverServeSimulatedActions(t *testing.T) {
	w := newTwins(t)
	w.report(t, w.real, shaReal, time.Now().UTC())
	if got := w.head(t, w.sim); got != "" {
		t.Fatalf("a simulated action sees the real connection's head %q", got)
	}
	if got := w.head(t, ids.UUID{}); got != "" {
		t.Fatalf("an action through no connection sees a gateway fact %q", got)
	}
	w.report(t, w.sim, shaSim, time.Now().UTC())
	if got := w.head(t, w.sim); got != shaSim {
		t.Fatalf("a simulated action sees %q, want its twin's %q", got, shaSim)
	}
	if got := w.head(t, w.real); got != shaReal {
		t.Fatalf("a real action sees %q, want %q", got, shaReal)
	}
}

// TestHR160_ProviderScopesAreOrgOrConnection (D43): a table of registrations
// against what is already supplied (both connections supply github.pull.head).
// A name is supplied from one scope; the connections that share a name share
// its type and subject type.
func TestHR160_ProviderScopesAreOrgOrConnection(t *testing.T) {
	w := newTwins(t)
	sa := ids.NewV7()
	w.exec(t, "INSERT INTO pc.service_accounts (org_id, id, name, created_by) VALUES ($1, $2, 'billing', 'test')", w.org, sa)
	w.svc.Packages = func(context.Context, ids.OrgID, ids.UUID, ids.UUID) (map[string][]string, error) {
		return map[string][]string{
			"github.pull.head": {"github.pull_request", "github.branch"}, "payments.charge.refundable": {"payments.charge"},
		}, nil
	}
	charge := domain.Declaration{Name: "payments.charge.refundable", Type: domain.TypeBoolean, SubjectType: "payments.charge", MaxLag: time.Minute}
	branch := headDecl
	branch.SubjectType = "github.branch"
	retyped := headDecl
	retyped.Type = domain.TypeIdentifier

	n := 0
	connection := func() ids.UUID {
		n++
		id := ids.NewV7()
		w.exec(t, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, allowed_hosts, default_mode,
			created_by, updated_by) VALUES ($1, $2, $3, 'http', $4, 'pc.github', 'https://api.github.com', 'pantherclaw_held',
			ARRAY['api.github.com'], 'enforce', 'test', 'test')`, w.org, id, "extra-"+string(rune('a'+n)), w.gw)
		return id
	}
	for _, c := range []struct {
		name string
		decl domain.Declaration
		ok   bool
	}{
		{"another connection, the same declaration", headDecl, true},
		{"another connection, another subject type", branch, false},
		{"another connection, another value type", retyped, false},
		{"a name nobody supplies", charge, true},
	} {
		_, err := w.svc.RegisterGatewayProvider(w.human, "case.n"+strconv.Itoa(len(c.name)), w.gw, connection(), []domain.Declaration{c.decl})
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok=%v", c.name, err, c.ok)
		}
	}
	// A connection that already supplies a name has its one provider.
	if _, err := w.svc.RegisterGatewayProvider(w.human, "again", w.gw, w.real, []domain.Declaration{headDecl}); err == nil {
		t.Error("a second provider for a connection")
	}
	// An org-scoped provider cannot supply a name any connection supplies.
	for name, d := range map[string]domain.Declaration{"head": headDecl, "charge": charge} {
		if _, err := w.svc.RegisterProvider(w.human, "billing-"+name, sa, []domain.Declaration{d}); err == nil {
			t.Errorf("a service account registered for %s, which connections supply", name)
		}
	}
	// And the reverse: a name an org-scoped provider supplies is refused to
	// connections.
	orgScoped := []domain.Declaration{{Name: "payments.refund.settled", Type: domain.TypeBoolean, SubjectType: "payments.refund", MaxLag: time.Minute}}
	if _, err := w.svc.RegisterProvider(w.human, "billing", sa, orgScoped); err != nil {
		t.Fatalf("a service account for an unsupplied name: %v", err)
	}
	w.svc.Packages = func(context.Context, ids.OrgID, ids.UUID, ids.UUID) (map[string][]string, error) {
		return map[string][]string{"payments.refund.settled": {"payments.refund"}}, nil
	}
	if _, err := w.svc.RegisterGatewayProvider(w.human, "case.settled", w.gw, connection(), orgScoped); err == nil {
		t.Error("a connection registered for a name an org-scoped provider supplies")
	}
	// The database refuses what the application missed: a name in both scopes.
	prov := ids.NewV7()
	w.exec(t, "INSERT INTO pc.fact_providers (org_id, id, name, service_account_id, created_by) VALUES ($1, $2, 'sneaky', $3, 'test')", w.org, prov, sa)
	err := w.p.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return dbq.New(tx).InsertFactDeclaration(ctx, dbq.InsertFactDeclarationParams{
			OrgID: w.org, ProviderID: prov, Name: "github.pull.head", ValueType: "object", SubjectType: "github.pull_request", MaxLagS: 60,
		})
	})
	if !db.IsUniqueViolation(err) {
		t.Errorf("the database accepted a name in both scopes: %v", err)
	}
}

// TestHR222_ATwinRegistersBesideTheDevSeedProvider: the provider `dev seed`
// writes for the real GitHub connection (every name the package names, one
// declaration per target type) does not stop the twin's provider, registered
// through the service with the same declarations, from registering.
func TestHR222_ATwinRegistersBesideTheDevSeedProvider(t *testing.T) {
	w := newTwins(t) // registers both through the service; start clean instead
	w.exec(t, "UPDATE pc.fact_providers SET state = 'DISABLED' WHERE org_id = $1", w.org)
	w.exec(t, "UPDATE pc.fact_declarations SET active = false WHERE org_id = $1", w.org)
	named := map[string][]string{
		"github.pull.head":    {"github.pull_request"},
		"github.pull.state":   {"github.pull_request"},
		"github.branch.rules": {"github.repository"},
	}
	w.svc.Packages = func(context.Context, ids.OrgID, ids.UUID, ids.UUID) (map[string][]string, error) { return named, nil }
	var decls []domain.Declaration
	for name, subjects := range named {
		for _, s := range subjects {
			decls = append(decls, domain.Declaration{Name: name, Type: domain.TypeObject, SubjectType: s, MaxLag: time.Minute})
		}
	}
	seed := domain.Provider{ID: ids.NewV7(), Org: w.org, Name: "github.gateway", GatewayID: w.gw, ConnectionID: w.real, State: domain.ProviderActive, Facts: decls}
	if err := w.store.CreateProvider(context.Background(), w.org, seed, "dev-seed", auditEvent(seed.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.RegisterGatewayProvider(w.human, "github.gateway.range", w.gw, w.sim, decls); err != nil {
		t.Fatalf("the twin beside the dev-seed provider: %v", err)
	}
}

func auditEvent(id ids.UUID) audit.Event {
	return audit.Event{
		Name: "facts.provider_registered", Actor: evdomain.Actor{Type: "operator", ID: "test"}, Outcome: audit.Success,
		Object: &audit.Object{Type: "fact_provider", ID: id.String()},
	}
}

// TestRace_ANameIsNeverSuppliedFromTwoScopes: two registrations of one name,
// one org-scoped and one for a connection, run at the same time, with each
// transaction held open after its insert; exactly one succeeds.
func TestRace_ANameIsNeverSuppliedFromTwoScopes(t *testing.T) {
	w := newTwins(t)
	sa, orgProv, connProv := ids.NewV7(), ids.NewV7(), ids.NewV7()
	third := ids.NewV7()
	w.exec(t, "INSERT INTO pc.service_accounts (org_id, id, name, created_by) VALUES ($1, $2, 'billing', 'test')", w.org, sa)
	w.exec(t, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, allowed_hosts, default_mode,
		created_by, updated_by) VALUES ($1, $2, 'github-three', 'http', $3, 'pc.github', 'https://api.github.com', 'pantherclaw_held',
		ARRAY['api.github.com'], 'enforce', 'test', 'test')`, w.org, third, w.gw)
	w.exec(t, "INSERT INTO pc.fact_providers (org_id, id, name, service_account_id, created_by) VALUES ($1, $2, 'race.org', $3, 'test')", w.org, orgProv, sa)
	w.exec(t, "INSERT INTO pc.fact_providers (org_id, id, name, gateway_id, connection_id, created_by) VALUES ($1, $2, 'race.conn', $3, $4, 'test')",
		w.org, connProv, w.gw, third)
	insert := func(provider ids.UUID, conn *ids.UUID) error {
		return w.p.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
			if err := dbq.New(tx).InsertFactDeclaration(ctx, dbq.InsertFactDeclarationParams{
				OrgID: w.org, ProviderID: provider, Name: "race.fact", ValueType: "boolean", SubjectType: "race.subject", MaxLagS: 60, ConnectionID: conn,
			}); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, "SELECT pg_sleep(0.5)")
			return err
		})
	}
	errs := make(chan error, 2)
	go func() { errs <- insert(orgProv, nil) }()
	go func() { errs <- insert(connProv, &third) }()
	ok, unique := 0, 0
	for range 2 {
		if err := <-errs; err == nil {
			ok++
		} else if db.IsUniqueViolation(err) {
			unique++
		} else {
			t.Fatal(err)
		}
	}
	if ok != 1 || unique != 1 {
		t.Fatalf("%d succeeded and %d were refused, want one each", ok, unique)
	}
}
