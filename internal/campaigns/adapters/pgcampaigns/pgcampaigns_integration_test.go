// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgcampaigns_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/campaigns/adapters/pgcampaigns"
	"github.com/katocxl/pantherclaw/internal/campaigns/app"
	"github.com/katocxl/pantherclaw/internal/campaigns/domain"
	"github.com/katocxl/pantherclaw/internal/campaigns/ports"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/redteam/library"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const (
	digest    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	image     = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	modelHost = "model.provider.test"
)

type ents struct{}

func (ents) Current(context.Context) (billing.Entitlements, error) {
	x := billing.CommunityEntitlements()
	x.Edition, x.Status, x.Limits.MaxAgents = billing.Business, billing.StatusValid, billing.Unlimited
	return x, nil
}

type world struct {
	pool                         *db.Pool
	svc                          *app.Service
	org                          ids.OrgID
	team, env, owner, gateway    ids.UUID
	twin, real                   ids.UUID
	relay, plainSim, realConn    ids.UUID
	twinRun, realRun, earlierRun ids.UUID
}

func newWorld(t *testing.T, d *dbtest.DB) *world {
	t.Helper()
	p := d.AppPool(t)
	w := &world{
		pool: p, org: ids.New[ids.Org](), team: ids.NewV7(), env: ids.NewV7(), owner: ids.NewV7(), gateway: ids.NewV7(),
		relay: ids.NewV7(), plainSim: ids.NewV7(), realConn: ids.NewV7(), twinRun: ids.NewV7(), realRun: ids.NewV7(), earlierRun: ids.NewV7(),
	}
	w.svc = &app.Service{Store: pgcampaigns.Store{Pool: p}, Editions: ents{}, Library: func(id string) (library.CampaignEntry, bool) {
		if id != "RT-140" {
			return library.CampaignEntry{}, false
		}
		return library.CampaignEntry{Digest: digest, Tier: "business", Attempts: []domain.Attempt{
			{ID: "merge", Boundary: "HR-201", Expected: domain.ExpectHeld, Operation: "github.pull_request.merge"},
		}}, true
	}}
	w.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", w.org)
	w.exec(t, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'eng', 'Eng')", w.org, w.team)
	w.exec(t, "INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'dev', 'Dev', 'DEVELOPMENT')", w.org, w.env, w.team)
	w.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", w.org, w.owner)
	w.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", w.org, w.gateway)
	for _, c := range []struct {
		id               ids.UUID
		name, pkg        string
		simulated, relay bool
	}{{w.relay, "relay", "model-relay", true, true}, {w.plainSim, "twin", "pc.github", true, false}, {w.realConn, "github", "pc.github", false, false}} {
		w.exec(t, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, simulated, model_relay, created_by, updated_by)
			VALUES ($1, $2, $3, 'http', $4, $5, 'http://127.0.0.1:9', 'none', $6, $7, 'test', 'test')`, w.org, c.id, c.name, w.gateway, c.pkg, c.simulated, c.relay)
	}
	inv := aapp.NewInventory(p, ents{})
	for i, rng := range []bool{true, false} {
		a, err := inv.Create(w.as(), adomain.Details{
			Name: []string{"range-coder", "real-coder"}[i], TeamID: w.team, EnvironmentID: w.env, OwnerUserID: w.owner,
			Context: adomain.ContextCI, RangeAgent: rng,
		})
		if err != nil {
			t.Fatal(err)
		}
		if rng {
			w.twin = a.ID
		} else {
			w.real = a.ID
		}
	}
	w.runOf(t, w.earlierRun, w.twin, true)
	return w
}

func (w *world) runOf(t *testing.T, id, agent ids.UUID, simulated bool) {
	t.Helper()
	w.exec(t, `INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_user_id, principal_user_id, principal_source, expires_at, simulated)
		VALUES ($1, $2, $3, $4, $5, $5, 'launcher', now() + interval '8 hours', $6)`, w.org, id, agent, w.env, w.owner, simulated)
}

func (w *world) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := w.try(sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (w *world) try(sql string, args ...any) error {
	return w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
}

func (w *world) as() context.Context {
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{
			Org: w.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: w.owner},
			Bindings: []td.Binding{{Role: td.RoleAgentOwner, Scope: td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}}},
		},
		Credential: tenancy.CredAccessToken,
	})
}

func (w *world) start(t *testing.T) domain.Campaign {
	t.Helper()
	c, err := w.svc.StartCampaign(w.as(), app.StartInput{
		Agent: w.twin, Campaigns: []app.Decl{{ID: "RT-140", Digest: digest}}, RunnerVersion: "test", ImageDigest: image,
		ModelHost: modelHost, Relay: w.relay,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestHR611_TheDatabaseHoldsTheTwinAndRelayMarks: a campaign of a real agent,
// or through a relay that is not a simulated model relay, is refused by the
// database itself; a twin has one open campaign; a model relay is simulated
// http and its mark cannot be changed by the application role.
// Covers: F900
func TestHR611_TheDatabaseHoldsTheTwinAndRelayMarks(t *testing.T) {
	w := newWorld(t, dbtest.New(t))
	insert := `INSERT INTO pc.campaigns (org_id, id, range_agent_id, started_by, runner_version, set_digest, scenario_ids, image_digest,
		model_host, relay_connection_id, scripted) VALUES ($1, $2, $3, 'user:x', 'test', $4, '{RT-140}', $5, $6, $7, false)`
	if err := w.try(insert, w.org, ids.NewV7(), w.real, digest, image, modelHost, w.relay); !db.IsCheckViolation(err) {
		t.Fatalf("a real agent's campaign: %v", err)
	}
	for _, conn := range []ids.UUID{w.plainSim, w.realConn} {
		if err := w.try(insert, w.org, ids.NewV7(), w.twin, digest, image, modelHost, conn); !db.IsCheckViolation(err) {
			t.Fatalf("relay %s: %v", conn, err)
		}
	}
	w.start(t)
	if err := w.try(insert, w.org, ids.NewV7(), w.twin, digest, image, modelHost, w.relay); !db.IsUniqueViolation(err) {
		t.Fatalf("a second open campaign: %v", err)
	}
	if err := w.try(`INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, simulated, model_relay, created_by, updated_by)
		VALUES ($1, $2, 'bad', 'http', $3, 'model-relay', 'http://127.0.0.1:9', 'none', false, true, 'test', 'test')`, w.org, ids.NewV7(), w.gateway); !db.IsCheckViolation(err) {
		t.Fatalf("a real model relay: %v", err)
	}
	if err := w.try("UPDATE pc.connections SET model_relay = true WHERE org_id = $1 AND id = $2", w.org, w.plainSim); err == nil {
		t.Fatal("the application role marked a connection a model relay")
	}
}

// TestHR613_TheModelRouteCountsOnTheServer: the server allows the open
// campaign's twin run, counts requests and bytes each way and nothing else,
// stops at the run total, and refuses a real agent's run, a run from before
// the campaign, a connection that is no relay, another gateway, and every
// call once the campaign has finished.
// Covers: F906
func TestHR613_TheModelRouteCountsOnTheServer(t *testing.T) {
	w := newWorld(t, dbtest.New(t))
	c := w.start(t)
	w.runOf(t, w.twinRun, w.twin, true)
	w.runOf(t, w.realRun, w.real, false)
	call := app.ModelCall{Gateway: w.gateway, Connection: w.relay, Run: w.twinRun, ModelHost: modelHost, BytesToModel: 100}
	got, err := w.svc.AuthorizeModelCall(context.Background(), w.org, call)
	if err != nil || got != c.ID {
		t.Fatalf("the twin run's call: %v %v", got, err)
	}
	if err := w.svc.ReportModelUsage(context.Background(), w.org, w.gateway, c.ID, w.twinRun, 40); err != nil {
		t.Fatal(err)
	}
	if err := w.svc.ReportModelUsage(context.Background(), w.org, ids.NewV7(), c.ID, w.twinRun, 40); !errors.Is(err, app.ErrModelRoute) {
		t.Fatalf("another gateway's report: %v", err)
	}
	for name, m := range map[string]app.ModelCall{
		"a real agent's run":          {Gateway: w.gateway, Connection: w.relay, Run: w.realRun, ModelHost: modelHost},
		"a run before the campaign":   {Gateway: w.gateway, Connection: w.relay, Run: w.earlierRun, ModelHost: modelHost},
		"a simulated non-relay":       {Gateway: w.gateway, Connection: w.plainSim, Run: w.twinRun, ModelHost: modelHost},
		"a real connection":           {Gateway: w.gateway, Connection: w.realConn, Run: w.twinRun, ModelHost: modelHost},
		"another gateway":             {Gateway: ids.NewV7(), Connection: w.relay, Run: w.twinRun, ModelHost: modelHost},
		"another model host":          {Gateway: w.gateway, Connection: w.relay, Run: w.twinRun, ModelHost: "api.other.test"},
		"another org's view of a run": {Gateway: w.gateway, Connection: w.relay, Run: ids.NewV7(), ModelHost: modelHost},
	} {
		if _, err := w.svc.AuthorizeModelCall(context.Background(), w.org, m); !errors.Is(err, app.ErrModelRoute) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The run total, at the database: past it no row is counted.
	if err := (pgcampaigns.Store{Pool: w.pool}).InTx(context.Background(), w.org, false, func(ctx context.Context, tx app.Tx) error {
		if ok, err := tx.AddModelRequest(ctx, c.ID, w.twinRun, modelHost, 1000, 1000); err != nil || ok {
			t.Errorf("past the total: %v %v", ok, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.FinishCampaign(w.as(), c.ID, []app.RunReport{{Run: w.twinRun, Scenario: "RT-140"}}); err != nil {
		t.Fatal(err)
	}
	d, err := w.svc.GetCampaign(w.as(), c.ID)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, u := range d.Usage {
		if u.Run == w.twinRun {
			found = true
			if u.Requests != 1 || u.BytesToModel != 100 || u.BytesFromModel != 40 || u.ModelHost != modelHost {
				t.Fatalf("usage %+v", u)
			}
		}
	}
	if !found {
		t.Fatal("the run's usage is missing")
	}
	if _, err := w.svc.AuthorizeModelCall(context.Background(), w.org, call); !errors.Is(err, app.ErrModelRoute) {
		t.Fatalf("a finished campaign's call: %v", err)
	}
}

// TestHR612_CampaignResultsStayInTheirOrg: the read port returns finished
// campaigns only, and another org reads none of them.
// Covers: F903
func TestHR612_CampaignResultsStayInTheirOrg(t *testing.T) {
	d := dbtest.New(t)
	w := newWorld(t, d)
	c := w.start(t)
	reader := ports.ResultReader(pgcampaigns.Store{Pool: w.pool})
	f := ports.Filter{Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Hour)}
	if r, err := reader.CampaignResults(context.Background(), w.org, f); err != nil || len(r.Items) != 0 {
		t.Fatalf("an open campaign read as a result: %v %v", r, err)
	}
	if _, err := w.svc.FinishCampaign(w.as(), c.ID, nil); err != nil {
		t.Fatal(err)
	}
	r, err := reader.CampaignResults(context.Background(), w.org, f)
	if err != nil || len(r.Items) != 1 || r.Items[0].Campaign.ID != c.ID {
		t.Fatalf("results %+v %v", r, err)
	}
	other := newWorld(t, d)
	if r, err := reader.CampaignResults(context.Background(), other.org, f); err != nil || len(r.Items) != 0 {
		t.Fatalf("another org read %d results: %v", len(r.Items), err)
	}
	if _, err := other.svc.GetCampaign(other.as(), c.ID); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("another org read the campaign: %v", err)
	}
}
