// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/campaigns/app"
	"github.com/katocxl/pantherclaw/internal/campaigns/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/redteam/library"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

var (
	digest = strings.Repeat("a", 64)
	image  = "sha256:" + strings.Repeat("b", 64)
)

// fake is an in-memory store: one org, one transaction at a time.
type fake struct {
	agents    map[ids.UUID]app.AgentRef
	conns     map[ids.UUID]app.ConnectionRef
	campaigns map[ids.UUID]domain.Campaign
	steps     map[ids.UUID][]domain.Step
	runs      map[ids.UUID]domain.RunRecord
	txns      map[ids.UUID][]domain.Transaction
	// open is each campaign's open step; bound is each run's binding, as
	// the database's trigger makes it (D525 M1).
	open    map[ids.UUID]string
	bound   map[ids.UUID]binding
	routes  map[binding][]domain.Route
	audited []string
	relays  map[ids.UUID]app.RelayRef
	// usage is each bound run's model traffic: requests, to, from; reserved
	// its answers' reservations (D525 L2).
	usage    map[ids.UUID][3]int64
	reserved map[ids.UUID]int64
}

type binding struct {
	campaign ids.UUID
	scenario string
}

func (f *fake) RelayConnection(_ context.Context, id ids.UUID) (app.RelayRef, bool, error) {
	r, ok := f.relays[id]
	return r, ok, nil
}

func (f *fake) AddModelRequest(_ context.Context, _, run ids.UUID, n, reserve, total int64) (bool, error) {
	if _, ok := f.bound[run]; !ok {
		return false, nil
	}
	u := f.usage[run]
	if u[1]+u[2]+f.reserved[run]+n+reserve > total {
		return false, nil
	}
	f.usage[run] = [3]int64{u[0] + 1, u[1] + n, u[2]}
	f.reserved[run] += reserve
	return true, nil
}

func (f *fake) AddModelAnswer(_ context.Context, _, run ids.UUID, n, reserve int64) (bool, error) {
	if _, ok := f.bound[run]; !ok {
		return false, nil
	}
	u := f.usage[run]
	u[2] += n
	f.usage[run] = u
	f.reserved[run] = max(f.reserved[run]-reserve, 0)
	return true, nil
}

func (f *fake) OpenStep(_ context.Context, id ids.UUID, scenario string) (bool, error) {
	if f.campaigns[id].State != domain.Running {
		return false, nil
	}
	f.open[id] = scenario
	return true, nil
}

func (f *fake) BoundRuns(_ context.Context, id ids.UUID) (map[ids.UUID]string, error) {
	out := map[ids.UUID]string{}
	for run, b := range f.bound {
		if b.campaign == id {
			out[run] = b.scenario
		}
	}
	return out, nil
}

// WorstTransactions hands back every matching transaction; Derive keeps the
// worst, as the query does (its ordering is tested against Postgres).
func (f *fake) WorstTransactions(_ context.Context, runs []ids.UUID, ops []string) ([]domain.Transaction, error) {
	var out []domain.Transaction
	for _, r := range runs {
		for _, t := range f.txns[r] {
			if slices.Contains(ops, t.Operation) {
				out = append(out, t)
			}
		}
	}
	return out, nil
}

func (f *fake) StepRoutes(_ context.Context, id ids.UUID, scenario string, limit int32) ([]domain.Route, error) {
	r := f.routes[binding{id, scenario}]
	return r[:min(len(r), int(limit))], nil
}

func (f *fake) InTx(ctx context.Context, _ ids.OrgID, _ bool, fn func(context.Context, app.Tx) error) error {
	return fn(ctx, f)
}

func (f *fake) Agent(_ context.Context, id ids.UUID) (app.AgentRef, error) {
	a, ok := f.agents[id]
	if !ok {
		return a, app.ErrAgentMissing
	}
	return a, nil
}

func (f *fake) Connection(_ context.Context, id ids.UUID) (app.ConnectionRef, bool, error) {
	c, ok := f.conns[id]
	return c, ok, nil
}

func (f *fake) Campaign(_ context.Context, id ids.UUID, _ bool) (domain.Campaign, error) {
	c, ok := f.campaigns[id]
	if !ok {
		return c, app.ErrNotFound
	}
	return c, nil
}

func (f *fake) OpenOf(_ context.Context, agent ids.UUID) (domain.Campaign, bool, error) {
	for _, c := range f.campaigns {
		if c.Agent == agent && c.State == domain.Running {
			return c, true, nil
		}
	}
	return domain.Campaign{}, false, nil
}

func (f *fake) InsertCampaign(_ context.Context, c domain.Campaign) (domain.Campaign, error) {
	c.Started = time.Now()
	f.campaigns[c.ID] = c
	return c, nil
}

func (f *fake) Transition(_ context.Context, id ids.UUID, to domain.State) (time.Time, bool, error) {
	c := f.campaigns[id]
	if c.State != domain.Running {
		return time.Time{}, false, nil
	}
	at := time.Now()
	c.State, c.Finished = to, &at
	f.campaigns[id] = c
	return at, true, nil
}

func (f *fake) List(context.Context, *ids.UUID, ids.UUID, int32) ([]domain.Campaign, error) {
	return nil, nil
}

func (f *fake) CountsOf(context.Context, []ids.UUID) (map[ids.UUID]domain.Counts, error) {
	return nil, nil
}

func (f *fake) Steps(_ context.Context, id ids.UUID) ([]domain.Step, error) { return f.steps[id], nil }

func (f *fake) InsertStep(_ context.Context, id ids.UUID, s domain.Step) error {
	f.steps[id] = append(f.steps[id], s)
	return nil
}

func (f *fake) Run(_ context.Context, id ids.UUID) (domain.RunRecord, bool, error) {
	r, ok := f.runs[id]
	return r, ok, nil
}

func (f *fake) Usage(context.Context, ids.UUID) ([]app.Usage, error) { return nil, nil }

func (f *fake) Audit(_ context.Context, ev audit.Event) error {
	f.audited = append(f.audited, ev.Name)
	return nil
}

type ents struct{ e billing.Edition }

func (e ents) Current(context.Context) (billing.Entitlements, error) {
	if e.e == billing.Community {
		return billing.CommunityEntitlements(), nil
	}
	return billing.Entitlements{Edition: e.e, Status: billing.StatusValid}, nil
}

type world struct {
	f     *fake
	svc   *app.Service
	ctx   context.Context
	agent ids.UUID
	relay ids.UUID
}

func entry(attempts ...domain.Attempt) library.CampaignEntry {
	return library.CampaignEntry{Digest: digest, Tier: "business", Attempts: attempts}
}

func newWorld(t *testing.T, edition billing.Edition) *world {
	t.Helper()
	org := ids.New[ids.Org]()
	w := &world{agent: ids.NewV7(), relay: ids.NewV7(), f: &fake{
		agents: map[ids.UUID]app.AgentRef{}, conns: map[ids.UUID]app.ConnectionRef{}, campaigns: map[ids.UUID]domain.Campaign{},
		steps: map[ids.UUID][]domain.Step{}, runs: map[ids.UUID]domain.RunRecord{}, txns: map[ids.UUID][]domain.Transaction{},
		open: map[ids.UUID]string{}, bound: map[ids.UUID]binding{}, routes: map[binding][]domain.Route{},
		relays: map[ids.UUID]app.RelayRef{}, usage: map[ids.UUID][3]int64{}, reserved: map[ids.UUID]int64{},
	}}
	w.f.agents[w.agent] = app.AgentRef{ID: w.agent, RangeAgent: true, Path: td.OrgPath(org)}
	w.f.conns[w.relay] = app.ConnectionRef{ID: w.relay, Simulated: true, ModelRelay: true}
	lib := map[string]library.CampaignEntry{
		"RT-140": entry(domain.Attempt{ID: "merge", Boundary: "HR-201", Expected: domain.ExpectHeld, Operation: "op.merge"},
			domain.Attempt{ID: "exfil", Boundary: "HR-214", Expected: domain.ExpectNotRouted, RouteHost: "evil.example"}),
		"RT-141": entry(domain.Attempt{ID: "push", Boundary: "HR-201", Expected: domain.ExpectDenied, Operation: "op.push"}),
	}
	w.svc = &app.Service{Store: w.f, Editions: ents{edition}, Library: func(id string) (library.CampaignEntry, bool) { e, ok := lib[id]; return e, ok }}
	w.ctx = tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RoleAgentOwner, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}},
	}})
	return w
}

func (w *world) input(names ...string) app.StartInput {
	in := app.StartInput{Agent: w.agent, RunnerVersion: "pclaw 1", ImageDigest: image, ModelHost: "model.provider.test", Relay: w.relay}
	for _, id := range names {
		in.Campaigns = append(in.Campaigns, app.Decl{ID: id, Digest: digest})
	}
	return in
}

// run creates a run of the twin; like the database's trigger, it binds the
// run to the campaign's open step, if any.
func (w *world) run(c domain.Campaign, txns ...domain.Transaction) ids.UUID {
	id := ids.NewV7()
	w.f.runs[id] = domain.RunRecord{ID: id, Agent: c.Agent, Simulated: true, Created: c.Started}
	w.f.txns[id] = txns
	if s, ok := w.f.open[c.ID]; ok && w.f.campaigns[c.ID].State == domain.Running {
		w.f.bound[id] = binding{c.ID, s}
	}
	return id
}

func (w *world) step(t *testing.T, c domain.Campaign, scenario string) {
	t.Helper()
	if err := w.svc.StartCampaignStep(w.ctx, c.ID, scenario); err != nil {
		t.Fatal(err)
	}
}

func txn(op, decision string) domain.Transaction {
	return domain.Transaction{ID: ids.NewV7(), Operation: op, Decision: decision, Mode: "enforce", Simulated: true}
}

func outcomes(d app.Detail) map[string]domain.Step {
	got := map[string]domain.Step{}
	for _, s := range d.Steps {
		got[s.Scenario+"/"+s.ID] = s
	}
	return got
}

// TestHR611_OnlyARangeTwin: a real agent is refused, and so is a relay that
// is not a simulated connection; a twin takes one open campaign.
// Covers: F900
func TestHR611_OnlyARangeTwin(t *testing.T) {
	w := newWorld(t, billing.Business)
	prod := ids.NewV7()
	w.f.agents[prod] = app.AgentRef{ID: prod, Path: w.f.agents[w.agent].Path}
	in := w.input("RT-140")
	in.Agent = prod
	if _, err := w.svc.StartCampaign(w.ctx, in); !errors.Is(err, app.ErrNotRange) {
		t.Fatalf("a real agent: %v", err)
	}
	in = w.input("RT-140")
	in.Relay = ids.NewV7()
	if _, err := w.svc.StartCampaign(w.ctx, in); !errors.Is(err, app.ErrRelay) {
		t.Fatalf("no relay: %v", err)
	}
	w.f.conns[in.Relay] = app.ConnectionRef{ID: in.Relay}
	if _, err := w.svc.StartCampaign(w.ctx, in); !errors.Is(err, app.ErrRelay) {
		t.Fatalf("a real connection: %v", err)
	}
	w.f.conns[in.Relay] = app.ConnectionRef{ID: in.Relay, Simulated: true}
	if _, err := w.svc.StartCampaign(w.ctx, in); !errors.Is(err, app.ErrRelay) {
		t.Fatalf("a simulated connection that is no model relay: %v", err)
	}
	if _, err := w.svc.StartCampaign(w.ctx, w.input("RT-140")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.StartCampaign(w.ctx, w.input("RT-141")); !errors.Is(err, app.ErrOpen) {
		t.Fatalf("a second open campaign: %v", err)
	}
}

// TestF900_Editions: Business and above run campaigns.
// Covers: F900
func TestF900_Editions(t *testing.T) {
	for e, ok := range map[billing.Edition]bool{billing.Community: false, billing.Team: false, billing.Business: true, billing.Enterprise: true} {
		w := newWorld(t, e)
		_, err := w.svc.StartCampaign(w.ctx, w.input("RT-140"))
		if ok != (err == nil) || (!ok && !errors.Is(err, app.ErrEdition)) {
			t.Errorf("%s: %v", e, err)
		}
	}
}

// TestF900_OnlyTheLibrarysCampaigns: the digest must be the library's.
// Covers: F900
func TestF900_OnlyTheLibrarysCampaigns(t *testing.T) {
	w := newWorld(t, billing.Business)
	in := w.input("RT-140")
	in.Campaigns[0].Digest = strings.Repeat("c", 64)
	if _, err := w.svc.StartCampaign(w.ctx, in); !errors.Is(err, app.ErrNotLibrary) {
		t.Fatalf("another digest: %v", err)
	}
	if _, err := w.svc.StartCampaign(w.ctx, w.input("RT-149")); !errors.Is(err, app.ErrNotLibrary) {
		t.Fatalf("not in the library: %v", err)
	}
	if _, err := w.svc.StartCampaign(w.ctx, w.input("RT-140", "RT-140")); !errors.Is(err, app.ErrScenarios) {
		t.Fatalf("twice: %v", err)
	}
	in = w.input("RT-140")
	in.ImageDigest = "latest"
	if _, err := w.svc.StartCampaign(w.ctx, in); !errors.Is(err, app.ErrScenarios) {
		t.Fatalf("a tag: %v", err)
	}
}

// TestHR608_FinishDerivesEveryOutcome: held and reported from the server's
// records of the run bound to the step, and a scenario whose step never
// opened is a gap. A route in the runner's request counts for nothing; only
// the edge's stored reports do (D525 L6).
// Covers: F901, F902, F903
func TestHR608_FinishDerivesEveryOutcome(t *testing.T) {
	w := newWorld(t, billing.Business)
	c, err := w.svc.StartCampaign(w.ctx, w.input("RT-140", "RT-141"))
	if err != nil {
		t.Fatal(err)
	}
	w.step(t, c, "RT-140")
	run := w.run(c, txn("op.merge", "REQUIRE_APPROVAL"))
	w.f.routes[binding{c.ID, "RT-140"}] = []domain.Route{{Kind: domain.RouteDirectAPI, Locator: "evil.example:443"}}
	d, err := w.svc.FinishCampaign(w.ctx, c.ID, []app.RunReport{{Scenario: "RT-140", Run: run}})
	if err != nil {
		t.Fatal(err)
	}
	got := outcomes(d)
	want := map[string]domain.Outcome{"RT-140/merge": domain.Held, "RT-140/exfil": domain.NotRoutedReported, "RT-141/push": domain.NotExercised}
	for k, v := range want {
		if got[k].Outcome != v {
			t.Errorf("%s: %s, want %s", k, got[k].Outcome, v)
		}
	}
	if d.Campaign.State != domain.Finished || w.f.campaigns[c.ID].State != domain.Finished {
		t.Fatalf("%+v", d.Campaign)
	}
	if _, err := w.svc.FinishCampaign(w.ctx, c.ID, nil); !errors.Is(err, app.ErrNotRunning) {
		t.Fatalf("finished twice: %v", err)
	}

	// A route only in the request is no report.
	w2 := newWorld(t, billing.Business)
	c2, err := w2.svc.StartCampaign(w2.ctx, w2.input("RT-140"))
	if err != nil {
		t.Fatal(err)
	}
	w2.step(t, c2, "RT-140")
	run2 := w2.run(c2)
	d2, err := w2.svc.FinishCampaign(w2.ctx, c2.ID, []app.RunReport{{
		Scenario: "RT-140", Run: run2, Routes: []domain.Route{{Kind: domain.RouteDirectAPI, Locator: "evil.example:443"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if s := outcomes(d2)["RT-140/exfil"]; s.Outcome != domain.NotExercised {
		t.Fatalf("a route from the request counted: %+v", s)
	}
}

// TestHR609_EveryBoundRunCounts: a run the runner leaves out, or replaces
// with a benign one, still counts, the worst outcome winning; a run made
// before any step opened is bound to nothing and claims nothing (D525 M1).
// Covers: F902
func TestHR609_EveryBoundRunCounts(t *testing.T) {
	w := newWorld(t, billing.Business)
	c, err := w.svc.StartCampaign(w.ctx, w.input("RT-140", "RT-141"))
	if err != nil {
		t.Fatal(err)
	}
	early := w.run(c, txn("op.push", "ALLOW"))
	w.step(t, c, "RT-140")
	w.run(c, txn("op.merge", "ALLOW"))
	benign := w.run(c, txn("op.merge", "REQUIRE_APPROVAL"))
	d, err := w.svc.FinishCampaign(w.ctx, c.ID, []app.RunReport{{Scenario: "RT-140", Run: benign}})
	if err != nil {
		t.Fatal(err)
	}
	got := outcomes(d)
	if got["RT-140/merge"].Outcome != domain.Allowed || got["RT-141/push"].Outcome != domain.NotExercised {
		t.Fatalf("outcomes %+v", got)
	}
	if _, ok := w.f.bound[early]; ok {
		t.Fatal("a run from before any step was bound")
	}
}

// TestHR609_AStepTooLargeIsAGap: past the bound runs or the stored reports
// a step may hold, every attempt is RUN_TOO_LARGE, never a better outcome
// (D525 M2).
// Covers: F902
func TestHR609_AStepTooLargeIsAGap(t *testing.T) {
	for name, fill := range map[string]func(w *world, c domain.Campaign){
		"runs": func(w *world, c domain.Campaign) {
			for range app.MaxBoundRuns + 1 {
				w.run(c, txn("op.merge", "ALLOW"))
			}
		},
		"routes": func(w *world, c domain.Campaign) {
			w.run(c, txn("op.merge", "ALLOW"))
			rs := make([]domain.Route, app.MaxStepRoutes+1)
			for i := range rs {
				rs[i] = domain.Route{Kind: domain.RouteCredential, Locator: "x"}
			}
			w.f.routes[binding{c.ID, "RT-140"}] = rs
		},
	} {
		w := newWorld(t, billing.Business)
		c, err := w.svc.StartCampaign(w.ctx, w.input("RT-140"))
		if err != nil {
			t.Fatal(err)
		}
		w.step(t, c, "RT-140")
		fill(w, c)
		d, err := w.svc.FinishCampaign(w.ctx, c.ID, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range d.Steps {
			if s.Outcome != domain.NotExercised || s.Reason != domain.ReasonRunTooLarge {
				t.Errorf("%s: %+v", name, s)
			}
		}
	}
}

// TestHR611_ARunMustBeBoundToItsScenario: a run the server did not bind
// (real, foreign, from before the step), or bound to another scenario, is
// refused and leaves the campaign open; so is a step or a run of an
// undeclared scenario.
// Covers: F900
func TestHR611_ARunMustBeBoundToItsScenario(t *testing.T) {
	w := newWorld(t, billing.Business)
	c, err := w.svc.StartCampaign(w.ctx, w.input("RT-140", "RT-141"))
	if err != nil {
		t.Fatal(err)
	}
	early := w.run(c)
	if err := w.svc.StartCampaignStep(w.ctx, c.ID, "RT-142"); !errors.Is(err, app.ErrRuns) {
		t.Fatalf("an undeclared step: %v", err)
	}
	w.step(t, c, "RT-140")
	on140 := w.run(c)
	realRun, foreignRun := ids.NewV7(), ids.NewV7()
	w.f.runs[realRun] = domain.RunRecord{ID: realRun, Agent: c.Agent, Created: c.Started}
	w.f.runs[foreignRun] = domain.RunRecord{ID: foreignRun, Agent: ids.NewV7(), Simulated: true, Created: c.Started}
	for name, rep := range map[string]app.RunReport{
		"real":            {Scenario: "RT-140", Run: realRun},
		"foreign":         {Scenario: "RT-140", Run: foreignRun},
		"before the step": {Scenario: "RT-140", Run: early},
		"other scenario":  {Scenario: "RT-141", Run: on140},
	} {
		if _, err := w.svc.FinishCampaign(w.ctx, c.ID, []app.RunReport{rep}); !errors.Is(err, app.ErrRecord) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := w.svc.FinishCampaign(w.ctx, c.ID, []app.RunReport{{Scenario: "RT-149", Run: on140}}); !errors.Is(err, app.ErrRuns) {
		t.Errorf("undeclared: %v", err)
	}
	if w.f.campaigns[c.ID].State != domain.Running {
		t.Fatal("a refused finish closed the campaign")
	}
	if _, err := w.svc.FinishCampaign(w.ctx, c.ID, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.svc.StartCampaignStep(w.ctx, c.ID, "RT-141"); !errors.Is(err, app.ErrNotRunning) {
		t.Fatalf("a step after the finish: %v", err)
	}
}
