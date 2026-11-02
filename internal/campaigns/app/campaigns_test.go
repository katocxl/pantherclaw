// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app_test

import (
	"context"
	"errors"
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
	marked    map[ids.UUID]string
	audited   []string
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

func (f *fake) Transactions(_ context.Context, run ids.UUID) ([]domain.Transaction, error) {
	return f.txns[run], nil
}

func (f *fake) SetRunScenario(_ context.Context, _ domain.Campaign, run ids.UUID, scenario string) error {
	f.marked[run] = scenario
	return nil
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
		steps: map[ids.UUID][]domain.Step{}, runs: map[ids.UUID]domain.RunRecord{}, txns: map[ids.UUID][]domain.Transaction{}, marked: map[ids.UUID]string{},
	}}
	w.f.agents[w.agent] = app.AgentRef{ID: w.agent, RangeAgent: true, Path: td.OrgPath(org)}
	w.f.conns[w.relay] = app.ConnectionRef{ID: w.relay, Simulated: true}
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

func (w *world) run(c domain.Campaign, txns ...domain.Transaction) ids.UUID {
	id := ids.NewV7()
	w.f.runs[id] = domain.RunRecord{ID: id, Agent: c.Agent, Simulated: true, Created: c.Started}
	w.f.txns[id] = txns
	return id
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

// TestHR608_FinishDerivesEveryOutcome: held, reported and not exercised, from
// the server's records and the report, with a scenario that never ran left a
// gap.
// Covers: F901, F902, F903
func TestHR608_FinishDerivesEveryOutcome(t *testing.T) {
	w := newWorld(t, billing.Business)
	c, err := w.svc.StartCampaign(w.ctx, w.input("RT-140", "RT-141"))
	if err != nil {
		t.Fatal(err)
	}
	run := w.run(c, domain.Transaction{ID: ids.NewV7(), Operation: "op.merge", Decision: "REQUIRE_APPROVAL", Mode: "enforce", Simulated: true})
	d, err := w.svc.FinishCampaign(w.ctx, c.ID, []app.RunReport{{
		Scenario: "RT-140", Run: run, Routes: []domain.Route{{Kind: domain.RouteDirectAPI, Locator: "evil.example:443"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]domain.Outcome{}
	for _, s := range d.Steps {
		got[s.Scenario+"/"+s.ID] = s.Outcome
	}
	want := map[string]domain.Outcome{"RT-140/merge": domain.Held, "RT-140/exfil": domain.NotRoutedReported, "RT-141/push": domain.NotExercised}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %s, want %s", k, got[k], v)
		}
	}
	if d.Campaign.State != domain.Finished || w.f.campaigns[c.ID].State != domain.Finished || w.f.marked[run] != "RT-140" {
		t.Fatalf("%+v", d.Campaign)
	}
	if _, err := w.svc.FinishCampaign(w.ctx, c.ID, nil); !errors.Is(err, app.ErrNotRunning) {
		t.Fatalf("finished twice: %v", err)
	}
}

// TestHR609_ALeftOutRunOnlyWidensTheGap: with no runs named, nothing is
// claimed.
// Covers: F902
func TestHR609_ALeftOutRunOnlyWidensTheGap(t *testing.T) {
	w := newWorld(t, billing.Business)
	c, err := w.svc.StartCampaign(w.ctx, w.input("RT-140"))
	if err != nil {
		t.Fatal(err)
	}
	w.run(c, domain.Transaction{ID: ids.NewV7(), Operation: "op.merge", Decision: "ALLOW", Mode: "enforce", Simulated: true})
	d, err := w.svc.FinishCampaign(w.ctx, c.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d.Counts.NotExercised != 2 || d.Counts.Held != 0 {
		t.Fatalf("%+v", d.Counts)
	}
}

// TestHR611_ARunMustBeTheTwins: a real, foreign or earlier run is refused and
// leaves the campaign open; a run of an undeclared scenario too.
// Covers: F900
func TestHR611_ARunMustBeTheTwins(t *testing.T) {
	w := newWorld(t, billing.Business)
	c, err := w.svc.StartCampaign(w.ctx, w.input("RT-140"))
	if err != nil {
		t.Fatal(err)
	}
	for name, rec := range map[string]domain.RunRecord{
		"real":    {Agent: c.Agent, Created: c.Started},
		"foreign": {Agent: ids.NewV7(), Simulated: true, Created: c.Started},
		"earlier": {Agent: c.Agent, Simulated: true, Created: c.Started.Add(-time.Minute)},
	} {
		id := ids.NewV7()
		w.f.runs[id] = rec
		if _, err := w.svc.FinishCampaign(w.ctx, c.ID, []app.RunReport{{Scenario: "RT-140", Run: id}}); !errors.Is(err, app.ErrRecord) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := w.svc.FinishCampaign(w.ctx, c.ID, []app.RunReport{{Scenario: "RT-141", Run: w.run(c)}}); !errors.Is(err, app.ErrRuns) {
		t.Errorf("undeclared: %v", err)
	}
	if w.f.campaigns[c.ID].State != domain.Running {
		t.Fatal("a refused finish closed the campaign")
	}
}
