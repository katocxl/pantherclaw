// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package simulation_test

import (
	"context"
	"fmt"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/policy/simulation"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// world is a service and a runner over the in-memory store and a fake
// replay engine.
type world struct {
	store  *memStore
	replay *fakeReplay
	svc    *simulation.Service
	runner *simulation.Runner
}

func newWorld(edition billing.Edition) *world {
	w := &world{store: newMemStore(), replay: &fakeReplay{byTxn: map[ids.UUID]outcome{}}}
	v := versions{proposedBundle}
	w.svc = &simulation.Service{Store: w.store, Versions: v, Editions: editions(edition), IsNotFound: func(err error) bool { return err != nil }}
	w.runner = &simulation.Runner{Store: w.store, Replay: w.replay, Versions: v, Chunk: 7, Budget: time.Hour}
	return w
}

// record adds n recorded decisions of operation, newest first after the
// ones already there, each decided as o.
func (w *world) record(n int, operation string, o outcome) {
	last := now
	if k := len(w.store.recorded); k > 0 {
		last = w.store.recorded[k-1].Created
	}
	for i := range n {
		txn := ids.NewV7()
		w.store.recorded = append(w.store.recorded, simulation.Recorded{
			Transaction: txn, Evaluation: 1, Created: last.Add(-time.Duration(i+1) * time.Hour), Agent: ids.NewV7(), Operation: operation,
		})
		w.replay.byTxn[txn] = o
	}
}

func (w *world) run(t *testing.T, id ids.UUID) simulation.Simulation {
	t.Helper()
	for i := 0; ; i++ {
		more, err := w.runner.Step(context.Background(), org, id)
		if err != nil {
			t.Fatal(err)
		}
		if !more {
			break
		}
		if i > 1000 {
			t.Fatal("the simulation never finished")
		}
	}
	s, err := w.svc.Get(as(td.RolePolicyAuthor), id)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (w *world) simulate(t *testing.T, r simulation.Request) simulation.Simulation {
	t.Helper()
	r.Version = version
	s, err := w.svc.Simulate(as(td.RolePolicyAuthor), r)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func code(err error) string { return pcerr.ReasonOf(err) }

// TestClassify: D5's categories, by severity (stand-in for
// replay.Classify).
func TestClassify(t *testing.T) {
	for _, c := range []struct {
		before, after adomain.Decision
		br, ar        string
		want          simulation.Category
	}{
		{adomain.Allow, adomain.Allow, "GRANT_COVERS", "GRANT_COVERS", simulation.Unchanged},
		{adomain.Allow, adomain.Deny, "GRANT_COVERS", "REFUND_TOO_LARGE", simulation.NewlyDenied},
		{adomain.RequireApproval, adomain.CannotAuthorize, "HOLD", "FACT_MISSING", simulation.NewlyDenied},
		{adomain.Allow, adomain.RequireApproval, "GRANT_COVERS", "HOLD", simulation.NewlyHeld},
		{adomain.AllowWithObligations, adomain.RequireStepUp, "C", "S", simulation.NewlyHeld},
		{adomain.Allow, adomain.AllowWithObligations, "GRANT_COVERS", "CONSTRAINED", simulation.NewlyConstrained},
		{adomain.Deny, adomain.Allow, "REFUND_TOO_LARGE", "GRANT_COVERS", simulation.NewlyAllowed},
		{adomain.RequireApproval, adomain.RequireStepUp, "HOLD", "S", simulation.NewlyAllowed},
		{adomain.Deny, adomain.CannotAuthorize, "X", "Y", simulation.ReasonChanged},
		{adomain.Deny, adomain.Deny, "X", "Y", simulation.ReasonChanged},
	} {
		if got := simulation.Classify(c.before, c.after, c.br, c.ar); got != c.want {
			t.Errorf("%s/%s → %s/%s: %s, want %s", c.before, c.br, c.after, c.ar, got, c.want)
		}
	}
}

// TestSimulationReportsEachCategoryAndTheBurden: every category is counted
// apart, per operation and per agent; newly held decisions are counted
// per day and by the role the version requires; a decision that does not
// reproduce, or that the version cannot evaluate on its recorded inputs,
// is unevaluable with its limitation codes, never guessed (R-26).
func TestSimulationReportsEachCategoryAndTheBurden(t *testing.T) {
	w := newWorld(billing.Team)
	const refund, get = "payments.refund.create", "payments.refund.get"
	w.record(3, refund, outcome{orig: adomain.Allow, origReason: "GRANT_COVERS", prop: adomain.Deny, propReason: "REFUND_TOO_LARGE"})
	w.record(2, refund, outcome{
		orig: adomain.Allow, origReason: "GRANT_COVERS", prop: adomain.RequireApproval, propReason: "REFUND_LARGE", rule: "hold-large",
	})
	w.record(1, refund, outcome{
		orig: adomain.Allow, origReason: "GRANT_COVERS", prop: adomain.RequireStepUp, propReason: "STEP_UP_NEEDED", rule: "step-up",
	})
	w.record(1, refund, outcome{orig: adomain.Allow, origReason: "GRANT_COVERS", prop: adomain.AllowWithObligations, propReason: "C"})
	w.record(4, get, outcome{orig: adomain.Deny, origReason: "R", prop: adomain.Allow, propReason: "GRANT_COVERS"})
	w.record(2, get, outcome{orig: adomain.Deny, origReason: "R", prop: adomain.Deny, propReason: "OTHER"})
	w.record(5, get, outcome{orig: adomain.Allow, origReason: "GRANT_COVERS", prop: adomain.Allow, propReason: "GRANT_COVERS"})
	w.record(1, get, outcome{orig: adomain.Allow, origReason: "GRANT_COVERS", notReproduced: true})
	w.record(2, refund, outcome{orig: adomain.Allow, origReason: "GRANT_COVERS", incomplete: true})

	s := w.run(t, w.simulate(t, simulation.Request{}).ID)
	want := simulation.Counts{
		simulation.NewlyDenied: 3, simulation.NewlyHeld: 3, simulation.NewlyConstrained: 1, simulation.NewlyAllowed: 4,
		simulation.ReasonChanged: 2, simulation.Unchanged: 5, simulation.Unevaluable: 3,
	}
	if s.State != simulation.Done || s.Evaluated != 21 || !reflect.DeepEqual(s.Report.Counts, want) {
		t.Fatalf("simulation: %s, %d evaluated, %v", s.State, s.Evaluated, s.Report.Counts)
	}
	if got := s.Report.ByOperation[refund]; got[simulation.NewlyDenied] != 3 || got[simulation.Unevaluable] != 2 || got.Total() != 9 {
		t.Errorf("by operation %s: %v", refund, got)
	}
	if len(s.Report.ByAgent) != 21 {
		t.Errorf("by agent: %d agents", len(s.Report.ByAgent))
	}
	if !reflect.DeepEqual(s.Report.HeldByRole, map[string]int{"refund_approver": 2, simulation.RoleStepUp: 1}) {
		t.Errorf("held by role: %v", s.Report.HeldByRole)
	}
	days := 0
	for _, n := range s.Report.HeldPerDay {
		days += n
	}
	if days != 3 {
		t.Errorf("held per day: %v", s.Report.HeldPerDay)
	}
	notices := strings.Join(s.Notices(), "\n")
	if !strings.Contains(notices, "expanded exposure: 4") || !strings.Contains(notices, "3 recorded decision(s) could not be evaluated") {
		t.Errorf("notices: %s", notices)
	}
	samples, err := w.svc.Samples(as(td.RolePolicyAuthor), s.ID, simulation.SampleFilter{Category: simulation.Unevaluable}, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	var lims []string
	for _, x := range samples.Items {
		lims = append(lims, strings.Join(x.Limitations, ","))
	}
	slices.Sort(lims)
	if !slices.Equal(lims, []string{"INPUT_UNAVAILABLE", "INPUT_UNAVAILABLE", simulation.NotReproduced}) {
		t.Errorf("unevaluable limitations: %v", lims)
	}
	if !strings.Contains(simulation.Limits, "not agent replanning or business outcomes") {
		t.Error("the report's limits text lacks F192's statement")
	}
}

// TestHR237_SimulationIsBounded: the window is 1 to 30 days and inside
// retention, the count 1 to 50 000; the runner stops at its cap and keeps
// at most 25 samples per category and operation.
func TestHR237_SimulationIsBounded(t *testing.T) {
	w := newWorld(billing.Team)
	for _, c := range []struct {
		r    simulation.Request
		want string
	}{
		{simulation.Request{Version: version, Days: 31}, "INVALID_SIMULATION_WINDOW"},
		{simulation.Request{Version: version, Days: -1}, "INVALID_SIMULATION_WINDOW"},
		{simulation.Request{Version: version, Max: simulation.MaxEvaluations + 1}, "INVALID_SIMULATION_BOUNDS"},
		{simulation.Request{Version: version, Max: -5}, "INVALID_SIMULATION_BOUNDS"},
	} {
		if _, err := w.svc.Simulate(as(td.RolePolicyAuthor), c.r); code(err) != c.want {
			t.Errorf("%+v: %v, want %s", c.r, err, c.want)
		}
	}
	w.store.retention = 7
	if _, err := w.svc.Simulate(as(td.RolePolicyAuthor), simulation.Request{Version: version, Days: 8}); code(err) != "INVALID_SIMULATION_WINDOW" {
		t.Fatalf("a window past retention: %v", err)
	}
	w.store.retention = 90

	w.record(60, "payments.refund.create", outcome{orig: adomain.Allow, origReason: "GRANT_COVERS", prop: adomain.Deny, propReason: "NO"})
	s := w.simulate(t, simulation.Request{Days: 30, Max: 40})
	if s.Max != 40 || s.WindowEnd.Sub(s.WindowStart) != 30*24*time.Hour {
		t.Fatalf("stored bounds: %+v", s)
	}
	s = w.run(t, s.ID)
	if s.State != simulation.Done || s.Evaluated != 40 || s.Report.Counts.Total() != 40 || w.replay.calls != 80 {
		t.Fatalf("capped run: %s, %d evaluated, %d counted, %d replays", s.State, s.Evaluated, s.Report.Counts.Total(), w.replay.calls)
	}
	if n := len(w.store.samples[s.ID]); n != simulation.SamplesPerGroup {
		t.Fatalf("%d samples of one category and operation, want %d", n, simulation.SamplesPerGroup)
	}
	if !slices.ContainsFunc(s.Notices(), func(n string) bool { return strings.Contains(n, "cap of 40") }) {
		t.Errorf("notices: %v", s.Notices())
	}
	def := w.simulate(t, simulation.Request{})
	if def.Max != simulation.DefaultMaxEvaluations || def.WindowEnd.Sub(def.WindowStart) != simulation.DefaultDays*24*time.Hour {
		t.Fatalf("defaults: %+v", def)
	}
}

// TestHR237_SimulationOneRunningPerOrg: a second simulation is refused
// while one is queued or running; a cancelled one stops counting and frees
// the org; a finished one cannot be cancelled.
func TestHR237_SimulationOneRunningPerOrg(t *testing.T) {
	w := newWorld(billing.Team)
	w.record(30, "payments.refund.create", outcome{orig: adomain.Allow, origReason: "GRANT_COVERS", prop: adomain.Allow, propReason: "GRANT_COVERS"})
	first := w.simulate(t, simulation.Request{})
	if _, err := w.svc.Simulate(as(td.RolePolicyAuthor), simulation.Request{Version: version}); code(err) != "SIMULATION_RUNNING" {
		t.Fatalf("a second simulation while one is queued: %v", err)
	}
	// Cancelled after the first chunk's replays: that chunk is not
	// counted, and nothing more runs.
	w.replay.onReplay = func() {
		if w.replay.calls == 14 {
			s := w.store.sims[first.ID]
			s.State = simulation.Cancelled
			w.store.sims[first.ID] = s
		}
	}
	more, err := w.runner.Step(context.Background(), org, first.ID)
	if err != nil || more {
		t.Fatalf("step after cancel: %v %v", more, err)
	}
	if s := w.store.sims[first.ID]; s.State != simulation.Cancelled || s.Evaluated != 0 || w.replay.calls != 14 {
		t.Fatalf("cancelled: %s, %d evaluated, %d replays", s.State, s.Evaluated, w.replay.calls)
	}
	w.replay.onReplay = nil
	second := w.simulate(t, simulation.Request{})
	done := w.run(t, second.ID)
	if _, err := w.svc.Cancel(as(td.RolePolicyAuthor), done.ID); code(err) != "SIMULATION_FINISHED" {
		t.Fatalf("cancel a finished simulation: %v", err)
	}
	third := w.simulate(t, simulation.Request{})
	if c, err := w.svc.Cancel(as(td.RolePolicyAuthor), third.ID); err != nil || c.State != simulation.Cancelled {
		t.Fatalf("cancel a queued simulation: %+v %v", c, err)
	}
	if more, err := w.runner.Step(context.Background(), org, third.ID); err != nil || more {
		t.Fatalf("a cancelled simulation ran: %v %v", more, err)
	}
	names := []string{}
	for _, ev := range w.store.audits {
		names = append(names, ev.Name)
	}
	if !slices.Contains(names, "policy.simulation_requested") || !slices.Contains(names, "policy.simulation_cancelled") {
		t.Errorf("audit: %v", names)
	}
}

// TestHR237_SimulationIsTeamAndFailsClosed: Community is refused with
// EDITION_REQUIRED, and so is a server without entitlements wired; a
// caller without policy.simulate is refused before anything is read.
func TestHR237_SimulationIsTeamAndFailsClosed(t *testing.T) {
	w := newWorld(billing.Community)
	if _, err := w.svc.Simulate(as(td.RolePolicyAuthor), simulation.Request{Version: version}); code(err) != "EDITION_REQUIRED" {
		t.Fatalf("community: %v", err)
	}
	w.svc.Editions = nil
	if _, err := w.svc.Simulate(as(td.RolePolicyAuthor), simulation.Request{Version: version}); code(err) != "EDITION_REQUIRED" {
		t.Fatalf("no entitlements: %v", err)
	}
	for _, ed := range []billing.Edition{billing.Team, billing.Business, billing.Enterprise} {
		w := newWorld(ed)
		if _, err := w.svc.Simulate(as(td.RolePolicyPublisher), simulation.Request{Version: version}); err != nil {
			t.Fatalf("%s: %v", ed, err)
		}
	}
	w = newWorld(billing.Team)
	for _, role := range []td.RoleName{td.RoleApprover, td.RoleAuditor, ""} {
		if _, err := w.svc.Simulate(as(role), simulation.Request{Version: version}); pcerr.CodeOf(err) != pcerr.PermissionDenied {
			t.Errorf("role %q: %v", role, err)
		}
		if _, err := w.svc.Get(as(role), ids.NewV7()); err == nil || code(err) == "SIMULATION_NOT_FOUND" {
			t.Errorf("role %q read a simulation: %v", role, err)
		}
	}
	if len(w.store.sims) != 0 || len(w.store.enqueued) != 0 {
		t.Fatal("a refused request stored or enqueued a simulation")
	}
	if _, err := w.svc.Simulate(as(td.RolePolicyAuthor), simulation.Request{Version: ids.NewV7()}); code(err) != "POLICY_VERSION_NOT_FOUND" {
		t.Fatalf("unknown version: %v", err)
	}
}

// TestHR237_SimulationOutputsCarryNoInputValues: a report, a sample and a
// result hold ids, decisions, reason codes and counts only; no field can
// carry a recorded input value (raw JSON, bytes, maps of values or the
// recording).
func TestHR237_SimulationOutputsCarryNoInputValues(t *testing.T) {
	allowed := map[reflect.Type]bool{
		reflect.TypeFor[ids.UUID](): true, reflect.TypeFor[time.Time](): true, reflect.TypeFor[adomain.Decision](): true,
		reflect.TypeFor[simulation.Category](): true, reflect.TypeFor[simulation.Counts](): true,
		reflect.TypeFor[map[string]simulation.Counts](): true, reflect.TypeFor[map[string]int](): true,
	}
	for _, typ := range []reflect.Type{reflect.TypeFor[simulation.Report](), reflect.TypeFor[simulation.Sample](), reflect.TypeFor[simulation.Result]()} {
		for i := range typ.NumField() {
			f := typ.Field(i)
			k := f.Type.Kind()
			ok := allowed[f.Type] || k == reflect.String || k == reflect.Int || (k == reflect.Slice && f.Type.Elem().Kind() == reflect.String)
			if !ok {
				t.Errorf("%s.%s is %s: outputs carry ids, decisions, codes and counts only", typ.Name(), f.Name, f.Type)
			}
		}
	}
	// What the runner stores comes from the outcome's decisions and codes:
	// a checklist detail with an input value never reaches a sample.
	w := newWorld(billing.Team)
	w.record(1, "payments.refund.create", outcome{
		orig: adomain.Allow, origReason: "GRANT_COVERS", prop: adomain.RequireApproval, propReason: "REFUND_LARGE", rule: "hold-large",
	})
	w.record(1, "payments.refund.create", outcome{orig: adomain.Allow, origReason: "GRANT_COVERS", incomplete: true})
	s := w.run(t, w.simulate(t, simulation.Request{}).ID)
	dump := fmt.Sprintf("%+v %+v", s, w.store.samples[s.ID])
	for _, secret := range []string{"payments.charge.state", "never read", "policy org-policy@2 rule"} {
		if strings.Contains(dump, secret) {
			t.Errorf("an output holds %q:\n%s", secret, dump)
		}
	}
}

// TestT101_SimulationHoldsReadPortsOnly: the runner reaches recorded
// decisions only through the replay engine and stored versions, whose
// ports read (HR-197); the package imports no finalization, gateway,
// connector or dispatch code, so a simulation cannot act on a target; and
// nothing in internal/authority imports it.
func TestT101_SimulationHoldsReadPortsOnly(t *testing.T) {
	for _, c := range []struct {
		typ     reflect.Type
		methods []string
	}{
		{reflect.TypeFor[simulation.Replayer](), []string{"Replay"}},
		{reflect.TypeFor[simulation.Versions](), []string{"PolicyVersion"}},
	} {
		var got []string
		for i := range c.typ.NumMethod() {
			got = append(got, c.typ.Method(i).Name)
		}
		if !slices.Equal(got, c.methods) {
			t.Errorf("%s has methods %v, want %v", c.typ, got, c.methods)
		}
	}
	forbidden := []string{
		"internal/authority/finalize", "internal/authority/adapters", "internal/gateway", "internal/connectors", "internal/connections",
		"internal/sandbox", "internal/credentials", "internal/platform/jobs", "internal/platform/db", "net/http",
	}
	pkg, err := build.Import("github.com/katocxl/pantherclaw/internal/policy/simulation", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range pkg.Imports {
		for _, f := range forbidden {
			if strings.Contains(imp, f) {
				t.Errorf("the simulation package imports %s", imp)
			}
		}
	}
	authority, err := build.Import("github.com/katocxl/pantherclaw/internal/authority", "", build.FindOnly)
	if err != nil {
		t.Fatal(err)
	}
	files := 0
	err = filepath.WalkDir(authority.Dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		files++
		for _, imp := range f.Imports {
			if strings.Contains(imp.Path.Value, "internal/policy/simulation") {
				t.Errorf("%s imports %s", path, imp.Path.Value)
			}
		}
		return nil
	})
	if err != nil || files < 50 {
		t.Fatalf("walked %d files of internal/authority: %v", files, err)
	}
}
