// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgsimulation_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/rpcauth"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
	"github.com/katocxl/pantherclaw/internal/platform/rpc/protoperms"
	"github.com/katocxl/pantherclaw/internal/policy/simulation"
	"github.com/katocxl/pantherclaw/internal/policy/simulation/simulationrpc"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// decide records four refunds under the published policy (holds over 50)
// and returns the draft that holds over 20 for an approver and
// forbids over 60.
func (w *world) decide() ids.UUID {
	w.t.Helper()
	w.refundable("ch_1", "ch_2", "ch_3", "ch_4")
	w.policy(false, holdOver50)
	draft := w.policy(true, holdOver20, forbidOver60)
	run := w.run()
	for _, c := range []struct {
		charge, amount string
		want           adomain.Decision
	}{
		{"ch_1", "10.00", adomain.Allow}, {"ch_2", "30.00", adomain.Allow},
		{"ch_3", "55.00", adomain.RequireApproval}, {"ch_4", "70.00", adomain.RequireApproval},
	} {
		if r := w.refund(run, c.charge, c.amount); r.Decision != c.want {
			w.t.Fatalf("refund of %s: %s", c.amount, r.Decision)
		}
	}
	return draft
}

// TestHR232_SimulationWritesOnlyItsOwnRows: a simulation of a draft over
// recorded refunds counts them by category (a refund it would newly hold
// is unevaluable, with its limitation) and keeps its samples, while every
// other table of the database keeps its rows: no transaction, receipt,
// reservation, permit, claim, ledger entry, audit event or job, and no
// target reached (the runner has no gateway or finalization, only the
// replay engine's read ports).
func TestHR232_SimulationWritesOnlyItsOwnRows(t *testing.T) {
	w := newWorld(t)
	draft := w.decide()
	s, err := w.svc.Simulate(w.human, simulation.Request{Version: draft, Days: 1})
	if err != nil {
		t.Fatal(err)
	}
	before := w.rowCounts()
	w.finish(s.ID)
	after := w.rowCounts()
	for tb, n := range before {
		switch {
		case tb == "policy_simulation_samples":
			if after[tb] != n+4 {
				t.Errorf("samples: %d before, %d after", n, after[tb])
			}
		case after[tb] != n:
			t.Errorf("table %s: %d rows before the simulation ran, %d after", tb, n, after[tb])
		}
	}
	if len(after) != len(before) || len(before) < 50 {
		t.Fatalf("tables counted: %d before, %d after", len(before), len(after))
	}
	got, err := w.svc.Get(w.human, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	// The 30.00 refund the draft would hold is unevaluable: the hold needs
	// reads (the approval's) its allowed evaluation never made (R-26).
	want := simulation.Counts{simulation.Unchanged: 1, simulation.Unevaluable: 1, simulation.ReasonChanged: 1, simulation.NewlyDenied: 1}
	if got.State != simulation.Done || got.Evaluated != 4 || !reflect.DeepEqual(got.Report.Counts, want) || got.Finished == nil || got.Started == nil {
		t.Fatalf("simulation: %s %d %v", got.State, got.Evaluated, got.Report.Counts)
	}
	unevaluable, err := w.svc.Samples(w.human, s.ID, simulation.SampleFilter{Category: simulation.Unevaluable}, 0, "")
	if err != nil || len(unevaluable.Items) != 1 || unevaluable.Items[0].Original != "ALLOW" || unevaluable.Items[0].Proposed != "" ||
		!slices.Equal(unevaluable.Items[0].Limitations, []string{"INPUT_UNAVAILABLE"}) {
		t.Fatalf("unevaluable samples: %+v %v", unevaluable.Items, err)
	}
	if c := got.Report.ByOperation["payments.refund.create"]; c.Total() != 4 || len(got.Report.ByAgent[w.agent.String()]) == 0 {
		t.Fatalf("by workflow: %v %v", got.Report.ByOperation, got.Report.ByAgent)
	}
	// Run again: a finished simulation is not counted twice.
	w.finish(s.ID)
	if again, _ := w.svc.Get(w.human, s.ID); again.Evaluated != 4 {
		t.Fatalf("a finished simulation ran again: %d", again.Evaluated)
	}
}

type callers map[string]tapp.Caller

func (c callers) Authenticate(_ context.Context, bearer string) (tapp.Caller, error) {
	if cl, ok := c[bearer]; ok {
		return cl, nil
	}
	return tapp.Caller{}, pcerr.New(pcerr.Unauthenticated, "UNAUTHENTICATED", "invalid or expired credentials")
}

type bearerRT struct{ tok string }

func (b bearerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.tok)
	return http.DefaultTransport.RoundTrip(r)
}

// api serves PolicySimulationService over HTTP as the server does: the
// permission interceptor with the protos' declarations, and protovalidate.
func (w *world) api(svc *simulation.Service) (callers, string) {
	w.t.Helper()
	declared, err := protoperms.Declared(filepath.Join("..", "..", "..", "..", "proto"))
	if err != nil {
		w.t.Fatal(err)
	}
	perms := map[string]td.Permission{}
	for proc, p := range declared {
		perms[proc] = td.Permission(p)
	}
	cs := callers{}
	s, err := rpc.NewServer(rpc.Options{Authenticate: rpcauth.New(cs, perms, nil)})
	if err != nil {
		w.t.Fatal(err)
	}
	pantherclawv1connect.RegisterPolicySimulationServiceHandler(s, simulationrpc.New(svc))
	mux := http.NewServeMux()
	rpc.Mount(mux, s)
	ts := httptest.NewServer(mux)
	w.t.Cleanup(ts.Close)
	return cs, ts.URL
}

func client(cs callers, url, name string, org ids.OrgID, roles ...td.RoleName) pantherclawv1connect.PolicySimulationServiceClient {
	var bs []td.Binding
	for _, r := range roles {
		bs = append(bs, td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}})
	}
	cs[name] = tapp.Caller{Subject: td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()}, Bindings: bs}}
	return pantherclawv1connect.NewPolicySimulationServiceClient(connect.NewClient(connecthttp.NewTransport(&http.Client{
		Timeout: 30 * time.Second, Transport: bearerRT{name},
	}, url)))
}

func wantCode(t *testing.T, what string, err error, want connect.Code) {
	t.Helper()
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Code() != want {
		t.Fatalf("%s: %v, want %s", what, err, want)
	}
}

// TestHR237_SimulationThroughTheRPC: served as the API serves it, a
// simulation needs policy.simulate (policy author and publisher, org
// admin; not the auditor or approver), one runs per org, another org's
// caller cannot see it, its report and samples carry ids, decisions and
// reason codes but none of the recorded inputs (charges, amounts, the
// refund's reason), and a Community server refuses it (EDITION_REQUIRED).
func TestHR237_SimulationThroughTheRPC(t *testing.T) {
	w := newWorld(t)
	draft := w.decide()
	cs, url := w.api(w.svc)
	ctx := context.Background()
	author := client(cs, url, "author", w.org, td.RolePolicyAuthor)
	for _, r := range []td.RoleName{td.RoleAuditor, td.RoleApprover, td.RoleSecurityAdmin} {
		_, err := client(cs, url, string(r), w.org, r).SimulatePolicyVersion(ctx, &pantherclawv1.SimulatePolicyVersionRequest{VersionId: draft.String()})
		wantCode(t, string(r), err, connect.CodePermissionDenied)
	}
	_, err := author.SimulatePolicyVersion(ctx, &pantherclawv1.SimulatePolicyVersionRequest{VersionId: draft.String(), Days: 31})
	wantCode(t, "a 31-day window", err, connect.CodeInvalidArgument)
	_, err = author.SimulatePolicyVersion(ctx, &pantherclawv1.SimulatePolicyVersionRequest{VersionId: ids.NewV7().String()})
	wantCode(t, "an unknown version", err, connect.CodeNotFound)
	res, err := author.SimulatePolicyVersion(ctx, &pantherclawv1.SimulatePolicyVersionRequest{VersionId: draft.String(), Days: 2, MaxEvaluations: 3})
	if err != nil {
		t.Fatal(err)
	}
	sim := res.GetSimulation()
	if sim.GetState() != pantherclawv1.PolicySimulationState_POLICY_SIMULATION_STATE_QUEUED || sim.GetMaxEvaluations() != 3 ||
		len(sim.GetContentDigest()) != 64 || !strings.Contains(sim.GetLimits(), "not agent replanning") {
		t.Fatalf("queued: %+v", sim)
	}
	var jobsQueued int
	w.db.AdminQueryRow(t, `SELECT count(*) FROM pc.river_job WHERE kind = 'policy_simulate'`, nil, &jobsQueued)
	if jobsQueued != 1 {
		t.Fatalf("%d jobs queued for the simulation", jobsQueued)
	}
	publisher := client(cs, url, "publisher", w.org, td.RolePolicyPublisher)
	_, err = publisher.SimulatePolicyVersion(ctx, &pantherclawv1.SimulatePolicyVersionRequest{VersionId: draft.String()})
	wantCode(t, "a second simulation while one is queued", err, connect.CodeFailedPrecondition)

	other := ids.New[ids.Org]()
	_, err = client(cs, url, "other", other, td.RolePolicyAuthor).GetSimulation(ctx, &pantherclawv1.GetSimulationRequest{Id: sim.GetId()})
	wantCode(t, "another org's caller", err, connect.CodeNotFound)

	id, _ := ids.ParseUUID(sim.GetId())
	w.finish(id)
	admin := client(cs, url, "admin", w.org, td.RoleOrgAdmin)
	got, err := admin.GetSimulation(ctx, &pantherclawv1.GetSimulationRequest{Id: sim.GetId()})
	if err != nil {
		t.Fatal(err)
	}
	if s := got.GetSimulation(); s.GetState() != pantherclawv1.PolicySimulationState_POLICY_SIMULATION_STATE_DONE || s.GetEvaluated() != 3 ||
		!strings.Contains(strings.Join(s.GetNotices(), " "), "cap of 3") {
		t.Fatalf("done: %+v", s)
	}
	samples, err := author.ListSimulationSamples(ctx, &pantherclawv1.ListSimulationSamplesRequest{SimulationId: sim.GetId(), PageSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	next, err := author.ListSimulationSamples(ctx, &pantherclawv1.ListSimulationSamplesRequest{
		SimulationId: sim.GetId(), PageToken: samples.GetNextPageToken(),
	})
	if err != nil || len(samples.GetSamples()) != 2 || samples.GetNextPageToken() == "" || len(next.GetSamples()) != 1 {
		t.Fatalf("samples: %d then %d, %v", len(samples.GetSamples()), len(next.GetSamples()), err)
	}
	list, err := author.ListSimulations(ctx, &pantherclawv1.ListSimulationsRequest{})
	if err != nil || len(list.GetSimulations()) != 1 {
		t.Fatalf("list: %v %v", list, err)
	}
	out := ""
	for _, m := range []proto.Message{got, samples, next, list} {
		b, err := protojson.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		out += string(b)
	}
	for _, input := range []string{"ch_1", "ch_2", "ch_3", "ch_4", "10.00", "30.00", "55.00", "70.00", "duplicate", "payments.charge.refundable"} {
		if strings.Contains(out, input) {
			t.Errorf("an output holds the recorded input %q", input)
		}
	}
	if !strings.Contains(out, "REQUIRE_APPROVAL") || !strings.Contains(out, w.agent.String()) {
		t.Errorf("the outputs lack decisions or ids:\n%s", out)
	}

	community := *w.svc
	community.Editions = nil
	ccs, curl := w.api(&community)
	_, err = client(ccs, curl, "author", w.org, td.RolePolicyAuthor).SimulatePolicyVersion(ctx, &pantherclawv1.SimulatePolicyVersionRequest{
		VersionId: draft.String(),
	})
	wantCode(t, "a Community server", err, connect.CodePermissionDenied)
	if !strings.Contains(err.Error(), "Team edition") {
		t.Fatalf("community: %v", err)
	}
}

// TestHR237_SimulationSchemaHoldsTheBounds: as pc_app, the database
// refuses a window over 30 days, a second queued simulation in an org, a
// 26th sample of a category and operation, a sample of a simulation that
// is not running, a simulation that moves backwards, and any change to a
// sample.
func TestHR237_SimulationSchemaHoldsTheBounds(t *testing.T) {
	w := newWorld(t)
	draft := w.policy(true, holdOver50)
	ctx := context.Background()
	insert := func(days int32) (dbq.PcPolicySimulation, error) {
		var out dbq.PcPolicySimulation
		err := w.pool.InTenantTx(ctx, w.org, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			out, err = dbq.New(tx).InsertPolicySimulation(ctx, dbq.InsertPolicySimulationParams{
				OrgID: w.org, ID: ids.NewV7(), VersionID: draft, ContentDigest: make([]byte, 32), Days: days, MaxEvaluations: 10, RequestedBy: "test",
			})
			return err
		})
		return out, err
	}
	if _, err := insert(31); !db.IsCheckViolation(err) {
		t.Fatalf("a 31-day window: %v", err)
	}
	sim, err := insert(30)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := insert(1); !db.IsUniqueViolation(err) {
		t.Fatalf("a second queued simulation: %v", err)
	}
	q := func(fn func(q *dbq.Queries) error) error {
		return w.pool.InTenantTx(ctx, w.org, func(ctx context.Context, tx db.TenantTx) error { return fn(dbq.New(tx)) })
	}
	sample := func(op string) dbq.InsertSimulationSampleParams {
		return dbq.InsertSimulationSampleParams{
			OrgID: w.org, SimulationID: sim.ID, Category: "NEWLY_DENIED", TransactionID: ids.NewV7(), Evaluation: 1, AgentID: ids.NewV7(),
			Operation: op, OriginalDecision: "ALLOW", ProposedDecision: "DENY",
		}
	}
	if err := q(func(q *dbq.Queries) error { return q.InsertSimulationSample(ctx, sample("payments.refund.create")) }); !db.IsCheckViolation(err) {
		t.Fatalf("a sample of a queued simulation: %v", err)
	}
	if err := q(func(q *dbq.Queries) error { _, err := q.StartPolicySimulation(ctx, w.org, sim.ID); return err }); err != nil {
		t.Fatal(err)
	}
	for i := range simulation.SamplesPerGroup {
		if err := q(func(q *dbq.Queries) error { return q.InsertSimulationSample(ctx, sample("payments.refund.create")) }); err != nil {
			t.Fatalf("sample %d: %v", i+1, err)
		}
	}
	if err := q(func(q *dbq.Queries) error { return q.InsertSimulationSample(ctx, sample("payments.refund.create")) }); !db.IsCheckViolation(err) {
		t.Fatalf("a 26th sample: %v", err)
	}
	if err := q(func(q *dbq.Queries) error { return q.InsertSimulationSample(ctx, sample("payments.refund.get")) }); err != nil {
		t.Fatalf("a sample of another operation: %v", err)
	}
	if err := q(func(q *dbq.Queries) error { _, err := q.CancelPolicySimulation(ctx, w.org, sim.ID); return err }); err != nil {
		t.Fatal(err)
	}
	exec := func(sql string) error {
		return w.pool.InTenantTx(ctx, w.org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql, sim.ID)
			return err
		})
	}
	if err := exec(`UPDATE pc.policy_simulations SET state = 'RUNNING' WHERE id = $1`); !db.IsCheckViolation(err) {
		t.Fatalf("a cancelled simulation ran again: %v", err)
	}
	for _, sql := range []string{
		`UPDATE pc.policy_simulation_samples SET proposed_decision = 'ALLOW' WHERE simulation_id = $1`,
		`DELETE FROM pc.policy_simulation_samples WHERE simulation_id = $1`,
		`UPDATE pc.policy_simulations SET window_start = window_start - interval '1 day' WHERE id = $1`,
		`DELETE FROM pc.policy_simulations WHERE id = $1`,
	} {
		if err := exec(sql); !db.IsPermissionDenied(err) {
			t.Errorf("%s: %v", sql, err)
		}
	}
}
