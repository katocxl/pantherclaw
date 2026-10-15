// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/adapters/pgauthority"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	"github.com/katocxl/pantherclaw/internal/authority/replay"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	polpg "github.com/katocxl/pantherclaw/internal/policy/adapters/pgstore"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/policy/exceptions"
	"github.com/katocxl/pantherclaw/internal/policy/rollout"
	"github.com/katocxl/pantherclaw/internal/policy/scenario"
	"github.com/katocxl/pantherclaw/internal/policy/simulation"
	"github.com/katocxl/pantherclaw/internal/policy/simulation/pgsimulation"
	"github.com/katocxl/pantherclaw/internal/policy/validate"
	"github.com/katocxl/pantherclaw/internal/server"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The M11.1 exit (G0 M11.1 design decision 17): one organization's policy
// goes the whole lifecycle. A draft is validated (a conflict is found, then
// fixed) and tested (a surviving mutant refuses publication, then is
// fixed); it is simulated over the decisions the organization recorded,
// shadowed on live traffic, piloted on a cohort of one agent whose target
// becomes ACKNOWLEDGED and VERIFIED, and completed. A loosening needs two
// confirmations with two security keys; a rollback carries an emergency
// rule; an exception waives an exceptable hold for one agent, the receipt
// shows EXCEPTION_APPLIED, and the exception expires by the database clock.
//
// Team features are exercised in-process: the e2e server is Community
// because the licence roots are empty until Day-0. Simulation, shadow and
// pilot run through the services the server wires, over the same database,
// with a Team edition (teamEdition, as M7's evidence-pack test does); the
// simulation is driven with Runner.Step over a store without the job
// client, so the server's Community worker never picks it up. Every
// decision goes through the real gateway and server, which select the
// pilot version from the database (D35, D36).

// Rules of the lifecycle's versions, on refunds of the payments simulator.
// ruleSeed is the dev seed's published rule (dev-holds), kept unchanged in
// every version so that only the lifecycle's own changes are classified.
const (
	ruleSeed = `{"id": "approve-large-refunds", "kind": "REQUIRE_APPROVAL", "summary": "refunds over 50.00 USD need an approver",
		"operations": ["payments.refund.create"], "when": "action.params.amount > money(\"50.00\", \"USD\")",
		"reason": "REFUND_NEEDS_APPROVAL", "approval": {"role": "approver", "count": 1}}`
	ruleCap = `{"id": "cap-refunds", "kind": "CONSTRAIN", "summary": "no refund over 90.00 USD",
		"operations": ["payments.refund.create"], "when": "true", "reason": "REFUND_OVER_CAP",
		"constraint": {"kind": "amount_max", "param": "amount", "max": "90.00", "currency": "USD"}}`
	// ruleCapEUR conflicts with ruleCap: two caps on the same amount in
	// different currencies.
	ruleCapEUR = `{"id": "cap-refunds-eur", "kind": "CONSTRAIN", "summary": "no refund over 80.00 EUR",
		"operations": ["payments.refund.create"], "when": "true", "reason": "REFUND_OVER_EUR_CAP",
		"constraint": {"kind": "amount_max", "param": "amount", "max": "80.00", "currency": "EUR"}}`
	ruleHold = `{"id": "hold-refunds", "kind": "REQUIRE_APPROVAL", "summary": "an approver reviews refunds over 20.00 USD",
		"operations": ["payments.refund.create"], "when": "action.params.amount > money('20.00', 'USD')",
		"reason": "REFUND_HELD_FOR_REVIEW", "approval": {"role": "approver", "count": 1}, "exceptable": true}`
	ruleEmergency = `{"id": "stop-fraud-refunds", "kind": "FORBID", "summary": "no refunds for fraud while the incident lasts",
		"operations": ["payments.refund.create"], "when": "action.params.reason == 'fraudulent'",
		"reason": "FRAUD_REFUNDS_STOPPED", "emergency": true}`
)

// refundCase is a scenario test of a refund of amount with reason.
func refundCase(id, amount, reason, decision, code, rule string) string {
	expect := fmt.Sprintf(`{"decision": %q, "reason": %q}`, decision, code)
	if rule != "" {
		expect = fmt.Sprintf(`{"decision": %q, "reason": %q, "rule": %q}`, decision, code, rule)
	}
	return fmt.Sprintf(`{"id": %q, "summary": "a %s refund of %s USD",
		"action": {"operation": "payments.refund.create", "target": {"type": "payments.charge", "id": "ch_1"},
			"params": {"amount": {"value": %q, "currency": "USD"}, "reason": %q}},
		"given": {"facts": {"payments.charge.refundable": {"value": {"bool": true}, "age_seconds": 10}}},
		"expect": %s}`, id, reason, amount, amount, reason, expect)
}

var (
	seedTests = []string{
		refundCase("seed-over", "50.01", "duplicate", "REQUIRE_APPROVAL", "REFUND_NEEDS_APPROVAL", "approve-large-refunds"),
	}
	// seedAtAllowed pins the seed's threshold while nothing else holds
	// 50.00; seedAtHeld while the lifecycle's hold does.
	seedAtAllowed = refundCase("seed-at", "50.00", "duplicate", "ALLOW", "GRANT_COVERS", "")
	seedAtHeld    = refundCase("seed-at", "50.00", "duplicate", "REQUIRE_APPROVAL", "REFUND_HELD_FOR_REVIEW", "hold-refunds")
	capTests      = []string{
		refundCase("cap-at", "90.00", "duplicate", "REQUIRE_APPROVAL", "REFUND_NEEDS_APPROVAL", "approve-large-refunds"),
		refundCase("cap-over", "90.01", "duplicate", "DENY", "REFUND_OVER_CAP", "cap-refunds"),
	}
	holdTests = []string{
		refundCase("hold-over", "30.00", "duplicate", "REQUIRE_APPROVAL", "REFUND_HELD_FOR_REVIEW", "hold-refunds"),
		refundCase("hold-under", "10.00", "duplicate", "ALLOW", "GRANT_COVERS", ""),
	}
	// holdAt pins the hold's threshold: without it the > / >= mutant
	// survives (HR-044).
	holdAt         = refundCase("hold-at", "20.00", "duplicate", "ALLOW", "GRANT_COVERS", "")
	emergencyTests = []string{
		refundCase("fraud-stopped", "10.00", "fraudulent", "DENY", "FRAUD_REFUNDS_STOPPED", "stop-fraud-refunds"),
		refundCase("no-hold", "30.00", "duplicate", "ALLOW", "GRANT_COVERS", ""),
	}
)

func lifecycleBundle(rules, tests []string) string {
	return `{"id": "dev-holds", "rules": [` + strings.Join(rules, ",") + `], "tests": [` + strings.Join(tests, ",") + `]}`
}

func cat(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

// lifecycle is the exit's stack, its people and its in-process Team
// services.
type lifecycle struct {
	s          *stack
	people     *m2Stack
	alice, bob *user
	agent      ids.UUID
	dir        string
	rollouts   *rollout.Service
	sims       *simulation.Service
	simRunner  *simulation.Runner
	publisher  context.Context
	author     context.Context
}

// gateVersions is the publish gate as the server wires it
// (internal/server/wiring_m11_gate.go), for the in-process rollout service.
func gateVersions(pool *db.Pool) *policyapp.Versions {
	defs := &defspg.Store{Pool: pool}
	facts := &factspg.Store{Pool: pool}
	v := &policyapp.Versions{
		Store: &polpg.Store{Pool: pool}, Facts: facts, Subjects: facts, Definitions: defs,
		Authz: grantsapp.SubjectAuthorizer{}, Limits: celenv.DefaultLimits,
		Validator: validate.New(defs, facts, facts, celenv.DefaultLimits),
		Tests:     scenario.New(defs, facts, celenv.DefaultLimits, policyapp.DefaultBudget),
	}
	v.Changes = policyapp.NewChanges(pool, nil, "", func(ctx context.Context, org ids.OrgID) ([32]byte, [32]byte, error) {
		ds, err := defs.ActiveDefinitions(ctx, org)
		if err != nil {
			return [32]byte{}, [32]byte{}, err
		}
		catalog, err := facts.Catalog(ctx, org)
		if err != nil {
			return [32]byte{}, [32]byte{}, err
		}
		return pdomain.DefinitionsDigest(ds), pdomain.CatalogDigest(catalog), nil
	})
	v.Changes.Register(policyapp.ChangePublish, v.ApplyPublish)
	return v
}

// noJobs is the simulation store without its job client: the e2e drives
// the runner itself, so the server's Community worker never picks a run up.
type noJobs struct{ pgsimulation.Store }

func (s noJobs) InTx(ctx context.Context, org ids.OrgID, readOnly bool, fn func(context.Context, simulation.Tx) error) error {
	return s.Store.InTx(ctx, org, readOnly, func(ctx context.Context, tx simulation.Tx) error { return fn(ctx, noEnqueue{tx}) })
}

type noEnqueue struct{ simulation.Tx }

func (noEnqueue) Enqueue(context.Context, ids.UUID) error { return nil }

func startLifecycle(t *testing.T) *lifecycle {
	t.Helper()
	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", people: &p})
	l := &lifecycle{s: s, people: &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p}, dir: t.TempDir()}
	org := s.org.String()
	var out, errb bytes.Buffer
	if code := server.Run(context.Background(), []string{"org", "admin-invite", "--config", s.serverCfg, "--org", org}, &out, &errb, noEnv); code != 0 {
		t.Fatalf("org admin-invite: %d %s", code, errb.String())
	}
	l.alice = l.people.user(t, "alice", "alice@example.test")
	l.alice.login(t, org, pciToken.FindStringSubmatch(out.String())[1])
	var aliceID string
	s.query(t, "SELECT id::text FROM pc.users WHERE subject = 'alice'", nil, &aliceID)
	// Alice authors and publishes policies, and reassesses coverage (a
	// security admin).
	for _, role := range []string{"policy_author", "policy_publisher", "security_admin"} {
		if code, o, e := l.alice.pclaw(t, "role", "bind", "--role", role, "--user", aliceID); code != 0 {
			t.Fatalf("role bind %s: %d %s %s", role, code, o, e)
		}
	}
	// Bob is the organization's second policy publisher: from now on a
	// loosening needs both of them (F1).
	code, invite, errs := l.alice.pclaw(t, "invite", "create", "--email", "bob@example.test", "--role", "policy_publisher")
	if code != 0 || pciToken.FindStringSubmatch(invite) == nil {
		t.Fatalf("invite bob: %d %s %s", code, invite, errs)
	}
	l.bob = l.people.user(t, "bob", "bob@example.test")
	l.bob.login(t, org, pciToken.FindStringSubmatch(invite)[1])
	l.agent = mustUUID(t, s.row(t, "SELECT agent_id::text FROM pc.runs WHERE id = $1", s.run))

	pool := s.pool
	kp, err := keys.NewFileProvider([]string{s.kek})
	if err != nil {
		t.Fatal(err)
	}
	// The replay engine as the server wires it (wiring_replay.go): read ports only.
	versions := &pgauthority.ReplaySource{Pool: pool, Definitions: &defspg.Store{Pool: pool}, FactStore: &factspg.Store{Pool: pool}}
	engine := &replay.Engine{Source: versions, Inputs: recording.NewSealer(pccrypto.NewEnvelope(keystore.NewDEKStore(pool, kp)))}
	l.rollouts = &rollout.Service{Pool: pool, Editions: teamEdition{}, Replay: engine, Lag: -1}
	l.rollouts.Gate = rollout.Connect(gateVersions(pool), l.rollouts)
	l.sims = &simulation.Service{
		Store: noJobs{pgsimulation.Store{Pool: pool}}, Versions: versions, Editions: teamEdition{},
		IsNotFound: func(err error) bool { return errors.Is(err, replay.ErrNotFound) },
	}
	l.simRunner = &simulation.Runner{Store: pgsimulation.Store{Pool: pool}, Replay: engine, Versions: versions}
	l.publisher = s.person(t, "rollout-publisher", td.RolePolicyPublisher).ctx
	l.author = s.person(t, "simulating-author", td.RolePolicyAuthor).ctx
	return l
}

// create stores bundle as a draft version through pclaw and returns its id.
func (l *lifecycle) create(t *testing.T, name, bundle string) string {
	t.Helper()
	f := filepath.Join(l.dir, name+".json")
	if err := os.WriteFile(f, []byte(bundle), 0o600); err != nil {
		t.Fatal(err)
	}
	code, o, e := l.alice.pclaw(t, "policy", "create", "--file", f)
	if code != 0 {
		t.Fatalf("policy create %s: %d %s %s", name, code, o, e)
	}
	return field(t, o, "id")
}

func (l *lifecycle) published(t *testing.T) string {
	t.Helper()
	return l.s.row(t, "SELECT id::text FROM pc.policy_versions WHERE state = 'PUBLISHED'")
}

// refund refunds amount as the seeded agent and checks the decision.
func (l *lifecycle) refund(t *testing.T, amount string, wantCode int, wantDecision string) reply {
	t.Helper()
	code, r := l.s.refund(t, ids.NewV7(), amount)
	if code != wantCode || (wantDecision != "" && r.Decision != wantDecision) {
		t.Fatalf("refund %s: %d %+v, want %d %s", amount, code, r, wantCode, wantDecision)
	}
	return r
}

// confirmBoth confirms change request id with alice's and bob's keys and
// returns the states after each.
func (l *lifecycle) confirmBoth(t *testing.T, alice, bob keyHolder, id string) (string, string) {
	t.Helper()
	if n := l.s.row(t, "SELECT required::text FROM pc.policy_change_requests WHERE id = $1", id); n != "2" {
		t.Fatalf("change request %s needs %s confirmations, want 2 (two publishers)", id, n)
	}
	return alice.confirmChange(t, id), bob.confirmChange(t, id)
}

func TestE2E_M11_PolicyLifecycle(t *testing.T) {
	l := startLifecycle(t)
	s, ctx := l.s, context.Background()

	// 0. The organization's first policy: a cap on refunds, published by one
	// publisher (it only tightens), then decisions are recorded under it.
	v1 := l.create(t, "v1", lifecycleBundle([]string{ruleSeed, ruleCap}, cat(seedTests, []string{seedAtAllowed}, capTests)))
	if code, o, e := l.alice.pclaw(t, "policy", "publish", v1); code != 0 || !strings.Contains(e, "published version") {
		t.Fatalf("publish v1: %d %s %s", code, o, e)
	}
	l.refund(t, "10.00", http.StatusOK, "")
	l.refund(t, "30.00", http.StatusOK, "")

	// 1. Validate: a draft with two caps in different currencies conflicts
	// (F196); without the second cap it validates.
	conflicting := l.create(t, "v2-conflict", lifecycleBundle([]string{ruleSeed, ruleCap, ruleCapEUR, ruleHold}, cat(seedTests, []string{seedAtHeld}, capTests, holdTests)))
	code, o, e := l.alice.pclaw(t, "policy", "validate", conflicting)
	if rep := parseGate(t, o); rep.Validation.Passed || !slices.ContainsFunc(rep.Validation.Findings, func(f finding) bool {
		return f.Code == "CONFLICT" && slices.Contains(f.Rules, "cap-refunds-eur")
	}) {
		t.Fatalf("validate a conflicting draft: %d %s %s", code, o, e)
	}

	// 2. Test: the fixed draft's tests do not pin the hold's threshold, so
	// a mutant survives and the gate refuses to publish it (HR-044, HR-230).
	weak := l.create(t, "v2-weak", lifecycleBundle([]string{ruleSeed, ruleCap, ruleHold}, cat(seedTests, []string{seedAtHeld}, capTests, holdTests)))
	if code, o, e = l.alice.pclaw(t, "policy", "validate", weak); code != 0 || !parseGate(t, o).Validation.Passed {
		t.Fatalf("validate the fixed draft: %d %s %s", code, o, e)
	}
	code, o, e = l.alice.pclaw(t, "policy", "test", weak)
	if rep := parseGate(t, o); rep.Tests.Passed || rep.Tests.Survivors == 0 || len(rep.Tests.Surviving) == 0 || rep.Tests.Surviving[0].Rule != "hold-refunds" {
		t.Fatalf("test a draft with a surviving mutant: %d %s %s", code, o, e)
	}
	if code, o, e = l.alice.pclaw(t, "policy", "publish", weak); code == 0 || !strings.Contains(e, "POLICY_TESTS_FAILED") {
		t.Fatalf("publish a draft whose tests let a mutant survive: %d %s %s", code, o, e)
	}
	if l.published(t) != v1 {
		t.Fatal("a draft that failed its tests was published")
	}
	v2 := l.create(t, "v2", lifecycleBundle([]string{ruleSeed, ruleCap, ruleHold}, cat(seedTests, []string{seedAtHeld}, capTests, holdTests, []string{holdAt})))
	if code, o, e = l.alice.pclaw(t, "policy", "test", v2); code != 0 || !parseGate(t, o).Tests.Passed {
		t.Fatalf("test v2: %d %s %s", code, o, e)
	}

	// 3. Simulate v2 over the recorded decisions (F187): the 30.00 refund
	// would be newly held, the 10.00 one unchanged.
	sim, err := l.sims.Simulate(l.author, simulation.Request{Version: mustUUID(t, v2), Days: 1})
	if err != nil {
		t.Fatalf("simulate v2: %v", err)
	}
	for more := true; more; {
		if more, err = l.simRunner.Step(ctx, s.org, sim.ID); err != nil {
			t.Fatalf("simulation step: %v", err)
		}
	}
	if sim, err = l.sims.Get(l.author, sim.ID); err != nil || sim.State != simulation.Done ||
		sim.Report.Counts[replay.NewlyHeld] < 1 || sim.Report.Counts[replay.Unchanged] < 1 {
		samples, _ := l.sims.Samples(l.author, sim.ID, simulation.SampleFilter{}, 10, "")
		t.Fatalf("simulation of v2: %+v %v; samples %+v", sim, err, samples)
	}

	// 4. Shadow v2 on live traffic: the 30.00 refund is still allowed, and
	// the shadow records that v2 would hold it (F200, HR-233).
	ro, err := l.rollouts.StartRollout(l.publisher, mustUUID(t, v2), nil)
	if err != nil || ro.Stage != "SHADOW" {
		t.Fatalf("start the shadow rollout: %+v %v", ro, err)
	}
	l.refund(t, "31.00", http.StatusOK, "")
	if sw, err := l.rollouts.SweepOrg(ctx, s.org); err != nil || sw.Shadowed < 1 {
		t.Fatalf("shadow sweep: %+v %v", sw, err)
	}
	sum, err := l.rollouts.GetShadowSummary(l.publisher, ro.ID)
	if err != nil || sum.ByCategory[replay.NewlyHeld] < 1 {
		t.Fatalf("shadow summary: %+v %v", sum, err)
	}

	// 5. Pilot v2 on a cohort of the one agent: it tightens the published
	// policy, so the pilot starts at once, and the agent's next 30.00 refund
	// is held. The sweep finds the decision (ACKNOWLEDGED) and, once the
	// agent's route is covered, VERIFIED (F202, HR-234).
	if _, err := l.rollouts.CreateCohort(l.publisher, "pilot-one"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.rollouts.ChangeCohort(l.publisher, "pilot-one", []ids.UUID{l.agent}, false); err != nil {
		t.Fatal(err)
	}
	ro, cr, err := l.rollouts.StartPilot(l.publisher, ro.ID, []string{"pilot-one"})
	if err != nil || cr != nil || ro.Stage != "PILOT" {
		t.Fatalf("start the pilot: %+v %+v %v", ro, cr, err)
	}
	r := l.refund(t, "32.00", http.StatusForbidden, "REQUIRE_APPROVAL")
	if !strings.Contains(strings.Join(r.Reasons, ","), "REFUND_HELD_FOR_REVIEW") {
		t.Fatalf("the pilot's hold: %+v", r)
	}
	target := func(want string) {
		t.Helper()
		if _, err := l.rollouts.SweepOrg(ctx, s.org); err != nil {
			t.Fatal(err)
		}
		ts, err := l.rollouts.ListTargets(l.publisher, ro.ID, "", ids.UUID{}, 10) // a first page
		if err != nil || len(ts) != 1 || ts[0].AgentID != l.agent || ts[0].State != want {
			reason := ""
			if len(ts) == 1 && ts[0].Reason != nil {
				reason = *ts[0].Reason
			}
			t.Fatalf("pilot targets of %s: %+v %v (reason %s), want the agent %s; snapshots %s; rows %s", ro.ID, ts, err, reason, want,
				s.row(t, "SELECT coalesce(string_agg(operation || ':' || state || ':' || coalesce(agent_id::text, '-'), ','), 'none') FROM pc.coverage_snapshots"),
				s.row(t, "SELECT coalesce(string_agg(rollout_id::text || ':' || agent_id::text || ':' || state, ','), 'none') FROM pc.policy_rollout_targets"))
		}
	}
	target("ACKNOWLEDGED")
	// Coverage reads only traffic older than a minute (a receipt's
	// transaction may commit late), so wait for the first refunds to age.
	deadline := time.Now().Add(2 * time.Minute)
	for s.row(t, "SELECT count(*)::text FROM pc.transactions WHERE created_at < now() - interval '1 minute'") == "0" {
		if time.Now().After(deadline) {
			t.Fatal("no transaction aged past a minute")
		}
		time.Sleep(2 * time.Second)
	}
	if code, o, e := l.alice.pclaw(t, "coverage", "reassess", s.conn.String(), "--agent", l.agent.String()); code != 0 {
		t.Fatalf("coverage reassess: %d %s %s", code, o, e)
	}
	target("VERIFIED")

	// 6. Complete: v2 is published for every agent.
	if ro, cr, err = l.rollouts.CompleteRollout(l.publisher, ro.ID); err != nil || cr != nil || ro.Stage != "COMPLETE" {
		t.Fatalf("complete the rollout: %+v %+v %v", ro, cr, err)
	}
	if l.published(t) != v2 {
		t.Fatalf("published after completion: %s, want v2 %s", l.published(t), v2)
	}

	// 7. A loosening: v3 drops the hold (and adds an emergency rule). Its
	// publication waits for both publishers' security keys (F1, HR-231).
	aliceKey := signInWithKey(t, s, l.people, "alice", "alice@example.test")
	bobKey := signInWithKey(t, s, l.people, "bob", "bob@example.test")
	v3 := l.create(t, "v3", lifecycleBundle([]string{ruleSeed, ruleCap, ruleEmergency}, cat(seedTests, []string{seedAtAllowed}, capTests, emergencyTests)))
	code, o, e = l.alice.pclaw(t, "policy", "publish", v3)
	m := changeRequestURL.FindStringSubmatch(e)
	if code != 0 || !strings.Contains(e, "waiting for confirmation") || m == nil {
		t.Fatalf("publish the loosening v3: %d %s %s", code, o, e)
	}
	if first, second := l.confirmBoth(t, aliceKey, bobKey, m[1]); first != "PENDING" || second != "APPROVED" {
		t.Fatalf("confirmations of v3: %s then %s", first, second)
	}
	if l.published(t) != v3 {
		t.Fatalf("published after two confirmations: %s, want v3 %s", l.published(t), v3)
	}
	l.refund(t, "33.00", http.StatusOK, "")

	// 8. Roll back to v2: the emergency rule of v3 is carried forward
	// (F206, F207, HR-236); the rollback tightens, so it is published.
	code, o, e = l.alice.pclaw(t, "policy", "rollback", v2)
	if code != 0 || !strings.Contains(e, "emergency rules carried forward from the published version: stop-fraud-refunds") {
		t.Fatalf("roll back to v2: %d %s %s", code, o, e)
	}
	rolled := l.published(t)
	if rolled == v2 || rolled == v3 || s.row(t, `SELECT count(*)::text FROM pc.policy_versions v, jsonb_array_elements(convert_from(v.bundle, 'UTF8')::jsonb->'rules') r
		WHERE v.id = $1 AND r->>'id' IN ('stop-fraud-refunds', 'hold-refunds')`, rolled) != "2" {
		t.Fatalf("the rolled-back version %s lacks the hold or the carried emergency rule", rolled)
	}
	l.refund(t, "34.00", http.StatusForbidden, "REQUIRE_APPROVAL")

	// 9. An exception waives the exceptable hold for the agent, approved
	// like a loosening (F2, F208, HR-235): its refund over 20.00 is allowed,
	// and the receipt names the exception. It expires by the database clock
	// after a minute, and the hold applies again.
	code, o, e = l.alice.pclaw(t, "policy", "exception", "request", "hold-refunds", "--agent", l.agent.String(),
		"--operation", "payments.refund.create", "--reason", "month-end refund backlog", "--expires-in", "1m")
	m = changeRequestURL.FindStringSubmatch(o + e)
	if code != 0 || m == nil {
		t.Fatalf("request an exception: %d %s %s", code, o, e)
	}
	exception := field(t, o, "id")
	if first, second := l.confirmBoth(t, aliceKey, bobKey, m[1]); first != "PENDING" || second != "APPROVED" {
		t.Fatalf("confirmations of the exception: %s then %s", first, second)
	}
	if st := s.row(t, "SELECT state FROM pc.policy_exceptions WHERE id = $1", exception); st != "ACTIVE" {
		t.Fatalf("exception state %s, want ACTIVE", st)
	}
	r = l.refund(t, "35.00", http.StatusOK, "")
	waived := false
	var decision string
	s.query(t, "SELECT receipt_jws FROM pc.decision_receipts WHERE transaction_id = $1 ORDER BY evaluation DESC LIMIT 1", []any{r.TransactionID}, &decision)
	checklist, _ := papClaims(t, decision)["checklist"].([]any)
	for _, it := range checklist {
		item, _ := it.(map[string]any)
		if item["status"] == "WAIVED" && item["code"] == "EXCEPTION_APPLIED" && item["detail"] == exception {
			waived = true
		}
	}
	if !waived {
		t.Fatalf("the decision receipt does not show the exception: %v", checklist)
	}
	deadline = time.Now().Add(3 * time.Minute)
	for s.row(t, "SELECT (expires_at <= now())::text FROM pc.policy_exceptions WHERE id = $1", exception) != "true" {
		if time.Now().After(deadline) {
			t.Fatal("the exception did not expire by the database clock")
		}
		time.Sleep(2 * time.Second)
	}
	l.refund(t, "36.00", http.StatusForbidden, "REQUIRE_APPROVAL")
	if n, err := (&exceptions.Service{Pool: s.pool}).Sweep(ctx, s.org); err != nil || n != 1 {
		t.Fatalf("exception sweep: %d %v", n, err)
	}
	if st := s.row(t, "SELECT state FROM pc.policy_exceptions WHERE id = $1", exception); st != "EXPIRED" {
		t.Fatalf("exception state %s after the sweep, want EXPIRED", st)
	}
}

// finding is one validation finding.
type finding struct {
	Code  string   `json:"code"`
	Rules []string `json:"rules"`
}

// gateReport is what pclaw policy validate and policy test print
// (protojson).
type gateReport struct {
	Validation struct {
		Passed   bool      `json:"passed"`
		Findings []finding `json:"findings"`
	} `json:"validation"`
	Tests struct {
		Passed    bool `json:"passed"`
		Survivors int  `json:"survivors"`
		Surviving []struct {
			Rule     string `json:"rule"`
			Mutation string `json:"mutation"`
		} `json:"surviving"`
	} `json:"tests"`
}

func parseGate(t *testing.T, out string) gateReport {
	t.Helper()
	var r gateReport
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("gate report %q: %v", out, err)
	}
	return r
}
