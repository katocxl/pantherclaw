// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"crypto/rand"
	"encoding/json/jsontext"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	simmodel "github.com/katocxl/pantherclaw/internal/sim/model"
)

// m29TaskCap is the exit's task token rule: every allowed call fits.
const m29TaskCap = 5000

// TestE2E_M29_ModelRoute is the M29 exit (G0 M29 D828) on the real server,
// gateway and database, with the fake model in process and its key sealed
// for the gateway. No test spends a token (HR-699).
//
// Covers: F980, F981, F982, F983, F985, F987, F988, HR-690, HR-691, HR-692, HR-693, HR-694, HR-696, HR-698, T-310, T-311, T-312, T-313, T-314, T-316, T-318
func TestE2E_M29_ModelRoute(t *testing.T) {
	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", people: &p, model: true, billing: true})
	people := &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p}
	alice, b, key := approver(t, s, people)
	d := &rangeDriver{t: t, s: s, admin: alice, recs: map[string]*callRec{}}
	d.bindRoles("gateway_admin")
	modelRangeAgent(t, s)
	var agent, inst string
	s.query(t, "SELECT agent_id::text FROM pc.runs WHERE id = $1", []any{s.run}, &agent)
	s.query(t, "SELECT id::text FROM pc.agent_instances WHERE agent_id = $1 AND state = 'ADMITTED' LIMIT 1", []any{agent}, &inst)
	grant := d.issueGrant(agent, modelBounds, modelTokenLimits(m29TaskCap), "")
	run := d.startRun(agent, inst, grant)
	sim := s.model.sim
	call := func(r modelReq) modelAnswer {
		t.Helper()
		if r.run == "" {
			r.run = run
		}
		if r.path == "" {
			r.path = modelPath(r.conn)
		}
		a, err := s.modelCall(r)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	refused := func(step string, a modelAnswer, status int, typ, code string) {
		t.Helper()
		r, err := a.refusal()
		if err != nil || a.code != status || r.Error.Type != typ || r.PantherClaw.DecisiveCode != code ||
			!strings.Contains(r.Error.Message, "PantherClaw: ") {
			t.Fatalf("%s: %d %s (%v)", step, a.code, a.body, err)
		}
	}
	calls := func() int { return sim.Stats().Calls[simmodel.OpMessages] + sim.Stats().Calls[simmodel.OpChat] }

	// (1) A call passes with the gateway's key; the key the agent sent
	// never reaches the model; the usage row has the reported counts and
	// the token reservation settles at them.
	agentKey := "sk-" + "ant-" + "api03-" + rand.Text() + rand.Text()
	body := modelBody("anthropic", simmodel.ModelDefault, 64, false, "")
	a := call(modelReq{conn: "anthropic", body: body, hdr: map[string]string{"X-Api-Key": agentKey}})
	txn := a.hdr.Get("PC-Transaction-Id")
	if a.code != http.StatusOK || !strings.Contains(string(a.body), simmodel.Reply) || txn == "" {
		t.Fatalf("(1) call: %d %s", a.code, a.body)
	}
	if sim.Presented(agentKey) || sim.Stats().LastKey != simmodel.DefaultKey {
		t.Fatalf("(1) the model saw the agent's key (last key %q)", sim.Stats().LastKey)
	}
	in := int64(len(body)+3) / 4
	if outcome, reported, gotIn, gotOut, _ := s.usageRow(t, txn); outcome != "ACCEPTED" || !reported || gotIn != in || gotOut != 8 {
		t.Fatalf("(1) usage row: %s %v %d %d, want %d 8", outcome, reported, gotIn, gotOut, in)
	}
	settled := "COMMITTED " + strconv.FormatInt(in+8, 10)
	waitFor(t, "(1) settle at usage", func() bool { return slices.Contains(s.reservationStates(t, txn), settled) })

	// (2) A streamed answer reaches the agent while the model is still
	// sending it.
	sim.SetFaults(simmodel.Faults{StreamDelayMS: 300})
	resp, err := s.modelOpen(modelReq{conn: "anthropic", path: "/messages", run: run, body: modelBody("anthropic", simmodel.ModelDefault, 64, true, "")})
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("(2) stream: %v %v", err, resp)
	}
	first := make([]byte, 1)
	if _, err := io.ReadFull(resp.Body, first); err != nil {
		t.Fatal(err)
	}
	firstAt := time.Now()
	rest, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || !strings.Contains(string(rest), "message_stop") || time.Since(firstAt) < 600*time.Millisecond {
		t.Fatalf("(2) the stream was not passed on as it came (%v after the first byte): %v %s", time.Since(firstAt), err, rest)
	}
	sim.SetFaults(simmodel.Faults{})

	// (3) A call over the token rule is denied in Anthropic's error shape
	// with the token reason and no budget numbers (HR-400).
	before := calls()
	a = call(modelReq{conn: "anthropic", body: modelBody("anthropic", simmodel.ModelDefault, m29TaskCap+1, false, "")})
	refused("(3) over the cap", a, http.StatusForbidden, "permission_error", "TOKEN_BUDGET_EXHAUSTED")
	if r, _ := a.refusal(); r.Type != "error" || strings.Contains(string(a.body), strconv.Itoa(m29TaskCap)) || calls() != before {
		t.Fatalf("(3) refusal shape or budget numbers: %s (model calls %d)", a.body, calls()-before)
	}

	// (4) A credential in the prompt is held; an approver approves it; the
	// identical request with the same action passes.
	tok := "ghp_" + (rand.Text() + rand.Text())[:36]
	secretBody := strings.Replace(body, "Say hi.", "Push with "+tok+" please.", 1)
	act := ids.NewV7()
	a = call(modelReq{conn: "anthropic", body: secretBody, act: act})
	refused("(4) secret", a, http.StatusForbidden, "permission_error", "SECRET_IN_PAYLOAD")
	if calls() != before {
		t.Fatal("(4) a held prompt reached the model")
	}
	held, _ := a.refusal()
	path := "/approvals/" + s.requestOf(t, held.PantherClaw.TransactionID) + "?org=" + s.org.String()
	if code, page := b.page(t, path); code != http.StatusOK || !strings.Contains(page, "anthropic.messages.create") || strings.Contains(page, tok) {
		t.Fatalf("(4) approval page: %d (it must name the operation and never show the prompt)", code)
	}
	base, _, _ := strings.Cut(path, "?")
	code, opts := b.post(t, base+"/approve-options", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("(4) approve options: %d %v", code, opts)
	}
	assertion, err := key.Assert(opts["options"])
	if err != nil {
		t.Fatal(err)
	}
	if code, res := b.post(t, base+"/approve", map[string]any{"ceremony": opts["ceremony"], "response": jsontext.Value(assertion)}); code != http.StatusOK ||
		string(res["state"]) != `"APPROVED"` {
		t.Fatalf("(4) approve: %d %v", code, res)
	}
	if a = call(modelReq{conn: "anthropic", body: secretBody, act: act}); a.code != http.StatusOK || calls() != before+1 {
		t.Fatalf("(4) the approved retry: %d %s", a.code, a.body)
	}

	// (5) A cut stream is UNKNOWN and its reservation stays HELD (on the
	// openai connection: an UNKNOWN counts toward its circuit).
	a = call(modelReq{conn: "openai", body: modelBody("openai", simmodel.ModelCut, 64, true, `"stream_options":{"include_usage":true}`)})
	txn = a.hdr.Get("PC-Transaction-Id")
	if a.code != http.StatusOK || !a.cut || txn == "" {
		t.Fatalf("(5) cut stream: %d cut %v %s", a.code, a.cut, a.body)
	}
	if outcome, reported, _, _, _ := s.usageRow(t, txn); outcome != "UNKNOWN" || reported {
		t.Fatalf("(5) usage row: %s %v", outcome, reported)
	}
	if st := s.reservationStates(t, txn); len(st) == 0 || slices.ContainsFunc(st, func(x string) bool { return x != "HELD" }) {
		t.Fatalf("(5) reservations %v", st)
	}

	// (6) A provider-side tool the connection does not allow is refused
	// before anything is asked or sent.
	before = calls()
	a = call(modelReq{conn: "anthropic", body: modelBody("anthropic", simmodel.ModelDefault, 64, false, `"tools":[{"type":"web_search_20250305","name":"web_search"}]`)})
	refused("(6) server tool", a, http.StatusForbidden, "permission_error", "MODEL_SERVER_TOOL_NOT_ALLOWED")
	if calls() != before {
		t.Fatal("(6) a refused provider-side tool reached the model")
	}

	// (7) A run started with max_tokens caps its calls below the grant's
	// rule; the same call passes in a run without a cap.
	code, out, errs := alice.pclaw(t, "run", "start", agent, "--instance", inst, "--grant", grant, "--task", "range", "--max-tokens", "100")
	if code != 0 {
		t.Fatalf("(7) run start --max-tokens: %d %s %s", code, out, errs)
	}
	capped := field(t, out, "id")
	if a = call(modelReq{conn: "anthropic", run: capped, body: modelBody("anthropic", simmodel.ModelDefault, 16, false, "")}); a.code != http.StatusOK {
		t.Fatalf("(7) a call within the run cap: %d %s", a.code, a.body)
	}
	over := modelBody("anthropic", simmodel.ModelDefault, 200, false, "")
	refused("(7) over the run cap", call(modelReq{conn: "anthropic", run: capped, body: over}), http.StatusForbidden, "permission_error", "TOKEN_BUDGET_EXHAUSTED")
	if a = call(modelReq{conn: "anthropic", body: over}); a.code != http.StatusOK {
		t.Fatalf("(7) the same call without a run cap: %d %s", a.code, a.body)
	}

	// (8) The monthly token report: refused on Community; on Team, with a
	// price the admin set, an estimate labeled as one.
	m29Edition(t, s, "community")
	if code, out, errs := alice.pclaw(t, "tokens", "report", "--by", "connection", "--json"); code == 0 || !strings.Contains(errs, "EDITION_REQUIRED") {
		t.Fatalf("(8) Community report: %d %s %s", code, out, errs)
	}
	m29Edition(t, s, "team")
	conn := s.model.conns["anthropic"].String()
	rev := s.row(t, "SELECT revision::text FROM pc.connections WHERE id = $1", conn)
	if code, out, errs := alice.pclaw(t, "connection", "update", conn, "--revision", rev,
		"--price-currency", "USD", "--price-input", "3", "--price-output", "15"); code != 0 {
		t.Fatalf("(8) price: %d %s %s", code, out, errs)
	}
	a = call(modelReq{conn: "anthropic", body: body})
	if _, _, _, _, est := s.usageRow(t, a.hdr.Get("PC-Transaction-Id")); a.code != http.StatusOK || !strings.HasSuffix(est, " USD") {
		t.Fatalf("(8) priced call: %d estimate %q", a.code, est)
	}
	code, out, errs = alice.pclaw(t, "tokens", "report", "--by", "connection", "--json")
	if code != 0 || !strings.Contains(out, "USD") || !strings.Contains(out, "Costs are estimates") {
		t.Fatalf("(8) Team report: %d %s %s", code, out, errs)
	}

	// (9) A body that names max_tokens twice is refused as invalid JSON,
	// and the model sees nothing.
	before = calls()
	a = call(modelReq{conn: "anthropic", body: `{"model":"sim-model","max_tokens":8,"max_tokens":900000,"messages":[]}`})
	refused("(9) duplicate member", a, http.StatusBadRequest, "invalid_request_error", "invalid_json")
	if calls() != before {
		t.Fatal("(9) the model saw a refused body")
	}
}

// m29Edition applies a plan of this edition as the billing extension does.
func m29Edition(t *testing.T, s *stack, edition string) {
	t.Helper()
	time.Sleep(10 * time.Millisecond) // each event strictly newer than the last
	if err := hostedPlans(t, s.pool).ApplyPlan(context.Background(), s.org, entitlements.Snapshot{
		PlanID: edition, Edition: edition, Status: entitlements.StatusActive,
		EventID: "evt_m29_" + edition, EventAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
}

// waitFor polls cond for up to 20 seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: timed out", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
