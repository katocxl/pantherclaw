// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/redteam/app"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
	simmodel "github.com/katocxl/pantherclaw/internal/sim/model"
)

// The model connections of the end-to-end tests and the range (G0 M29
// D826–D828): the fake model runs in process, dev seed points the model
// connections "anthropic" and "openai" at it, and the simulator's key is
// sealed for the gateway. No test spends a token (HR-699): the only model
// any of them reaches is the simulator.

// modelSim is the fake model and the connections seeded to it.
type modelSim struct {
	sim *simmodel.Server
	// url is the connections' base URL: the simulator's /v1.
	url string
	// conns are the seeded model connections by name.
	conns map[string]ids.UUID
}

func startModelSim(t *testing.T) *modelSim {
	t.Helper()
	m := &modelSim{sim: simmodel.New("", simmodel.Faults{}, pclog.Discard()), conns: map[string]ids.UUID{}}
	srv := httptest.NewServer(m.sim.Handler())
	t.Cleanup(srv.Close)
	m.url = srv.URL + "/v1"
	return m
}

var seededModel = regexp.MustCompile(`seeded model connection ([0-9a-f-]{36}) \(([a-z]+), `)

func (m *modelSim) seeded(t *testing.T, out string) {
	t.Helper()
	for _, g := range seededModel.FindAllStringSubmatch(out, -1) {
		m.conns[g[2]] = mustUUID(t, g[1])
	}
	if m.conns["anthropic"].IsZero() || m.conns["openai"].IsZero() {
		t.Fatalf("dev seed seeded no model connections: %q", out)
	}
}

// sealModel seals the simulator's key for both model connections, as a
// gateway admin does with pclaw seal, and waits for the gateway to have it.
func (s *stack) sealModel(t *testing.T) {
	t.Helper()
	for _, name := range []string{"anthropic", "openai"} {
		s.waitConfig(t, s.sealFor(t, s.model.conns[name], simmodel.DefaultKey))
	}
}

// modelOps are the model operations of both packages, which a model grant
// allows.
const modelOps = `"anthropic.messages.create", "anthropic.messages.count_tokens", "anthropic.models.read",
	"openai.chat.create", "openai.responses.create", "openai.models.read"`

// modelBounds is a grant's bounds for model calls.
const modelBounds = `{"operations": [` + modelOps + `]}`

// modelTokenLimits is a task token rule of limit tokens over the create
// operations (G0 M29 D821).
func modelTokenLimits(limit int) string {
	return fmt.Sprintf(`{"budgets": [{"id": "model_tokens", "grouping": "task",
		"operations": ["anthropic.messages.create", "openai.chat.create", "openai.responses.create"],
		"max_tokens": "%d", "period": "none"}]}`, limit)
}

// modelReq is one request an agent sends to its model through the gateway.
type modelReq struct {
	conn, path, body string
	// run and act are the run and action; empty and zero: the seeded run
	// and a fresh action.
	run string
	act ids.UUID
	// hdr are extra request headers.
	hdr map[string]string
}

// modelOpen sends a model request through the gateway as the seeded
// workload, signed with PAP/1, and returns the open response.
func (s *stack) modelOpen(r modelReq) (*http.Response, error) {
	if r.run == "" {
		r.run = s.run
	}
	if r.act.IsZero() {
		r.act = ids.NewV7()
	}
	method := http.MethodPost
	if r.body == "" {
		method = http.MethodGet
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, s.gateway+"/"+r.conn+"/v1"+r.path, strings.NewReader(r.body))
	if r.body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if r.conn == "anthropic" {
		req.Header.Set("Anthropic-Version", "2023-06-01")
	}
	for k, v := range r.hdr {
		req.Header.Set(k, v)
	}
	req.Header.Set(gateway.HeaderRunID, r.run)
	req.Header.Set(gateway.HeaderActionID, r.act.String())
	client := &http.Client{Timeout: 2 * time.Minute, Transport: &workloadclient.Transport{
		Key: s.key, Token: func() string { return s.token }, Base: http.DefaultTransport,
	}}
	return client.Do(req)
}

// modelAnswer is the gateway's whole answer to a model request; cut is set
// when the answer broke off (the gateway aborted the stream).
type modelAnswer struct {
	code int
	hdr  http.Header
	body []byte
	cut  bool
}

func (s *stack) modelCall(r modelReq) (modelAnswer, error) {
	resp, err := s.modelOpen(r)
	if err != nil {
		return modelAnswer{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	a := modelAnswer{code: resp.StatusCode, hdr: resp.Header, body: b}
	if err != nil {
		if !errors.Is(err, io.ErrUnexpectedEOF) && !strings.Contains(err.Error(), "EOF") && !strings.Contains(err.Error(), "reset") {
			return a, err
		}
		a.cut = true
	}
	return a, nil
}

// modelRefusal is a refusal in either provider's shape (D819) with the
// agent-safe explanation.
type modelRefusal struct {
	Type  string `json:"type"`
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
		Code    string `json:"code"`
	} `json:"error"`
	PantherClaw struct {
		Presentation  string `json:"presentation"`
		DecisiveCode  string `json:"decisive_code"`
		TransactionID string `json:"transaction_id"`
	} `json:"pantherclaw"`
}

func (a modelAnswer) refusal() (modelRefusal, error) {
	var r modelRefusal
	err := json.Unmarshal(a.body, &r, json.RejectUnknownMembers(false))
	return r, err
}

// observe turns a model answer into a range observation: the decision the
// explanation presents, with its decisive code as the reason.
func (a modelAnswer) observe() domain.Observation {
	if a.code < 300 {
		return domain.Observation{Outcome: domain.OutcomeAllow, TransactionID: a.hdr.Get("PC-Transaction-Id"), Detail: fmt.Sprintf("%d", a.code)}
	}
	r, err := a.refusal()
	if err != nil {
		return domain.Observation{Outcome: domain.OutcomeRefused, Code: fmt.Sprintf("http_%d", a.code), Detail: string(capBytes(a.body))}
	}
	code := r.PantherClaw.DecisiveCode
	o := domain.Observation{Reason: code, Reasons: []string{code}, TransactionID: r.PantherClaw.TransactionID, Detail: string(capBytes(a.body))}
	switch r.PantherClaw.Presentation {
	case "deny":
		o.Outcome = domain.OutcomeDeny
	case "hold":
		o.Outcome = domain.OutcomeHold
	default:
		o.Outcome, o.Code = domain.OutcomeRefused, code
	}
	return o
}

// modelBody is a messages request in the connection's API shape.
func modelBody(conn, model string, maxTokens int, stream bool, extra string) string {
	field, msgs := "max_tokens", `"messages":[{"role":"user","content":"Say hi."}]`
	if conn == "openai" {
		field = "max_completion_tokens"
	}
	b := fmt.Sprintf(`{"model":%q,%q:%d,%s`, model, field, maxTokens, msgs)
	if stream {
		b += `,"stream":true`
	}
	if extra != "" {
		b += "," + extra
	}
	return b + "}"
}

// modelPath is the create path of a connection's API.
func modelPath(conn string) string {
	if conn == "openai" {
		return "/chat/completions"
	}
	return "/messages"
}

// reservations returns the states of a transaction's reservations and the
// settled amount of each, as "STATE" or "STATE settled".
func (s *stack) reservationStates(t *testing.T, txn string) []string {
	t.Helper()
	var out []string
	err := s.pool.InTenantTx(context.Background(), s.org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := tx.Query(ctx, "SELECT state || coalesce(' ' || settled_amount::bigint::text, '') FROM pc.reservations WHERE transaction_id = $1 ORDER BY id", txn)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var st string
			if err := rows.Scan(&st); err != nil {
				return err
			}
			out = append(out, st)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// usageRow waits for the model usage row of a transaction (D825) and
// returns its outcome, reported flag and token counts.
func (s *stack) usageRow(t *testing.T, txn string) (outcome string, reported bool, in, out int64, estimate string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		var n int
		s.query(t, "SELECT count(*) FROM pc.model_usage WHERE transaction_id = $1", []any{txn}, &n)
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no model usage row for %s", txn)
		}
		time.Sleep(100 * time.Millisecond)
	}
	s.query(t, `SELECT outcome, reported, input_tokens, output_tokens, coalesce(estimate::text || ' ' || estimate_currency, '')
		FROM pc.model_usage WHERE transaction_id = $1`, []any{txn}, &outcome, &reported, &in, &out, &estimate)
	return outcome, reported, in, out, estimate
}

// The range's model capability (G0 M29 D827): a stack with the fake model
// and the model connections.
const capModel app.Capability = "model"

// modelRangeCap is the token cap of a model scenario's grant: an ordinary
// call fits many times; over_cap asks for more.
const modelRangeCap = 20000

// modelRangeAgent makes the org's agents range agents, so that their runs are
// simulated: the seeded model connections are simulated, and HR-220 lets
// only simulated runs reach them.
func modelRangeAgent(t *testing.T, s *stack) {
	t.Helper()
	s.db.AdminExec(t, "UPDATE pc.agents SET range_agent = true WHERE org_id = $1", s.org)
}

// setupModel gives a model scenario's agent a grant of its own for the
// model operations, with a task token rule (D821).
func (d *rangeDriver) setupModel() {
	if !requires(d.sc, string(capModel)) || requires(d.sc, "sandbox") {
		return
	}
	modelRangeAgent(d.t, d.s)
	d.ownGrant(modelBounds, modelTokenLimits(modelRangeCap))
}

// modelCallStep runs model.call (D827; RT-192..RT-197).
func (d *rangeDriver) modelCallStep(st domain.Step) (domain.Observation, error) {
	var w struct {
		Attack     string `json:"attack"`
		Connection string `json:"connection"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	conn := w.Connection
	if conn == "" {
		conn = "anthropic"
	}
	if d.s.model == nil {
		return domain.Observation{}, errors.New("the stack has no fake model")
	}
	sim := d.s.model.sim
	before := sim.Stats().Requests
	req := modelReq{conn: conn, path: modelPath(conn), run: d.defaultRun}
	// silent attacks must be refused before anything reaches the model.
	silent := true
	switch w.Attack {
	case "call":
		req.body, silent = modelBody(conn, simmodel.ModelDefault, 64, false, ""), false
	case "over_cap":
		req.body = modelBody(conn, simmodel.ModelDefault, modelRangeCap+1, false, "")
	case "secret":
		// The token goes in a message, as an agent pasting a file would.
		req.body = strings.Replace(modelBody(conn, simmodel.ModelDefault, 64, false, ""), "Say hi.", "Use "+d.fix["planted_github_token"]+" to push.", 1)
	case "big_body":
		req.body = `{"model":"` + simmodel.ModelDefault + `","max_tokens":8,"messages":[{"role":"user","content":"` +
			strings.Repeat("a", 16<<20) + `"}]}`
	case "server_tool":
		tool := `"tools":[{"type":"web_search_20250305","name":"web_search"}]`
		if conn == "openai" {
			tool = `"web_search_options":{}`
		}
		req.body = modelBody(conn, simmodel.ModelDefault, 64, false, tool)
	case "duplicate_member":
		req.body = `{"model":"` + simmodel.ModelDefault + `","max_tokens":8,"max_tokens":900000,"messages":[{"role":"user","content":"hi"}]}`
		if conn == "openai" {
			req.body = strings.ReplaceAll(req.body, "max_tokens", "max_completion_tokens")
		}
	case "cut_stream":
		req.body, silent = modelBody(conn, simmodel.ModelCut, 64, true, ""), false
	default:
		return domain.Observation{}, fmt.Errorf("unknown model.call attack %q", w.Attack)
	}
	a, err := d.s.modelCall(req)
	if err != nil {
		return domain.Observation{}, err
	}
	obs := a.observe()
	if silent && sim.Stats().Requests != before {
		// Whatever the gateway answered, the model saw the request.
		return domain.Observation{Outcome: domain.OutcomeAllow, Detail: "the model received a request the gateway should have stopped: " + obs.Detail}, nil
	}
	if w.Attack == "cut_stream" {
		return d.cutObservation(a, obs)
	}
	return obs, nil
}

// cutObservation is what a cut stream left (HR-692, HR-693): UNKNOWN when
// the answer broke off, the outcome is recorded UNKNOWN and every
// reservation of the call is still HELD.
func (d *rangeDriver) cutObservation(a modelAnswer, obs domain.Observation) (domain.Observation, error) {
	txn := a.hdr.Get("PC-Transaction-Id")
	if a.code >= 300 || txn == "" {
		return obs, nil
	}
	if !a.cut {
		return domain.Observation{Outcome: domain.OutcomeAllow, TransactionID: txn, Detail: "the cut stream reached the agent as whole"}, nil
	}
	outcome, reported, _, _, _ := d.s.usageRow(d.t, txn)
	states := d.s.reservationStates(d.t, txn)
	detail := fmt.Sprintf("outcome %s reported %v reservations %v", outcome, reported, states)
	if outcome != "UNKNOWN" || len(states) == 0 {
		return domain.Observation{Outcome: domain.OutcomeAllow, TransactionID: txn, Detail: detail}, nil
	}
	for _, st := range states {
		if st != "HELD" {
			return domain.Observation{Outcome: domain.OutcomeAllow, TransactionID: txn, Detail: detail}, nil
		}
	}
	return domain.Observation{Outcome: domain.OutcomeUnknown, TransactionID: txn, Detail: detail}, nil
}
