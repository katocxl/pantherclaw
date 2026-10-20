// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	wire "github.com/katocxl/pantherclaw/internal/a2a"
	"github.com/katocxl/pantherclaw/internal/gateway"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/redteam/app"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
	a2asim "github.com/katocxl/pantherclaw/internal/sim/a2a"
)

// The range driver's A2A part (G0 M14 D33, D46): RT-049..051 run on a stack
// with the A2A simulator as the peer agent and the seeded connection
// "peer" (options.a2a).

// a2aCapabilities are the A2A capabilities this driver offers.
func a2aCapabilities() map[app.Capability]bool {
	return map[app.Capability]bool{"a2a.send": true, "a2a.card_swap": true}
}

// needsA2A reports whether a scenario runs with the peer agent.
func needsA2A(sc domain.Scenario) bool {
	return requires(sc, "a2a.send") || requires(sc, "a2a.card_swap")
}

// callA2A sends a JSON-RPC A2A call through the gateway's A2A face: the
// step's tool is the method and its args the params.
func (d *rangeDriver) callA2A(conn string, w callWith, act ids.UUID) (domain.Observation, *callRec, error) {
	params := w.Args
	if len(params) == 0 {
		params = jsontext.Value("{}")
	}
	b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": w.Tool, "params": params})
	if err != nil {
		return domain.Observation{}, nil, err
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, d.s.gateway+"/a2a/"+conn, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(wire.HeaderVersion, wire.Version)
	req.Header.Set(gateway.HeaderRunID, d.runHeader())
	req.Header.Set(gateway.HeaderActionID, act.String())
	resp, err := d.client(w.Instance).Do(req)
	if err != nil {
		return domain.Observation{}, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	obs := observeA2A(resp.StatusCode, raw)
	return obs, &callRec{act: act, txn: obs.TransactionID, obs: obs}, nil
}

// observeA2A reads the face's JSON-RPC answer: a result is ALLOW; an error
// with PantherClaw's facts is classified like every face's; a refusal of
// the face itself (an A2A_* reason) is REFUSED with that reason as code.
func observeA2A(status int, raw []byte) domain.Observation {
	var out struct {
		Result jsontext.Value `json:"result"`
		Error  *struct {
			Data map[string]jsontext.Value `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return domain.Observation{Outcome: domain.OutcomeRefused, Code: fmt.Sprintf("http_%d", status), Detail: string(capBytes(raw))}
	}
	if out.Error == nil {
		return domain.Observation{Outcome: domain.OutcomeAllow, Response: capBytes(out.Result)}
	}
	str := func(n string) string {
		var s string
		_ = json.Unmarshal(out.Error.Data[n], &s)
		return s
	}
	if reason := str("reason"); strings.HasPrefix(reason, "A2A_") || reason == "PUSH_NOT_SUPPORTED" {
		return domain.Observation{Outcome: domain.OutcomeRefused, Code: reason, Detail: string(capBytes(raw))}
	}
	var f facts
	f.ErrorClass, f.Error, f.Decision, f.Outcome, f.TransactionID = str("error_class"), str("error"), str("decision"), str("outcome"), str("transaction_id")
	_ = json.Unmarshal(out.Error.Data["reasons"], &f.Reasons)
	return classify(f, string(capBytes(raw)))
}

// mutateA2A changes the peer agent (change "fault"):
//   - card: swap — the peer serves another card (RT-050); the gateway
//     reads it again and the step returns once the gateway refuses it;
//   - act: refund, amount — the peer acts on the message it was sent, in
//     the run delegated to it: it refunds amount through the payments
//     connection, and the step observes that refund (RT-049).
//   - other_run: get_task, task — another run of the requester's agent,
//     a child run delegated a2a.task.read (a valid grant, so only the
//     face's ownership check can refuse it), reads task (RT-051).
func (d *rangeDriver) mutateA2A(change string, args jsontext.Value) (domain.Observation, error) {
	var a struct {
		Card     string `json:"card"`
		Act      string `json:"act"`
		Amount   string `json:"amount"`
		OtherRun string `json:"other_run"`
		Task     string `json:"task"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return domain.Observation{}, err
	}
	switch {
	case change == "fault" && a.Card == "swap":
		d.s.a2a.sim.SetFaults(a2asim.Faults{Description: "now also moves money (RT-050)"})
		d.reloadGateway()
		for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
			obs, _, err := d.callA2A("peer", callWith{Tool: wire.MethodGetTask, Args: jsontext.Value(`{"id":"task-0"}`)}, ids.NewV7())
			if err == nil && obs.Code == "A2A_CARD_DRIFT" {
				return domain.Observation{}, nil
			}
		}
		return domain.Observation{}, fmt.Errorf("the gateway never refused the swapped card")
	case change == "fault" && a.Act == "refund":
		rec := d.s.a2a.sim.Received()
		if len(rec) == 0 || rec[len(rec)-1].PeerRun == "" {
			return domain.Observation{}, fmt.Errorf("the peer has no delegated run: %+v", rec)
		}
		code, r := d.s.peerRefund(d.t, rec[len(rec)-1].PeerRun, a.Amount)
		if code < 300 {
			return domain.Observation{Outcome: domain.OutcomeAllow}, nil
		}
		return classify(facts{ErrorClass: r.ErrorClass, Error: r.Error, Decision: r.Decision, Reasons: r.Reasons, TransactionID: r.TransactionID}, ""), nil
	case change == "fault" && a.OtherRun == "get_task":
		run, err := d.readerRun()
		if err != nil {
			return domain.Observation{}, err
		}
		params, _ := json.Marshal(map[string]string{"id": a.Task})
		obs, _, err := d.callOnce(callWith{Face: "a2a", Connection: "peer", Tool: wire.MethodGetTask, Args: params, run: run}, nil, 0)
		return obs, err
	}
	return domain.Observation{}, fmt.Errorf("sim.mutate a2a %s %s", change, args)
}

// readerRun starts a child run of the seeded run and delegates it a grant
// over a2a.task.read alone, within the seeded grant, and returns the run.
func (d *rangeDriver) readerRun() (string, error) {
	ctx := context.Background()
	var agent string
	d.s.query(d.t, "SELECT agent_id::text FROM pc.runs WHERE id = $1", []any{d.s.run}, &agent)
	wc := d.workloadService()
	child, err := wc.StartChildRun(ctx, &pantherclawv1.StartChildRunRequest{ParentRunId: d.s.run, AgentId: agent})
	if err != nil {
		return "", fmt.Errorf("StartChildRun: %w", err)
	}
	run := child.GetRun().GetId()
	if _, err := wc.DelegateGrant(ctx, &pantherclawv1.DelegateGrantRequest{
		RunId: d.s.run, ChildRunId: run, Bounds: []byte(`{"operations": ["a2a.task.read"]}`),
	}); err != nil {
		return "", fmt.Errorf("DelegateGrant: %w", err)
	}
	return run, nil
}
