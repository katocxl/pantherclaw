// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/gateway"
	"github.com/katocxl/pantherclaw/internal/gateway/sdk"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
)

// TestE2E_M8_SDKFace: an agent SDK asks the gateway's /sdk face before it
// calls the payments MCP server's create_refund itself (HR-201, HR-200).
// The payments target checks action tokens, so the gateway answers an
// allowed refund with the request it re-serialized from the action it
// mapped and the token that binds its body. The gateway sends nothing and
// records the call delegated. The target accepts that request once, and
// refuses it replayed or with its body changed by one byte (HR-188). A
// refund the org's policy holds answers hold with the wait handle; once
// bob approves it, the identical call with the same action id is allowed
// and its request accepted. A built-in tool is allowed OBSERVE_ONLY
// without a decision.
func TestE2E_M8_SDKFace(t *testing.T) {
	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", people: &p, access: capp.AccessTargetEnforced, actionTokens: true})
	_, b, key := approver(t, s, &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p})
	refund := func(amount string) string {
		body, _ := json.Marshal(map[string]any{
			"tool": "mcp__payments__create_refund", "server": "payments", "tool_use_id": "toolu_" + strings.ReplaceAll(amount, ".", ""),
			"input": map[string]string{"charge": "ch_1", "amount": amount, "currency": "USD", "reason": "duplicate"},
		})
		return string(body)
	}

	a := s.sdk(t, "", refund("30.00"))
	if a.Decision != "allow" || a.Coverage != sdk.CoveragePartial || a.Dispatch == nil || len(a.ActionHash) != 64 || s.sim.Stats().Refunds != 0 {
		t.Fatalf("allowed refund: %+v, target %+v", a, s.sim.Stats())
	}
	if got := s.row(t, `SELECT t.channel || ' ' || x.outcome FROM pc.execution_attempts x
		JOIN pc.transactions t ON t.org_id = x.org_id AND t.id = x.transaction_id WHERE x.transaction_id = $1`, a.TransactionID); got != "sdk delegated" {
		t.Fatalf("recorded %q", got)
	}
	if code := s.send(t, a.Dispatch, nil); code != http.StatusOK || s.sim.Stats().Refunds != 1 {
		t.Fatalf("the dispatched request: %d, target %+v", code, s.sim.Stats())
	}
	if code := s.send(t, a.Dispatch, nil); code < 400 || s.sim.Stats().Refunds != 1 {
		t.Fatalf("the request replayed: %d, target %+v", code, s.sim.Stats())
	}
	again := s.sdk(t, "", refund("31.00"))
	if code := s.send(t, again.Dispatch, func(b []byte) []byte { return bytes.Replace(b, []byte("31.00"), []byte("91.00"), 1) }); code < 400 ||
		s.sim.Stats().Refunds != 1 {
		t.Fatalf("the body changed: %d, target %+v", code, s.sim.Stats())
	}

	held := s.sdk(t, "", refund("85.00"))
	if held.Decision != "hold" || held.Dispatch != nil || held.Wait == nil || held.Wait.Handle != held.TransactionID || held.Wait.State != "PENDING" {
		t.Fatalf("held refund: %+v wait %+v", held, held.Wait)
	}
	s.approve(t, b, key, held.TransactionID)
	if w := s.waitState(t, held.Wait.Handle, pantherclawv1.WaitState_WAIT_STATE_PENDING); w.GetState() != pantherclawv1.WaitState_WAIT_STATE_READY {
		t.Fatalf("after the approval: %s", w.GetState())
	}
	done := s.sdk(t, held.ActionID, refund("85.00"))
	if done.Decision != "allow" || done.TransactionID != held.TransactionID || done.ActionHash != held.ActionHash || done.Dispatch == nil {
		t.Fatalf("resubmitted refund: %+v", done)
	}
	if code := s.send(t, done.Dispatch, nil); code != http.StatusOK || s.sim.Stats().Refunds != 2 {
		t.Fatalf("the approved request: %d, target %+v", code, s.sim.Stats())
	}
	if st := s.requestState(t, held.TransactionID); st != "CONSUMED" {
		t.Fatalf("approval %s", st)
	}

	observed := s.sdk(t, "", `{"tool":"Read","input":{"file_path":"/etc/hosts"},"tool_use_id":"toolu_read"}`)
	if observed.Decision != "allow" || observed.Coverage != sdk.CoverageObserveOnly || observed.TransactionID != "" {
		t.Fatalf("built-in tool: %+v", observed)
	}
}

// sdk sends one PAP/1-signed call to the payments connection's SDK face as
// the seeded workload, in its run, with the action id when one is given.
func (s *stack) sdk(t *testing.T, action, body string) sdk.Answer {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, s.gateway+"/sdk/payments", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(gateway.HeaderRunID, s.run)
	if action != "" {
		req.Header.Set(gateway.HeaderActionID, action)
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &workloadclient.Transport{
		Key: s.key, Token: func() string { return s.token }, Base: http.DefaultTransport,
	}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var a sdk.Answer
	if err := json.Unmarshal(raw, &a); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("SDK face: %d %s %v", resp.StatusCode, raw, err)
	}
	return a
}

// send sends a dispatch request to the target as an SDK does, its body
// changed by edit when one is given, and returns the status.
func (s *stack) send(t *testing.T, d *sdk.Dispatch, edit func([]byte) []byte) int {
	t.Helper()
	if d == nil {
		t.Fatal("no dispatch request")
	}
	body, err := base64.RawURLEncoding.DecodeString(d.Body)
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		body = edit(body)
	}
	req, _ := http.NewRequestWithContext(context.Background(), d.Method, d.URL, bytes.NewReader(body))
	for k, v := range d.Headers {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}
