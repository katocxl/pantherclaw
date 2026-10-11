// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway"
	"github.com/katocxl/pantherclaw/internal/gateway/sdk"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestE2E_M8_SDKFace: an agent SDK asks the gateway's /sdk face before it
// runs a tool itself (HR-201, HR-200). The gateway maps the raw Bash call
// through pc.shell into an sdk-channel action on the "shell" connection;
// an allowed command is recorded delegated, with a PARTIAL effect receipt.
// A command the org's policy holds answers hold with the wait handle, which
// the workload long-polls; once bob approves it, the identical call with
// the same action id is allowed and consumes the approval. A forbidden
// command is denied with the policy's reason, and an unmapped built-in
// tool is allowed OBSERVE_ONLY without a decision.
func TestE2E_M8_SDKFace(t *testing.T) {
	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", people: &p, shell: true})
	_, b, key := approver(t, s, &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p})
	dir := t.TempDir()
	bash := func(id, command string) string {
		body, _ := json.Marshal(map[string]any{
			"tool": "Bash", "input": map[string]any{"command": command, "description": "e2e"}, "tool_use_id": id, "cwd": dir,
		})
		return string(body)
	}

	a := s.sdk(t, "", bash("toolu_m8a", "ls -la"))
	if a.Decision != "allow" || a.Coverage != sdk.CoveragePartial || a.ActionID == "" || len(a.ActionHash) != 64 || a.TransactionID == "" {
		t.Fatalf("allowed command: %+v", a)
	}
	if got := s.row(t, `SELECT t.channel || ' ' || x.outcome || ' ' || x.access_mode FROM pc.execution_attempts x
		JOIN pc.transactions t ON t.org_id = x.org_id AND t.id = x.transaction_id WHERE x.transaction_id = $1`, a.TransactionID); got != "sdk delegated agent_held" {
		t.Fatalf("recorded %q", got)
	}
	if r := s.row(t, "SELECT receipt_jws FROM pc.effect_receipts WHERE transaction_id = $1", a.TransactionID); papClaims(t, r)["coverage"] != "PARTIAL" {
		t.Fatalf("the delegated command's effect receipt %q", r)
	}

	s.publishPolicy(t, `{"id": "sdk", "rules": [
		{"id": "no-rm", "kind": "FORBID", "summary": "destructive commands", "operations": ["shell.command.run"],
		 "when": "action.params.command.startsWith(\"rm \")", "reason": "SHELL_DESTRUCTIVE"},
		{"id": "push-review", "kind": "REQUIRE_APPROVAL", "summary": "pushes need an approver", "operations": ["shell.command.run"],
		 "when": "action.params.command.startsWith(\"git push\")", "reason": "PUSH_NEEDS_APPROVAL", "approval": {"role": "approver", "count": 1}}]}`)
	if a := s.sdk(t, "", bash("toolu_m8b", "rm -rf build")); a.Decision != "deny" || a.Code != "SHELL_DESTRUCTIVE" {
		t.Fatalf("forbidden command: %+v", a)
	}

	push := bash("toolu_m8c", "git push origin main")
	held := s.sdk(t, "", push)
	if held.Decision != "hold" || held.ErrorClass != "held" || held.Wait == nil || held.Wait.Handle != held.TransactionID ||
		held.Wait.State != "PENDING" || held.Wait.ApprovalRequestID == "" {
		t.Fatalf("held command: %+v wait %+v", held, held.Wait)
	}
	if w := s.waitState(t, held.Wait.Handle, pantherclawv1.WaitState_WAIT_STATE_UNSPECIFIED); w.GetState() != pantherclawv1.WaitState_WAIT_STATE_PENDING {
		t.Fatalf("waiting: %s", w.GetState())
	}
	page := "/approvals/" + held.Wait.ApprovalRequestID + "?org=" + s.org.String()
	if st := approveOperationOnPage(t, b, key, page, "shell.command.run"); st != `"APPROVED"` {
		t.Fatalf("approval state %s", st)
	}
	if w := s.waitState(t, held.Wait.Handle, pantherclawv1.WaitState_WAIT_STATE_PENDING); w.GetState() != pantherclawv1.WaitState_WAIT_STATE_READY {
		t.Fatalf("after the approval: %s", w.GetState())
	}
	done := s.sdk(t, held.ActionID, push)
	if done.Decision != "allow" || done.TransactionID != held.TransactionID || done.ActionHash != held.ActionHash {
		t.Fatalf("resubmitted command: %+v", done)
	}
	if st := s.requestState(t, held.TransactionID); st != "CONSUMED" {
		t.Fatalf("approval %s", st)
	}

	observed := s.sdk(t, "", `{"tool":"Read","input":{"file_path":"/etc/hosts"},"tool_use_id":"toolu_m8d"}`)
	if observed.Decision != "allow" || observed.Coverage != sdk.CoverageObserveOnly || observed.TransactionID != "" {
		t.Fatalf("unmapped tool: %+v", observed)
	}
}

// sdk sends one PAP/1-signed call to the shell connection's SDK face as the
// seeded workload, in its run, with the action id when one is given.
func (s *stack) sdk(t *testing.T, action, body string) sdk.Answer {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, s.gateway+"/sdk/shell", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(gateway.HeaderRunID, s.run)
	if action != "" {
		if _, err := ids.ParseUUID(action); err != nil {
			t.Fatal(err)
		}
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
