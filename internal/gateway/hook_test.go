// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/hook"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

const hookPath = "/hook/payments"

// withShell makes the connection a kind-local connection serving the
// pc.shell package (the Claude Code hook).
func withShell(h *harness) {
	h.pkgFile = "../../packages/pc-shell/package.yaml"
	h.conn.Kind, h.conn.GatewayConnection.Package, h.conn.AccessMode = "local", "pc.shell", "none"
}

func shellInput(command, cwd string) string {
	b, _ := json.Marshal(map[string]any{"tool": "shell", "input": map[string]string{
		"shell": "bash", "command": command, "cwd": cwd, "call": "toolu_01",
	}})
	return string(b)
}

type hookReply struct {
	code   int
	hdr    http.Header
	answer hook.Answer
	// raw is the answer as sent.
	raw []byte
}

func (h *harness) hook(t *testing.T, body string, hdr map[string]string) hookReply {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, h.url+hookPath, strings.NewReader(body))
	req.Header.Set("Authorization", "PAP "+testWorkloadToken())
	req.Header.Set(HeaderProof, "proof-not-checked-by-the-gateway")
	req.Header.Set(HeaderRunID, ids.NewV7().String())
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	r := hookReply{code: resp.StatusCode, hdr: resp.Header, raw: b}
	if err := json.Unmarshal(b, &r.answer); err != nil {
		t.Fatalf("answer %d %q: %v", resp.StatusCode, b, err)
	}
	return r
}

// TestHR186_TheHookIsAnsweredAndNeverDispatched: an allowed shell command
// is committed with BeginDispatch (no outbound request) and recorded
// DELEGATED, and the answer is allow; nothing reaches any target. A denial,
// a hold (which says to approve in PantherClaw, not locally), an allow
// with obligations the hook cannot honor, and the kill switch are deny
// with the reason and transaction. In monitor mode the call is recorded,
// not prevented.
func TestHR186_TheHookIsAnsweredAndNeverDispatched(t *testing.T) {
	h := setup(t, withShell)
	r := h.hook(t, shellInput("go test ./...", "/home/dev/proj"), nil)
	s := h.auth.snap()
	if r.code != http.StatusOK || r.answer.Decision != "allow" || r.answer.TransactionID != s.txn || r.answer.Receipt != "receipt-jws" ||
		len(s.begins) != 1 || s.begins[0].GetOutboundMethod() != "" || len(s.begins[0].GetOutboundBodySha256()) != 0 ||
		s.outcome() != pb.Outcome_OUTCOME_DELEGATED || h.target.calls() != 0 {
		t.Fatalf("allowed = %d %+v, begins %+v, outcome %s, target %d", r.code, r.answer, s.begins, s.outcome(), h.target.calls())
	}
	if a := s.actions[0].Action; a.Channel != "hook" || a.Operation != "shell.command.run" || a.Connection != connID {
		t.Fatalf("mapped %+v", a)
	}

	for name, tc := range map[string]struct {
		opt  func(*harness)
		code string
		held bool
	}{
		"denied": {func(h *harness) { h.auth.decision = pb.Decision_DECISION_DENY }, "GRANT_AMOUNT_EXCEEDED", false},
		"held":   {func(h *harness) { h.auth.decision = pb.Decision_DECISION_REQUIRE_APPROVAL }, "GRANT_AMOUNT_EXCEEDED", true},
		"obligations": {func(h *harness) {
			h.auth.obligations = []*pb.Obligation{{Kind: "clamp"}}
		}, "obligation_unsupported", false},
		"kill switch": {func(h *harness) { h.containment.err = control.ErrKillSwitch }, "kill_switch", false},
	} {
		h := setup(t, withShell, tc.opt)
		r := h.hook(t, shellInput("rm -rf build", "/home/dev/proj"), nil)
		s := h.auth.snap()
		if r.answer.Decision != "deny" || r.answer.Code != tc.code || r.answer.Held != tc.held || len(s.records) != 0 ||
			!strings.Contains(r.answer.Reason, "PantherClaw") {
			t.Errorf("%s: %+v, records %d", name, r.answer, len(s.records))
		}
		if tc.held && (!strings.Contains(r.answer.Reason, "not by you") || !strings.Contains(r.answer.Reason, r.answer.TransactionID)) {
			t.Errorf("%s: the hold does not say where to approve: %q", name, r.answer.Reason)
		}
	}

	h = setup(t, withShell, func(h *harness) {
		h.auth.decision, h.auth.mode = pb.Decision_DECISION_DENY, pb.DispatchMode_DISPATCH_MODE_MONITOR
	})
	if r := h.hook(t, shellInput("make", "/home/dev/proj"), nil); r.answer.Decision != "allow" || r.answer.Mode != "monitor" ||
		h.auth.snap().outcome() != pb.Outcome_OUTCOME_DELEGATED {
		t.Fatalf("monitor = %+v", r.answer)
	}
}

// TestHR187_HookPathsAreNormalizedAndTheCommandIsNot: every spelling of a
// directory reaches policy as one path; device paths, alternate data
// streams, trailing dots or spaces, and UNC spellings of this machine's
// disks (loopback servers, administrative shares) are refused before the
// Authority; the command text is kept exactly as sent.
func TestHR187_HookPathsAreNormalizedAndTheCommandIsNot(t *testing.T) {
	const command = "dir   C:\\Users\\dev\\..\\Admin  &&  echo  \"x\""
	for cwd, want := range map[string]string{
		`c:/Users/dev/./proj/../app`: `C:\Users\dev\app`,
		`C:\Users\dev\app\`:          `C:\Users\dev\app`,
		`\\fileserver\share\a\..\b`:  `\\fileserver\share\b`,
		`/home/dev//proj/./x/..`:     `/home/dev/proj`,
	} {
		h := setup(t, withShell)
		if r := h.hook(t, shellInput(command, cwd), nil); r.answer.Decision != "allow" {
			t.Fatalf("%s: %+v", cwd, r.answer)
		}
		var p struct {
			Shell   string `json:"shell"`
			Command string `json:"command"`
			Cwd     string `json:"cwd"`
			Call    string `json:"call"`
		}
		a := h.auth.snap().actions[0].Action
		if err := a.DecodeParams(&p); err != nil || p.Cwd != want || p.Command != command {
			t.Errorf("%s: params %+v %v, want cwd %s", cwd, p, err, want)
		}
	}
	for _, cwd := range []string{
		`\\?\C:\Users\dev`, `\\.\pipe\x`, `C:\Users\dev\file.txt:stream`, `C:\Users\dev.`, `C:\Users\dev \x`, "relative\\dir",
		`\\localhost\C$\Users\dev`, `\\127.0.0.1\c$\Users\dev`, `\\localhost\Users\dev`, `\\0--1.ipv6-literal.net\C$\Users\dev`,
		`\\dev-pc\C$\Users\dev`, `\\?\UNC\localhost\C$\Users\dev`, `\\.\C:\Users\dev`,
	} {
		h := setup(t, withShell)
		r := h.hook(t, shellInput("ls", cwd), nil)
		if r.answer.Decision != "deny" || r.answer.ErrorClass != "cannot_authorize" || h.auth.snap().authorize != 0 {
			t.Errorf("%q: %+v, authorize %d", cwd, r.answer, h.auth.snap().authorize)
		}
	}
	h := setup(t, withShell)
	if r := h.hook(t, shellInput("echo \u202eevil", "/home/dev"), nil); r.answer.Decision != "deny" || h.auth.snap().authorize != 0 {
		t.Errorf("a bidi character in the command: %+v", r.answer)
	}
}

// TestHR186_TheHookEndpointRefusesWhatIsNotAHookCall: an unverified
// workload is 401; no run, another connection kind, a browser Origin, a
// malformed body and a GET are refused without asking the Authority.
func TestHR186_TheHookEndpointRefusesWhatIsNotAHookCall(t *testing.T) {
	h := setup(t, withShell)
	for name, tc := range map[string]struct {
		body string
		hdr  map[string]string
		code int
	}{
		"no run":       {shellInput("ls", "/x"), map[string]string{HeaderRunID: ""}, http.StatusBadRequest},
		"no proof":     {shellInput("ls", "/x"), map[string]string{HeaderProof: ""}, http.StatusUnauthorized},
		"origin":       {shellInput("ls", "/x"), map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
		"not json":     {"{", nil, http.StatusBadRequest},
		"extra member": {`{"tool":"shell","input":{},"x":1}`, nil, http.StatusBadRequest},
	} {
		if r := h.hook(t, tc.body, tc.hdr); r.code != tc.code || r.answer.Decision != "deny" {
			t.Errorf("%s: %d %+v", name, r.code, r.answer)
		}
	}
	if s := h.auth.snap(); s.authorize != 0 {
		t.Fatalf("a refused request reached the Authority %d times", s.authorize)
	}
	h.auth.setIdentity("invalid_proof")
	if r := h.hook(t, shellInput("ls", "/x"), nil); r.code != http.StatusUnauthorized || r.hdr.Get(HeaderError) != "invalid_proof" ||
		r.answer.Decision != "deny" {
		t.Fatalf("unverified: %d %+v", r.code, r.answer)
	}
	payments := setup(t) // a kind-http connection
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, payments.url+hookPath, strings.NewReader(shellInput("ls", "/x")))
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("an http connection's hook: %d", resp.StatusCode)
	}
	req, _ = http.NewRequestWithContext(context.Background(), http.MethodGet, h.url+hookPath, nil)
	if resp, err = client.Do(req); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", resp.StatusCode)
	}
}
