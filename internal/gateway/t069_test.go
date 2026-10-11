// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/pclaw"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
)

// claudeCode runs `pclaw hook claude-code` for a Bash command, as the
// Claude Code plugin does, against the harness's real hook endpoint
// (connection "payments", made kind-local by withShell). It returns the
// exit code, stdout (what Claude Code reads as the decision) and stderr.
func (h *harness) claudeCode(t *testing.T, command string) (int, string, string) {
	t.Helper()
	dir := t.TempDir()
	kf, _, err := workloadclient.NewKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	kf.Identifier, kf.Server, kf.RunID = "pc:org/"+testOrg+"/agent/"+ids.NewV7().String()+"/inst/"+testAgent, "https://pc.example.test", ids.NewV7().String()
	keyFile, tokenFile := filepath.Join(dir, "key.json"), filepath.Join(dir, "token")
	if err := workloadclient.WriteKeyFile(keyFile, kf, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenFile, []byte(testWorkloadToken()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	event, _ := json.Marshal(map[string]any{
		"session_id": "t069", "hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": dir, "tool_use_id": "toolu_" + strings.ReplaceAll(ids.NewV7().String(), "-", ""),
		"tool_input": map[string]any{"command": command, "description": "t069"},
	})
	env := map[string]string{"PANTHERCLAW_GATEWAY": h.url, "PANTHERCLAW_HOOK_CONNECTION": "payments", "PANTHERCLAW_WORKLOAD_KEY_FILE": keyFile}
	var out, errb bytes.Buffer
	code := pclaw.Run(context.Background(), []string{"hook", "claude-code", "--token-file", tokenFile}, &out, &errb,
		func(k string) (string, bool) { v, ok := env[k]; return v, ok }, pclaw.Options{Stdin: bytes.NewReader(event)})
	return code, out.String(), errb.String()
}

// unrecorded is the Authority with a ledger that cannot take the record:
// it decides and commits, but RecordExecution fails.
type unrecorded struct{ *fakeAuthority }

func (unrecorded) RecordExecution(context.Context, *pb.RecordExecutionRequest) (*pb.RecordExecutionResponse, error) {
	return nil, connect.NewError(connect.CodeUnavailable, "the ledger is unavailable")
}

// withUnrecorded makes the gateway call the Authority through unrecorded.
func withUnrecorded(t *testing.T) func(*harness) {
	return func(h *harness) {
		s, err := rpc.NewServer(rpc.Options{Logger: pclog.Discard(), Authenticate: func(ctx context.Context, _ *connect.CallInfo, _ connect.Spec) (context.Context, error) {
			return ctx, nil
		}})
		if err != nil {
			t.Fatal(err)
		}
		pantherclawv1connect.RegisterAuthorityServiceHandler(s, unrecorded{h.auth})
		mux := http.NewServeMux()
		rpc.Mount(mux, s)
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		h.authorityURL = srv.URL
	}
}

// TestT069_TheHookAllowsOnlyWhatTheGatewayRecordedAsDelegated: Claude
// Code's hook (pclaw hook claude-code) asks the real hook endpoint about
// a command (T-069). An allow comes only for a command the gateway
// committed with BeginDispatch and recorded as DELEGATED, so a hook allow
// is a cooperative decision on the record, never enforcement, and nothing
// reaches a target. When the commit is refused (containment moved between
// the decision and the commit), the record cannot be written, or the
// Authority cannot be reached, the command is blocked (exit 2, no
// decision on stdout): the hook never fails open. In monitor mode the
// command runs, and the developer is told it was recorded, not decided.
func TestT069_TheHookAllowsOnlyWhatTheGatewayRecordedAsDelegated(t *testing.T) {
	h := setup(t, withShell)
	code, out, errs := h.claudeCode(t, "go test ./...")
	s := h.auth.snap()
	if code != 0 || !strings.Contains(out, `"permissionDecision":"allow"`) || len(s.begins) != 1 || s.begins[0].GetOutboundMethod() != "" ||
		s.outcome() != pb.Outcome_OUTCOME_DELEGATED || h.target.calls() != 0 {
		t.Fatalf("allowed: %d %q %q, begins %v, outcome %s, target %d", code, out, errs, s.begins, s.outcome(), h.target.calls())
	}

	for name, opt := range map[string]func(*harness){
		"commit refused": func(h *harness) {
			h.auth.beginErr = connect.NewError(connect.CodeFailedPrecondition, "the containment epoch moved")
		},
		"record failed":       withUnrecorded(t),
		"authority unreached": func(h *harness) { h.authorityURL = deadURL(t) },
	} {
		h := setup(t, withShell, opt)
		code, out, errs := h.claudeCode(t, "go test ./...")
		if code != 2 || out != "" || !strings.Contains(errs, "PantherClaw") || strings.Contains(errs, "allowed") {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", name, code, out, errs)
		}
	}

	h = setup(t, withShell, func(h *harness) {
		h.auth.decision, h.auth.mode = pb.Decision_DECISION_DENY, pb.DispatchMode_DISPATCH_MODE_MONITOR
	})
	code, out, errs = h.claudeCode(t, "rm -rf build")
	if code != 0 || !strings.Contains(out, "recorded, not decided") || h.auth.snap().outcome() != pb.Outcome_OUTCOME_DELEGATED {
		t.Fatalf("monitor mode: %d %q %q", code, out, errs)
	}
}

// TestT069_AHoldIsNeverTurnedIntoALocalAsk: a command that needs an
// approval or a step-up is blocked by the hook with no decision for Claude
// Code to turn into a question for the developer, and the reason says it
// is approved in PantherClaw by someone else, naming the transaction
// (T-069). Nothing is committed or recorded while it waits. Once approved
// there, the command asked again is allowed.
func TestT069_AHoldIsNeverTurnedIntoALocalAsk(t *testing.T) {
	for _, d := range []pb.Decision{pb.Decision_DECISION_REQUIRE_APPROVAL, pb.Decision_DECISION_REQUIRE_STEP_UP} {
		h := setup(t, withShell, func(h *harness) { h.auth.decision = d })
		code, out, errs := h.claudeCode(t, "terraform apply")
		s := h.auth.snap()
		if code != 2 || out != "" || strings.Contains(errs, `"ask"`) || !strings.Contains(errs, "not by you") || !strings.Contains(errs, s.txn) ||
			len(s.begins) != 0 || len(s.records) != 0 {
			t.Errorf("%s: exit %d, stdout %q, stderr %q, begins %d, records %d", d, code, out, errs, len(s.begins), len(s.records))
		}
		h.auth.decide(pb.Decision_DECISION_ALLOW)
		if code, out, errs := h.claudeCode(t, "terraform apply"); code != 0 || !strings.Contains(out, `"permissionDecision":"allow"`) {
			t.Errorf("%s, approved: exit %d, stdout %q, stderr %q", d, code, out, errs)
		}
	}
}
