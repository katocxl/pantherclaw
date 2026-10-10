// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

type recordApprovals struct {
	pantherclawv1connect.UnimplementedApprovalServiceHandler
	list    *pantherclawv1.ListApprovalRequestsRequest
	decline *pantherclawv1.DeclineApprovalRequestRequest
	ask     *pantherclawv1.RequestApprovalEvidenceRequest
	batch   *pantherclawv1.DeclineApprovalBatchRequest
}

func (r *recordApprovals) ListApprovalRequests(_ context.Context, req *pantherclawv1.ListApprovalRequestsRequest) (*pantherclawv1.ListApprovalRequestsResponse, error) {
	r.list = req
	return &pantherclawv1.ListApprovalRequestsResponse{}, nil
}

func (r *recordApprovals) DeclineApprovalRequest(_ context.Context, req *pantherclawv1.DeclineApprovalRequestRequest) (*pantherclawv1.DeclineApprovalRequestResponse, error) {
	r.decline = req
	return &pantherclawv1.DeclineApprovalRequestResponse{}, nil
}

func (r *recordApprovals) RequestApprovalEvidence(_ context.Context, req *pantherclawv1.RequestApprovalEvidenceRequest) (*pantherclawv1.RequestApprovalEvidenceResponse, error) {
	r.ask = req
	return &pantherclawv1.RequestApprovalEvidenceResponse{}, nil
}

func (r *recordApprovals) DeclineApprovalBatch(_ context.Context, req *pantherclawv1.DeclineApprovalBatchRequest) (*pantherclawv1.DeclineApprovalBatchResponse, error) {
	r.batch = req
	return &pantherclawv1.DeclineApprovalBatchResponse{}, nil
}

type recordWaitlist struct {
	pantherclawv1connect.UnimplementedWaitlistServiceHandler
	list    *pantherclawv1.ListWaitlistEntriesRequest
	metrics *pantherclawv1.GetWaitlistMetricsRequest
	chain   *pantherclawv1.SetEscalationChainRequest
}

func (r *recordWaitlist) ListWaitlistEntries(_ context.Context, req *pantherclawv1.ListWaitlistEntriesRequest) (*pantherclawv1.ListWaitlistEntriesResponse, error) {
	r.list = req
	return &pantherclawv1.ListWaitlistEntriesResponse{}, nil
}

func (r *recordWaitlist) GetWaitlistMetrics(_ context.Context, req *pantherclawv1.GetWaitlistMetricsRequest) (*pantherclawv1.GetWaitlistMetricsResponse, error) {
	r.metrics = req
	return &pantherclawv1.GetWaitlistMetricsResponse{}, nil
}

func (r *recordWaitlist) SetEscalationChain(_ context.Context, req *pantherclawv1.SetEscalationChainRequest) (*pantherclawv1.SetEscalationChainResponse, error) {
	r.chain = req
	return &pantherclawv1.SetEscalationChainResponse{}, nil
}

func TestM5p2Commands(t *testing.T) {
	ap, wl := &recordApprovals{}, &recordWaitlist{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterApprovalServiceHandler(cs, ap)
	pantherclawv1connect.RegisterWaitlistServiceHandler(cs, wl)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})
	id := ids.NewV7().String()

	if code, _, errs := run(t, env, "approval", "list", "--state", "pending,evidence_requested", "--waiting-for-me"); code != 0 ||
		len(ap.list.GetStates()) != 2 || !ap.list.GetWaitingForMe() {
		t.Fatalf("approval list = %d %q, %v", code, errs, ap.list)
	}
	if code, _, errs := run(t, env, "approval", "decline", id, "--reason", "too_risky", "--alternative", "person_performs", "--note", "call them"); code != 0 ||
		ap.decline.GetReason() != pantherclawv1.DeclineReason_DECLINE_REASON_TOO_RISKY ||
		ap.decline.GetAlternative() != pantherclawv1.SaferAlternative_SAFER_ALTERNATIVE_PERSON_PERFORMS || ap.decline.GetNote() != "call them" {
		t.Fatalf("approval decline = %d %q, %v", code, errs, ap.decline)
	}
	if code, _, errs := run(t, env, "approval", "decline", id, "--reason", "because"); code != 1 || !strings.Contains(errs, "--reason") {
		t.Fatalf("a reason off the list = %d %q", code, errs)
	}
	if code, _, _ := run(t, env, "approval", "request-evidence", id, "--question", "why_needed", "--within", "10m"); code != 0 ||
		ap.ask.GetQuestion() != pantherclawv1.EvidenceQuestion_EVIDENCE_QUESTION_WHY_NEEDED ||
		time.Until(ap.ask.GetEvidenceDeadlineTime().AsTime()) > 10*time.Minute {
		t.Fatalf("approval request-evidence = %d, %v", code, ap.ask)
	}
	a, b := ids.NewV7().String(), ids.NewV7().String()
	if code, _, _ := run(t, env, "approval", "decline-batch", "--ids", a+","+b, "--reason", "not_needed"); code != 0 ||
		len(ap.batch.GetIds()) != 2 || ap.batch.GetReason() != pantherclawv1.DeclineReason_DECLINE_REASON_NOT_NEEDED {
		t.Fatalf("approval decline-batch = %d, %v", code, ap.batch)
	}
	// An API key never approves; approving opens the page for a person.
	if code, _, errs := run(t, env, "approval", "approve", id); code != 1 || !strings.Contains(errs, "never approves") {
		t.Fatalf("approval approve with an API key = %d %q", code, errs)
	}
	if code, _, _ := run(t, env, "waitlist", "list", "--kind", "action_hold", "--priority", "1,2", "--overdue"); code != 0 ||
		len(wl.list.GetKinds()) != 1 || len(wl.list.GetPriorities()) != 2 || !wl.list.GetOverdue() {
		t.Fatalf("waitlist list = %d, %v", code, wl.list)
	}
	if code, _, errs := run(t, env, "waitlist", "list", "--priority", "5"); code != 1 || !strings.Contains(errs, "--priority") {
		t.Fatalf("priority 5 = %d %q", code, errs)
	}
	if code, _, _ := run(t, env, "waitlist", "metrics", "--days", "90", "--kind", "tool_review"); code != 0 ||
		wl.metrics.GetWindowDays() != 90 || wl.metrics.GetKinds()[0] != pantherclawv1.WaitlistKind_WAITLIST_KIND_TOOL_REVIEW {
		t.Fatalf("waitlist metrics = %d, %v", code, wl.metrics)
	}
	steps := filepath.Join(t.TempDir(), "steps.json")
	if err := os.WriteFile(steps, []byte(`{"steps": [{"atPercent": 0, "scope": "ESCALATION_SCOPE_NEAREST"}, {"atPercent": 50, "scope": "ESCALATION_SCOPE_ORG", "notifyOwners": true}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	team := ids.NewV7().String()
	if code, _, errs := run(t, env, "escalation", "set", "--file", steps, "--team", team, "--revision", "2"); code != 0 ||
		len(wl.chain.GetSteps()) != 2 || !wl.chain.GetSteps()[1].GetNotifyOwners() || wl.chain.GetTeamId() != team || wl.chain.GetRevision() != 2 {
		t.Fatalf("escalation set = %d %q, %v", code, errs, wl.chain)
	}
}

func TestApprovalApproveOpensThePage(t *testing.T) {
	dir := t.TempDir()
	env := envOf(map[string]string{"PANTHERCLAW_CONFIG_DIR": dir})
	if err := saveCreds(env, Credentials{Server: "http://127.0.0.1:8080", Org: "o-1", AccessToken: "x", AccessExpiry: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	id := ids.NewV7().String()
	code, out, errs := run(t, env, "approval", "approve", id)
	if code != 0 || !strings.Contains(out, "http://127.0.0.1:8080/approvals/"+id+"?org=o-1") {
		t.Fatalf("approval approve = %d %q %q", code, out, errs)
	}
	if code, _, _ := run(t, env, "approval", "approve", "../account"); code != 2 {
		t.Fatalf("a path for an id = %d", code)
	}
}

type fakeWaits struct {
	pantherclawv1connect.UnimplementedWorkloadServiceHandler
	states []pantherclawv1.WaitState
	calls  []*pantherclawv1.WaitRequest
	auth   string
}

func (f *fakeWaits) Wait(_ context.Context, req *pantherclawv1.WaitRequest) (*pantherclawv1.WaitResponse, error) {
	f.calls = append(f.calls, req)
	st := f.states[0]
	if len(f.states) > 1 {
		f.states = f.states[1:]
	}
	return &pantherclawv1.WaitResponse{Wait: &pantherclawv1.WaitInfo{Handle: req.GetHandle(), State: st, Code: "APPROVAL_DECLINED"}}, nil
}

func TestWorkloadWaitFollowsTheHandle(t *testing.T) {
	f := &fakeWaits{states: []pantherclawv1.WaitState{
		pantherclawv1.WaitState_WAIT_STATE_PENDING, pantherclawv1.WaitState_WAIT_STATE_READY,
	}}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterWorkloadServiceHandler(cs, f)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.auth = r.Header.Get("Authorization")
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	dir := t.TempDir()
	kf, _, err := workloadclient.NewKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	run0 := ids.NewV7().String()
	kf.Server, kf.Identifier, kf.RunID = ts.URL, "pc:org/x/agent/y/inst/z", run0
	keyFile, tokenFile := filepath.Join(dir, "workload.json"), filepath.Join(dir, "workload.token")
	if err := workloadclient.WriteKeyFile(keyFile, kf, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenFile, []byte("wt-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := envOf(map[string]string{})
	handle := ids.NewV7().String()
	code, out, errs := run(t, env, "workload", "wait", handle, "--key-file", keyFile, "--token-file", tokenFile, "--follow", "--timeout", "5")
	if code != 0 || len(f.calls) != 2 || f.calls[0].GetRunId() != run0 || f.calls[0].GetTimeoutSeconds() != 5 ||
		f.calls[1].GetKnownState() != pantherclawv1.WaitState_WAIT_STATE_PENDING || !strings.Contains(out, "WAIT_STATE_READY") ||
		!strings.HasPrefix(f.auth, "PAP ") {
		t.Fatalf("workload wait --follow = %d %q %q, calls %v, auth %q", code, out, errs, f.calls, f.auth)
	}
	f.states, f.calls = []pantherclawv1.WaitState{pantherclawv1.WaitState_WAIT_STATE_DECLINED}, nil
	if code, _, errs := run(t, env, "workload", "wait", handle, "--key-file", keyFile, "--token-file", tokenFile); code != 1 ||
		!strings.Contains(errs, "the hold ended: DECLINED APPROVAL_DECLINED") {
		t.Fatalf("a declined hold = %d %q", code, errs)
	}
}
