// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gitlab

import (
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

const (
	token = "glpat-" + "simulated-test-token-0000"
	head  = "1111111111111111111111111111111111111111"
	moved = "2222222222222222222222222222222222222222"
)

func start(t *testing.T) (*Server, string) {
	t.Helper()
	s := New([]Project{{
		ID: 42, Path: "acme/payments", DefaultBranch: "main", PipelineMustSucceed: true,
		Protected: map[string]Protection{"main": {}},
	}},
		[]MergeRequest{{Project: 42, IID: 7, Title: "Fix", Source: "fix", Target: "main", SHA: head, Author: "dev", ApprovalsRequired: 1, Pipeline: 900}},
		[]Pipeline{{ID: 900, Project: 42, Ref: "fix", SHA: head, Status: PipelineSuccess, Source: "push"}},
		Faults{}, pclog.Discard()).WithRequire(Require{Token: token})
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return s, srv.URL
}

func call(t *testing.T, method, url, tok, body string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.Header.Get("Simulated") != "true" {
		t.Fatal("not marked simulated")
	}
	b, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return resp.StatusCode, out
}

func TestGitLabSimAnswersAsGitLabDoes(t *testing.T) {
	s, url := start(t)
	mr := url + "/api/v4/projects/42/merge_requests/7"
	if code, _ := call(t, "GET", mr, "", ""); code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", code)
	}
	if code, _ := call(t, "GET", mr, "glpat-"+"another-token-000000000", ""); code != http.StatusUnauthorized {
		t.Fatalf("other token: %d", code)
	}
	code, got := call(t, "GET", mr, token, "")
	if code != http.StatusOK || got["sha"] != head || got["head_pipeline"].(map[string]any)["status"] != PipelineSuccess {
		t.Fatalf("merge request: %d %v", code, got)
	}
	if code, _ := call(t, "GET", url+"/api/v4/projects/42/protected_branches/main", token, ""); code != http.StatusOK {
		t.Fatalf("protected: %d", code)
	}
	if code, _ := call(t, "GET", url+"/api/v4/projects/42/protected_branches/dev", token, ""); code != http.StatusNotFound {
		t.Fatalf("unprotected: %d", code)
	}
	if code, _ := call(t, "PUT", mr+"/merge", token, `{"sha":"`+head+`"}`); code != http.StatusMethodNotAllowed {
		t.Fatalf("unapproved merge: %d", code)
	}
	s.Approve(42, 7, "reviewer")
	if code, a := call(t, "GET", mr+"/approvals", token, ""); code != http.StatusOK || a["approved"] != true {
		t.Fatalf("approvals: %d %v", code, a)
	}
	if code, _ := call(t, "PUT", mr+"/merge", token, `{"sha":"`+moved+`"}`); code != http.StatusConflict {
		t.Fatalf("other head: %d", code)
	}
	s.Push(42, 7, moved)
	s.Approve(42, 7, "reviewer")
	if code, _ := call(t, "PUT", mr+"/merge", token, `{"sha":"`+moved+`"}`); code != http.StatusMethodNotAllowed {
		t.Fatalf("running pipeline: %d", code)
	}
	m, _ := s.MergeRequest(42, 7)
	s.SetPipeline(m.Pipeline, PipelineSuccess)
	if code, out := call(t, "PUT", mr+"/merge", token, `{"sha":"`+moved+`"}`); code != http.StatusOK || out["state"] != "merged" {
		t.Fatalf("merge: %d %v", code, out)
	}
	if code, _ := call(t, "PUT", mr+"/merge", token, `{"sha":"`+moved+`"}`); code != http.StatusMethodNotAllowed {
		t.Fatalf("second merge: %d", code)
	}
	s.SetFaults(Faults{NotFound: true})
	if code, _ := call(t, "GET", mr, token, ""); code != http.StatusNotFound {
		t.Fatalf("not found: %d", code)
	}
	s.SetFaults(Faults{RateLimit: 1})
	if code, _ := call(t, "GET", mr, token, ""); code != http.StatusTooManyRequests {
		t.Fatalf("rate limit: %d", code)
	}
}
