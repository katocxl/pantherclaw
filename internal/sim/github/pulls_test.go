// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package github

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net/http"
	"strings"
	"testing"
)

// TestMergeIsGuardedByTheHeadSHA: GitHub answers 409 when the sha is not
// the head, so a merge approved at one commit cannot merge another; a
// merged, draft or unmergeable pull request answers 405.
func TestMergeIsGuardedByTheHeadSHA(t *testing.T) {
	w := newWorld(t)
	_, tok := w.mint(`{"repositories":["payments"],"permissions":{"contents":"write","pull_requests":"write"}}`)
	auth := "Bearer " + tok
	status, pr := w.do("POST", "/repos/acme/payments/pulls", auth, `{"title":"Fix","head":"fix/a","base":"main"}`)
	if status != http.StatusCreated || pr["number"] != float64(1) {
		t.Fatalf("open: %d %v", status, pr)
	}
	approved := w.head
	newer := w.sim.Push("acme/payments", "fix/a", map[string]string{"parser.go": "package parser // v2\n"})
	if status, _ := w.do("PUT", "/repos/acme/payments/pulls/1/merge", auth, `{"sha":"`+approved+`"}`); status != http.StatusConflict {
		t.Fatalf("stale head: %d", status)
	}
	w.sim.SetMergeable("acme/payments", 1, false)
	if status, _ := w.do("PUT", "/repos/acme/payments/pulls/1/merge", auth, `{"sha":"`+newer+`"}`); status != http.StatusMethodNotAllowed {
		t.Fatalf("unmergeable: %d", status)
	}
	w.sim.SetMergeable("acme/payments", 1, true)
	status, out := w.do("PUT", "/repos/acme/payments/pulls/1/merge", auth, `{"sha":"`+newer+`","merge_method":"squash"}`)
	if status != http.StatusOK || out["merged"] != true || w.sim.Branch("acme/payments", "main") != out["sha"] {
		t.Fatalf("merge: %d %v", status, out)
	}
	if p, _ := w.sim.PullRequest("acme/payments", 1); !p.Merged || p.State != "closed" || p.MergeMethod != "squash" {
		t.Fatalf("pull %+v", p)
	}
	if files := w.sim.Files("acme/payments", w.sim.Branch("acme/payments", "main")); files["parser.go"] != "package parser // v2\n" {
		t.Fatalf("merged files %v", files)
	}
	if status, _ := w.do("PUT", "/repos/acme/payments/pulls/1/merge", auth, `{"sha":"`+newer+`"}`); status != http.StatusMethodNotAllowed {
		t.Fatalf("merged twice: %d", status)
	}
}

// TestReviewsAreAtACommit: reviews record the commit they were made on,
// and the author cannot review their own pull request.
func TestReviewsAreAtACommit(t *testing.T) {
	w := newWorld(t)
	w.sim.AddToken("ghp_bob", "bob", []string{"acme/payments"}, map[string]string{"pull_requests": "write"})
	w.sim.AddToken("ghp_alice", "alice", []string{"acme/payments"}, map[string]string{"pull_requests": "write"})
	if status, _ := w.do("POST", "/repos/acme/payments/pulls", "token ghp_alice", `{"title":"Fix","head":"fix/a","base":"main"}`); status != http.StatusCreated {
		t.Fatalf("open: %d", status)
	}
	if status, _ := w.do("POST", "/repos/acme/payments/pulls/1/reviews", "token ghp_alice", `{"event":"APPROVE"}`); status != http.StatusUnprocessableEntity {
		t.Fatalf("self review: %d", status)
	}
	if status, _ := w.do("POST", "/repos/acme/payments/pulls/1/reviews", "token ghp_bob", `{"event":"APPROVE"}`); status != http.StatusOK {
		t.Fatalf("review: %d", status)
	}
	p, _ := w.sim.PullRequest("acme/payments", 1)
	if len(p.Reviews) != 1 || p.Reviews[0].User != "bob" || p.Reviews[0].State != "APPROVED" || p.Reviews[0].CommitID != w.head {
		t.Fatalf("reviews %+v", p.Reviews)
	}
}

// TestTheMCPServerToolsCallTheAPI: the GitHub MCP server's tools call the
// REST API with the server's token, so a merge through the MCP server is
// the same request, guarded by the same head, and recorded with the same
// token scope as a direct call (F099).
func TestTheMCPServerToolsCallTheAPI(t *testing.T) {
	w := newWorld(t)
	w.sim.AddToken("ghp_server", "developer", []string{"acme/payments"}, map[string]string{"contents": "write", "pull_requests": "write"})
	call := func(name, args string) (map[string]any, bool) {
		t.Helper()
		res, isErr, ok := w.sim.CallTool(t.Context(), "ghp_server", name, jsontext.Value(args))
		if !ok {
			t.Fatalf("%s: unknown tool", name)
		}
		var out map[string]any
		_ = json.Unmarshal(res, &out)
		return out, isErr
	}
	if out, isErr := call("create_branch", `{"owner":"acme","repo":"payments","branch":"fix/b","from_branch":"fix/a"}`); isErr ||
		w.sim.Branch("acme/payments", "fix/b") != w.head {
		t.Fatalf("create_branch: %v", out)
	}
	if out, isErr := call("create_pull_request", `{"owner":"acme","repo":"payments","title":"Fix","head":"fix/b","base":"main"}`); isErr {
		t.Fatalf("create_pull_request: %v", out)
	}
	if out, isErr := call("merge_pull_request", `{"owner":"acme","repo":"payments","pullNumber":1,"expectedHeadSha":"`+strings.Repeat("0", 40)+`"}`); !isErr ||
		out["message"] != "Head branch was modified. Review and try the merge again." {
		t.Fatalf("merge at another head: %v", out)
	}
	if out, isErr := call("merge_pull_request", `{"owner":"acme","repo":"payments","pullNumber":1,"expectedHeadSha":"`+w.head+`"}`); isErr || out["merged"] != true {
		t.Fatalf("merge: %v", out)
	}
	if _, _, ok := w.sim.CallTool(t.Context(), "ghp_server", "delete_repository", jsontext.Value(`{}`)); ok {
		t.Fatal("a tool the simulator does not serve")
	}
	reqs := w.sim.Requests()
	last := reqs[len(reqs)-1]
	if last.Method != http.MethodPut || last.Path != "/repos/acme/payments/pulls/1/merge" || last.User != "developer" ||
		last.Token != Fingerprint("ghp_server") || last.Status != http.StatusOK {
		t.Fatalf("recorded %+v", last)
	}
}
