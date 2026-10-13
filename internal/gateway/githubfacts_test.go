// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"encoding/json/v2"
	"maps"
	"net/http"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gateway/githubfacts"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/sim/github"
)

// factReport is one ReportFacts call, with how many decisions the
// Authority had been asked for when it came.
type factReport struct {
	conn    string
	obs     []*pb.FactObservation
	decided int
}

// withFactReports records the gateway's fact reports.
func withFactReports(h *harness) { h.reportFacts = true }

func (h *harness) factReports() []factReport {
	h.circuitMu.Lock()
	defer h.circuitMu.Unlock()
	return slices.Clone(h.facts)
}

// members decodes a reported object fact.
func members(t *testing.T, o *pb.FactObservation) map[string]any {
	t.Helper()
	var v struct {
		Object map[string]any `json:"object"`
	}
	if err := json.Unmarshal(o.GetValue(), &v); err != nil {
		t.Fatal(err)
	}
	return v.Object
}

const deployOnMain = "on:\n  push:\n    branches: [main]\njobs:\n  deploy: {runs-on: x, environment: production}\n"

// TestHR160_TheGatewayReportsGitHubFactsBeforeTheDecision: before a merge
// is decided, the gateway reads the facts the merge's prerequisites and
// consequence rules name, with a read-only token of its own that it then
// revokes, and reports them about the pull request as the connection's
// provider; deploy triggers are the base branch's after the merge. A
// contents write reports its branch's triggers at the branch head, and an
// operation that names no fact reads nothing.
func TestHR160_TheGatewayReportsGitHubFactsBeforeTheDecision(t *testing.T) {
	w := newGitHubWorld(t)
	mainHead := w.sim.Push("acme/payments", "main", map[string]string{".github/workflows/deploy.yml": deployOnMain})
	h := setup(t, withGitHubApp(t, w), withFactReports)
	if r := h.do(t, http.MethodGet, "/payments/repos/acme/payments/contents/README.md", "", nil); r.code != http.StatusOK {
		t.Fatalf("read = %d %+v", r.code, r.refusal)
	}
	if got := h.factReports(); len(got) != 0 {
		t.Fatalf("a read that names no fact reported %v", got)
	}
	if r := h.do(t, http.MethodPut, "/payments/repos/acme/payments/pulls/1/merge", `{"sha":"`+w.head+`"}`, nil); r.code != http.StatusOK {
		t.Fatalf("merge = %d %s %+v", r.code, r.body, r.refusal)
	}
	got := h.factReports()
	if len(got) != 1 || got[0].conn != connID || got[0].decided != 1 { // the read was decided; the merge not yet
		t.Fatalf("reports %+v", got)
	}
	byName := map[string]*pb.FactObservation{}
	for _, o := range got[0].obs {
		if o.GetSubjectType() != "github.pull_request" || o.GetSubjectId() != "acme/payments#1" {
			t.Errorf("a fact about %s %s", o.GetSubjectType(), o.GetSubjectId())
		}
		byName[o.GetName()] = o
	}
	want := []string{githubfacts.PullHead, githubfacts.PullPeople, githubfacts.PullReviews, githubfacts.PullChecks, githubfacts.BranchRules, githubfacts.RepoTriggers}
	if !slices.Equal(slices.Sorted(maps.Keys(byName)), slices.Sorted(slices.Values(want))) {
		t.Fatalf("reported %v, want %v", slices.Sorted(maps.Keys(byName)), want)
	}
	if head := members(t, byName[githubfacts.PullHead]); head["sha"] != w.head {
		t.Errorf("head %v", head)
	}
	if people := members(t, byName[githubfacts.PullPeople]); people["complete"] != true || len(people["pushers"].([]any)) == 0 {
		t.Errorf("people %v", people)
	}
	if d := members(t, byName[githubfacts.RepoTriggers]); d["state"] != "triggered" || d["at"] != mainHead {
		t.Errorf("triggers %v", d)
	}
	var reads []github.Token
	for _, tok := range w.sim.Tokens() {
		if maps.Equal(tok.Permissions, githubfacts.Scopes) {
			reads = append(reads, tok)
		}
		if !tok.Revoked || !slices.Equal(tok.Repos, []string{"acme/payments"}) {
			t.Errorf("token %+v", tok)
		}
	}
	if len(reads) != 1 || len(w.sim.Tokens()) != 3 {
		t.Fatalf("%d fact tokens of %d, want one beside each action's own", len(reads), len(w.sim.Tokens()))
	}

	branch := "/payments/repos/acme/payments/contents/docs/a.md"
	if r := h.do(t, http.MethodPut, branch, `{"message":"docs","content":"YQ==","branch":"fix/a"}`, nil); r.code != http.StatusCreated && r.code != http.StatusOK {
		t.Fatalf("write = %d %s %+v", r.code, r.body, r.refusal)
	}
	got = h.factReports()
	if len(got) != 2 || len(got[1].obs) != 1 || got[1].obs[0].GetName() != githubfacts.BranchTriggers ||
		got[1].obs[0].GetSubjectId() != "acme/payments@refs/heads/fix/a" {
		t.Fatalf("write reports %+v", got)
	}
	if d := members(t, got[1].obs[0]); d["state"] != "none" || d["at"] != w.head {
		t.Fatalf("a branch no workflow deploys: %v", d)
	}
}

// TestHR160_NoFactTokenNoFacts: when the fact token cannot be minted, the
// gateway reports nothing and the decision goes ahead without the facts
// (CANNOT_AUTHORIZE or "Consequence unknown" there, never a guess here).
func TestHR160_NoFactTokenNoFacts(t *testing.T) {
	w := newGitHubWorld(t)
	h := setup(t, withGitHubApp(t, w), withFactReports)
	w.sim.SetFaults(github.Faults{TokenStatus: http.StatusInternalServerError})
	r := h.do(t, http.MethodPut, "/payments/repos/acme/payments/pulls/1/merge", `{"sha":"`+w.head+`"}`, nil)
	if got := h.factReports(); len(got) != 0 || h.auth.snap().authorize != 1 {
		t.Fatalf("reports %+v, %d decisions", got, h.auth.snap().authorize)
	}
	if r.code != http.StatusBadGateway || r.refusal.Error != "credential_unavailable" {
		t.Fatalf("merge = %d %+v", r.code, r.refusal)
	}
	if p, _ := w.sim.PullRequest("acme/payments", 1); p.Merged {
		t.Fatal("merged without a token")
	}
}
