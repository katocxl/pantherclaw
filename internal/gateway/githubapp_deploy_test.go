// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
)

const actionsBot = "github-actions[bot]"

// TestHR206_TheGatewayFindsADeploymentByItsCommitAndEnvironment (G0 M8
// W1c, coordinator decision D13): a consequence's lease names the
// deployment listing and the merge commit and environment the server
// captured. The gateway counts only deployments the Actions workflow made
// (github-actions[bot]) and only its statuses, whatever is listed first; a
// decoy someone else made, or a status someone else posted, is set aside
// and counted as evidence. Each deployment's verdict is its latest status
// from the workflow; an "inactive" never preceded by a success or progress
// is unproven, and matching deployments that disagree give a disagreement,
// never the newest. Another environment or commit finds nothing in a
// complete listing. Each read gets a deployments: read token for the one
// repository, revoked after it.
func TestHR206_TheGatewayFindsADeploymentByItsCommitAndEnvironment(t *testing.T) {
	w := newGitHubWorld(t)
	w.sim.DeployOnPush("acme/payments", "main", "production", time.Hour)
	h := setup(t, withGitHubApp(t, w))
	if r := h.do(t, http.MethodPut, "/payments/repos/acme/payments/pulls/1/merge", `{"sha":"`+w.head+`"}`, nil); r.code != http.StatusOK {
		t.Fatalf("merge = %d %s %+v", r.code, r.body, r.refusal)
	}
	p, _ := w.sim.PullRequest("acme/payments", 1)
	deps := w.sim.Deployments("acme/payments")
	if len(deps) != 1 || deps[0].SHA != p.MergeCommitSHA || deps[0].Creator != actionsBot {
		t.Fatalf("deployments %+v for %s", deps, p.MergeCommitSHA)
	}
	read := func(sha, env string) dispatch.Observation {
		t.Helper()
		o, err := h.gw.engine.VerifyEffect(t.Context(), h.conn, dispatch.Lease{
			Purpose: "consequence", Operation: "github.deployment.list",
			Request: []byte(`{"mode":"lookup","params":{"environment":"` + env + `","sha":"` + sha + `"},"target":{"id":"acme/payments","type":"github.repository"}}`),
		})
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	if o := read(p.MergeCommitSHA, "production"); !o.Found || !o.Complete ||
		!maps.Equal(o.Fields, map[string]string{"/state": "pending", "/others": "0"}) {
		t.Fatalf("the merge's deployment: %+v", o)
	}

	// The workflow's deployment fails; someone with deployments: write
	// makes a decoy of the same commit and environment, listed first, and
	// reports it successful, and posts a success on the real one too.
	w.sim.SetDeploymentStatus("acme/payments", deps[0].ID, "failure")
	decoy := w.sim.AddDeployment("acme/payments", p.MergeCommitSHA, "main", "production", "mallory")
	w.sim.AddDeploymentStatus("acme/payments", decoy, "success", "mallory")
	w.sim.AddDeploymentStatus("acme/payments", deps[0].ID, "success", "mallory")
	if listed := w.sim.Deployments("acme/payments"); listed[len(listed)-1].ID != decoy {
		t.Fatal("the decoy is not the newest")
	}
	if o := read(p.MergeCommitSHA, "production"); !o.Found || !maps.Equal(o.Fields, map[string]string{"/state": "failure", "/others": "1"}) {
		t.Fatalf("with a decoy: %+v", o)
	}

	for name, c := range map[string]struct {
		statuses [][]string // per deployment of one commit, the workflow's statuses, oldest first
		want     string
	}{
		"a manual inactive":                  {[][]string{{"inactive"}}, "unproven"},
		"inactive after a success":           {[][]string{{"success", "inactive"}}, "inactive"},
		"inactive after progress":            {[][]string{{"in_progress", "inactive"}}, "inactive"},
		"matching deployments that disagree": {[][]string{{"success"}, {"failure"}}, "disagreement"},
		"matching deployments that agree":    {[][]string{{"success"}, {"in_progress", "success"}}, "success"},
		"a deployment only just made":        {[][]string{{}}, "pending"},
	} {
		sha := strings.Repeat(string("abcdef0123"[len(name)%10]), 40)
		for _, sts := range c.statuses {
			id := w.sim.AddDeployment("acme/payments", sha, "main", "staging-"+strings.ReplaceAll(name, " ", "-"), actionsBot)
			for _, s := range sts {
				w.sim.AddDeploymentStatus("acme/payments", id, s, actionsBot)
			}
		}
		o := read(sha, "staging-"+strings.ReplaceAll(name, " ", "-"))
		if !o.Found || o.Fields["/state"] != c.want {
			t.Errorf("%s: %+v, want %q", name, o, c.want)
		}
	}

	// More matches than are read, or a page that may be cut, never give a
	// verdict from some of them (#349 review): newer successes could hide a
	// failure.
	flood := strings.Repeat("7", 40)
	failed := w.sim.AddDeployment("acme/payments", flood, "main", "flood", actionsBot)
	w.sim.AddDeploymentStatus("acme/payments", failed, "failure", actionsBot)
	for range 10 {
		id := w.sim.AddDeployment("acme/payments", flood, "main", "flood", actionsBot)
		w.sim.AddDeploymentStatus("acme/payments", id, "success", actionsBot)
	}
	if o := read(flood, "flood"); o.Fields["/state"] != "disagreement" {
		t.Errorf("eleven matches: %+v", o)
	}
	crowd := strings.Repeat("8", 40)
	for i := range 30 {
		who := "mallory"
		if i < 5 {
			who = actionsBot
		}
		id := w.sim.AddDeployment("acme/payments", crowd, "main", "crowd", who)
		w.sim.AddDeploymentStatus("acme/payments", id, "success", who)
	}
	if o := read(crowd, "crowd"); o.Fields["/state"] != "disagreement" || o.Fields["/others"] != "25" {
		t.Errorf("a full page: %+v", o)
	}

	for name, o := range map[string]dispatch.Observation{
		"another environment": read(p.MergeCommitSHA, "qa"),
		"another commit":      read(strings.Repeat("9", 40), "production"),
	} {
		if o.Found || !o.Complete || o.HTTPStatus != http.StatusOK {
			t.Errorf("%s: %+v", name, o)
		}
	}
	for _, tok := range w.sim.Tokens() {
		if !tok.Revoked || !slices.Equal(tok.Repos, []string{"acme/payments"}) {
			t.Errorf("token %+v", tok)
		}
	}
	for _, req := range w.sim.Requests() {
		if strings.Contains(req.Path, "/deployments") && !maps.Equal(req.Permissions, map[string]string{"deployments": "read", "metadata": "read"}) {
			t.Errorf("%s went out with %v", req.Path, req.Permissions)
		}
	}
}
