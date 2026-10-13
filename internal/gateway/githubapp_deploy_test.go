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

// TestHR206_TheGatewayFindsADeploymentByItsCommitAndEnvironment (G0 M8
// W1c): a consequence's lease names the deployment listing and the merge
// commit and environment the server captured. The gateway lists the
// commit's deployments to that environment, finds the one whose sha and
// environment match, reads its statuses in the same lease, and reports only
// the declared field, the latest state. Another environment or commit finds
// nothing in a complete listing. Each read gets a deployments: read token
// for the one repository, revoked after it.
func TestHR206_TheGatewayFindsADeploymentByItsCommitAndEnvironment(t *testing.T) {
	w := newGitHubWorld(t)
	w.sim.DeployOnPush("acme/payments", "main", "production", time.Hour)
	h := setup(t, withGitHubApp(t, w))
	if r := h.do(t, http.MethodPut, "/payments/repos/acme/payments/pulls/1/merge", `{"sha":"`+w.head+`"}`, nil); r.code != http.StatusOK {
		t.Fatalf("merge = %d %s %+v", r.code, r.body, r.refusal)
	}
	p, _ := w.sim.PullRequest("acme/payments", 1)
	deps := w.sim.Deployments("acme/payments")
	if len(deps) != 1 || deps[0].SHA != p.MergeCommitSHA {
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
	if o := read(p.MergeCommitSHA, "production"); !o.Found || !o.Complete || !maps.Equal(o.Fields, map[string]string{"/0/state": "pending"}) {
		t.Fatalf("the merge's deployment: %+v", o)
	}
	w.sim.SetDeploymentStatus("acme/payments", deps[0].ID, "failure")
	if o := read(p.MergeCommitSHA, "production"); !o.Found || o.Fields["/0/state"] != "failure" {
		t.Fatalf("a failed deployment: %+v", o)
	}
	for name, o := range map[string]dispatch.Observation{
		"another environment": read(p.MergeCommitSHA, "staging"),
		"another commit":      read(strings.Repeat("a", 40), "production"),
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
