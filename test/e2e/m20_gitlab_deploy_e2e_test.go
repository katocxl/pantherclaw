// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"slices"
	"strconv"
	"testing"

	"github.com/katocxl/pantherclaw/internal/redteam/domain"
	"github.com/katocxl/pantherclaw/internal/sim"
	"github.com/katocxl/pantherclaw/internal/sim/gitlab"
)

// gitlabDeployRequirements has a release approver decide every deployment.
const gitlabDeployRequirements = `[{"operations": ["gitlab.deployment.trigger"], "reason": "DEPLOYMENTS_NEED_A_RELEASE",
	"approval": {"role": "release_approver", "count": 1}}]`

// gitlabMergeBounds are the bounds of a grant to merge the simulated merge
// requests, with or without the deployments the merges start.
func gitlabMergeBounds(deploy bool) string {
	merges := `"` + strconv.Itoa(sim.GitLabProject) + "!" + strconv.Itoa(sim.GitLabMergeRequest) + `", "` +
		strconv.Itoa(sim.GitLabProject) + "!" + strconv.Itoa(sim.GitLabUnverifiedMergeRequest) + `"`
	if !deploy {
		return `{"operations": ["gitlab.merge_request.merge", "gitlab.merge_request.read"],
			"targets": {"gitlab_merge_request": {"ids": [` + merges + `]}}}`
	}
	return `{"operations": ["gitlab.merge_request.merge", "gitlab.merge_request.read", "gitlab.deployment.trigger"],
		"targets": {"gitlab_merge_request": {"ids": [` + merges + `]},
			"gitlab_project": {"ids": ["` + strconv.Itoa(sim.GitLabProject) + `"]}}}`
}

// gitlabMergeFixtures names the merge requests to scenarios and approves
// them, so that nothing but the deployment decides a merge.
func (d *rangeDriver) gitlabMergeFixtures() {
	if d.fix == nil {
		d.fix = map[string]string{}
	}
	d.fix["gitlab_project"] = strconv.Itoa(sim.GitLabProject)
	d.fix["gitlab_merge_request"], d.fix["gitlab_head"] = strconv.Itoa(sim.GitLabMergeRequest), sim.GitLabHead
	d.fix["gitlab_unverified_merge_request"], d.fix["gitlab_unverified_head"] = strconv.Itoa(sim.GitLabUnverifiedMergeRequest), sim.GitLabUnverifiedHead
	d.s.gitlab.sim.Approve(sim.GitLabProject, sim.GitLabMergeRequest, "reviewer")
	d.s.gitlab.sim.Approve(sim.GitLabProject, sim.GitLabUnverifiedMergeRequest, "reviewer")
}

// TestT229_ADeployWithoutAVerifiedPipelineIsHeld: on the real stack, a merge
// into a project with environments is held as an unknown consequence while
// its head pipeline has not passed at its head, whatever the grant says;
// once the pipeline passed, it is the deployment a release approver decides;
// and a grant that does not cover the deployment refuses the merge
// (HR-521, T-229).
//
// Covers: F756
func TestT229_ADeployWithoutAVerifiedPipelineIsHeld(t *testing.T) {
	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", people: &p, gitlab: true})
	d := newRangeDriver(t)
	d.s, d.people = s, &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p}
	d.sc = domain.Scenario{ID: "M20-DEPLOY", Requires: []string{string(capGitLabMerge), string(capGitLabDeploy)}}
	d.setupM20Connectors()
	obs := d.gitlabMerge(t, sim.GitLabUnverifiedMergeRequest, sim.GitLabUnverifiedHead)
	if obs.Outcome != domain.OutcomeHold || !slices.Contains(obs.Reasons, "CONSEQUENCE_UNKNOWN") {
		t.Fatalf("a merge whose pipeline is running: %+v", obs)
	}
	if !s.gitlab.sim.SetPipeline(sim.GitLabRunningPipeline, "failed") {
		t.Fatal("no pipeline")
	}
	obs = d.gitlabMerge(t, sim.GitLabUnverifiedMergeRequest, sim.GitLabUnverifiedHead)
	if obs.Outcome != domain.OutcomeHold || !slices.Contains(obs.Reasons, "CONSEQUENCE_UNKNOWN") {
		t.Fatalf("a merge whose pipeline failed: %+v", obs)
	}
	s.gitlab.sim.SetPipeline(sim.GitLabRunningPipeline, "success")
	obs = d.gitlabMerge(t, sim.GitLabUnverifiedMergeRequest, sim.GitLabUnverifiedHead)
	if obs.Outcome != domain.OutcomeHold || !slices.Contains(obs.Reasons, "DEPLOYMENTS_NEED_A_RELEASE") {
		t.Fatalf("a verified deployment: %+v", obs)
	}
	d.defaultRun = d.grantRun(gitlabMergeBounds(false), "")
	obs = d.gitlabMerge(t, sim.GitLabMergeRequest, sim.GitLabHead)
	if obs.Outcome != domain.OutcomeDeny || !slices.Contains(obs.Reasons, "OPERATION_NOT_GRANTED") {
		t.Fatalf("a grant without the deployment: %+v", obs)
	}
	for _, iid := range []int{sim.GitLabMergeRequest, sim.GitLabUnverifiedMergeRequest} {
		if m, _ := s.gitlab.sim.MergeRequest(sim.GitLabProject, iid); m.Merges != 0 {
			t.Fatalf("merged: %+v", m)
		}
	}
	if got := s.gitlab.sim.Deployments(sim.GitLabProject); len(got) != 0 {
		t.Fatalf("deployments: %+v", got)
	}
}

// TestT229_AProjectWithoutAvailableEnvironmentsStillDeploys: a stopped
// environment is predicted, because a deploying job restarts it, and a new
// project with no environment is held when its .gitlab-ci.yml at the head or
// the target branch mentions environment or include or cannot be read, and when it has a custom
// configuration path or Auto DevOps. Only a project with no environment and
// none of these merges with no consequence (D287, D289, T-229).
//
// Covers: F756
func TestT229_AProjectWithoutAvailableEnvironmentsStillDeploys(t *testing.T) {
	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", people: &p, gitlab: true})
	d := newRangeDriver(t)
	d.s, d.people = s, &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p}
	d.sc = domain.Scenario{ID: "M20-STOPPED", Requires: []string{string(capGitLabMerge), string(capGitLabDeploy)}}
	d.setupM20Connectors()
	gl := s.gitlab.sim
	held := func(name string) {
		t.Helper()
		// A run of its own: a run may hold only so many actions.
		d.defaultRun = d.grantRunWith(gitlabMergeBounds(true), "", gitlabDeployRequirements)
		obs := d.gitlabMerge(t, sim.GitLabUnverifiedMergeRequest, sim.GitLabUnverifiedHead)
		if obs.Outcome != domain.OutcomeHold || !slices.Contains(obs.Reasons, "CONSEQUENCE_UNKNOWN") {
			t.Fatalf("%s: %+v", name, obs)
		}
	}
	gl.SetEnvironments(sim.GitLabProject, nil, []string{sim.GitLabEnvironment})
	held("a stopped environment")
	gl.SetEnvironments(sim.GitLabProject, nil, nil)
	gl.SetCIConfig(sim.GitLabProject, "deploy:\n  script: ./deploy\n  environment: production\n")
	held("a new project that deploys")
	gl.SetCIConfig(sim.GitLabProject, "include:\n  - project: acme/ci\n")
	held("a new project that includes")
	gl.SetCIConfig(sim.GitLabProject, "test:\n  script: go test\n")
	gl.SetCIConfigAt(sim.GitLabProject, "main", "deploy:\n  script: ./deploy\n  environment: production\n")
	held("a deploy job on the target branch only")
	gl.SetCIConfigAt(sim.GitLabProject, "main", "test:\n  script: go test\n")
	gl.SetFaults(gitlab.Faults{CIConfigError: true})
	held("an unreadable configuration")
	gl.SetFaults(gitlab.Faults{})
	gl.SetCIProject(sim.GitLabProject, "ci/deploy.yml", false)
	held("a custom configuration path")
	gl.SetCIProject(sim.GitLabProject, "", true)
	held("Auto DevOps")
	gl.SetCIProject(sim.GitLabProject, "", false)
	d.defaultRun = d.grantRun(gitlabMergeBounds(false), "")
	if obs := d.gitlabMerge(t, sim.GitLabMergeRequest, sim.GitLabHead); obs.Outcome != domain.OutcomeAllow {
		t.Fatalf("a project that deploys nothing: %+v", obs)
	}
	if got := gl.Deployments(sim.GitLabProject); len(got) != 0 {
		t.Fatalf("deployments: %+v", got)
	}
}

// TestT229_AFastForwardMergeIsNotVerifiable: GitLab names no merge commit for
// a fast-forward merge, so the deployment has no commit to be found by and
// the merge's downstream state says so, instead of counting as confirmed
// (HR-451, D287).
//
// Covers: F756
func TestT229_AFastForwardMergeIsNotVerifiable(t *testing.T) {
	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", people: &p, gitlab: true})
	d := newRangeDriver(t)
	d.s, d.people = s, &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p}
	d.sc = domain.Scenario{ID: "M20-FF", Requires: []string{string(capGitLabMerge)}}
	d.setupM20Connectors()
	s.gitlab.sim.SetFastForward(sim.GitLabProject, true)
	obs := d.gitlabMerge(t, sim.GitLabMergeRequest, sim.GitLabHead)
	if obs.Outcome != domain.OutcomeAllow {
		t.Fatalf("merge: %+v", obs)
	}
	s.eventually(t, "CONFIRMED", "SELECT coalesce(effect_state, '') FROM pc.transactions WHERE id = $1", obs.TransactionID)
	s.eventually(t, "NOT_VERIFIABLE", "SELECT coalesce(downstream_state, '') FROM pc.transactions WHERE id = $1", obs.TransactionID)
}

// TestT229_ADeploymentIsVerifiedFromGitLabsOwnRecord is the deploy's M17
// path (HR-451, HR-521): a merge is confirmed, its deployment is a
// consequence transaction of its own, and the merge stays downstream
// PENDING until GitLab's deployment of the merge commit succeeded.
//
// Covers: F756
func TestT229_ADeploymentIsVerifiedFromGitLabsOwnRecord(t *testing.T) {
	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", people: &p, gitlab: true})
	d := newRangeDriver(t)
	d.s, d.people = s, &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p}
	d.sc = domain.Scenario{ID: "M20-VERIFY", Requires: []string{string(capGitLabMerge)}}
	d.setupM20Connectors()
	obs := d.gitlabMerge(t, sim.GitLabMergeRequest, sim.GitLabHead)
	if obs.Outcome != domain.OutcomeAllow {
		t.Fatalf("merge: %+v", obs)
	}
	effect := "SELECT coalesce(effect_state, '') FROM pc.transactions WHERE id = $1"
	downstream := "SELECT coalesce(downstream_state, '') FROM pc.transactions WHERE id = $1"
	s.eventually(t, "CONFIRMED", effect, obs.TransactionID)
	s.eventually(t, "PENDING", downstream, obs.TransactionID)
	var consequence string
	s.query(t, `SELECT coalesce((SELECT to_transaction_id::text FROM pc.transaction_links
		WHERE from_transaction_id = $1 AND kind = 'consequence'), '')`, []any{obs.TransactionID}, &consequence)
	if consequence == "" {
		t.Fatal("no consequence transaction for the deployment")
	}
	got := s.gitlab.sim.Deployments(sim.GitLabProject)
	if len(got) != 1 || got[0].Environment != sim.GitLabEnvironment {
		t.Fatalf("deployments: %+v", got)
	}
	s.gitlab.sim.SetDeployment(got[0].ID, "success")
	s.db.AdminExec(t, "UPDATE pc.verifications SET next_at = now() WHERE transaction_id = $1 AND state = 'PENDING'", mustUUID(t, consequence))
	s.eventually(t, "CONFIRMED", effect, consequence)
	s.eventually(t, "CONFIRMED", downstream, obs.TransactionID)
}
