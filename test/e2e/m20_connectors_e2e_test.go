// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"encoding/base64"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strconv"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/redteam/app"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
	"github.com/katocxl/pantherclaw/internal/sim"
	"github.com/katocxl/pantherclaw/internal/sim/gitlab"
	"github.com/katocxl/pantherclaw/internal/sim/jira"
)

// The Jira and GitLab simulators' credentials: test values, not real ones.
var (
	jiraSecret  = base64.StdEncoding.EncodeToString([]byte("agent@example.test:simulated-e2e-api-token"))
	gitlabToken = "glpat-simulated-e2e-agent-token"
)

var (
	seededJira   = regexp.MustCompile(`seeded jira connection ([0-9a-f-]{36}) `)
	seededGitLab = regexp.MustCompile(`seeded gitlab connection ([0-9a-f-]{36}) `)
)

// jiraSim is the Jira simulator of a stack and the seeded connection
// "jira" to it (G0 M20 D254).
type jiraSim struct {
	sim  *jira.Server
	url  string
	conn ids.UUID
}

func startJiraSim(t *testing.T) *jiraSim {
	t.Helper()
	s := jira.New(sim.JiraProjects(), sim.JiraIssues(), jira.Faults{}, pclog.Discard()).WithRequire(jira.Require{Secret: jiraSecret})
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return &jiraSim{sim: s, url: srv.URL}
}

func (j *jiraSim) seeded(t *testing.T, out string) {
	t.Helper()
	m := seededJira.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("dev seed output %q", out)
	}
	j.conn = mustUUID(t, m[1])
}

// gitlabSim is the GitLab simulator of a stack and the seeded connection
// "gitlab" to it (G0 M20 D254).
type gitlabSim struct {
	sim  *gitlab.Server
	url  string
	conn ids.UUID
}

func startGitLabSim(t *testing.T) *gitlabSim {
	t.Helper()
	projects, mrs, pipelines := sim.GitLabStart()
	s := gitlab.New(projects, mrs, pipelines, gitlab.Faults{}, pclog.Discard()).WithRequire(gitlab.Require{Token: gitlabToken})
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return &gitlabSim{sim: s, url: srv.URL}
}

func (g *gitlabSim) seeded(t *testing.T, out string) {
	t.Helper()
	m := seededGitLab.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("dev seed output %q", out)
	}
	g.conn = mustUUID(t, m[1])
}

// jiraComment has the scenario's agent comment on an issue through the
// gateway's connection "jira" over the REST route.
func (d *rangeDriver) jiraComment(t *testing.T, issue, body string) domain.Observation {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"body": body})
	obs, _, err := d.callOnce(callWith{Face: "http", Connection: "jira", Method: http.MethodPost, Path: "/rest/api/2/issue/" + issue + "/comment", Body: b}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	return obs
}

// gitlabMerge has the scenario's agent merge the simulated merge request
// at sha through the gateway's connection "gitlab" over the REST route.
func (d *rangeDriver) gitlabMerge(t *testing.T, sha string) domain.Observation {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"sha": sha})
	path := "/api/v4/projects/" + strconv.Itoa(sim.GitLabProject) + "/merge_requests/" + strconv.Itoa(sim.GitLabMergeRequest) + "/merge"
	obs, _, err := d.callOnce(callWith{Face: "http", Connection: "gitlab", Method: http.MethodPut, Path: path, Body: b}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	return obs
}

// TestT226_AJiraCommentInACustomerProjectIsExternalDisclosure: on the real
// stack an agent comments through pc.jira with the credential only the
// gateway holds, on an internal issue its grant names; a comment on a help
// desk ticket predicts external_disclosure, which the grant does not allow;
// and an issue Jira will not show is a missing fact, never internal (HR-522,
// T-226).
//
// Covers: F756
func TestT226_AJiraCommentInACustomerProjectIsExternalDisclosure(t *testing.T) {
	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", people: &p, jira: true})
	d := newRangeDriver(t)
	d.s, d.people = s, &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p}
	d.sc = domain.Scenario{ID: "M20-JIRA", Requires: []string{string(capJiraComment)}}
	d.setupM20Connectors()
	if obs := d.jiraComment(t, sim.JiraIssue, "Retries fixed in the e2e build"); obs.Outcome != domain.OutcomeAllow {
		t.Fatalf("internal comment: %+v", obs)
	}
	if is, _ := s.jira.sim.Issue(sim.JiraIssue); len(is.Comments) != 1 || is.Comments[0].Body != "Retries fixed in the e2e build" {
		t.Fatalf("commented: %+v", is)
	}
	if obs := d.jiraComment(t, sim.JiraTicket, "Your refund was sent"); obs.Outcome != domain.OutcomeDeny ||
		!slices.Contains(obs.Reasons, "OPERATION_NOT_GRANTED") {
		t.Fatalf("help desk comment: %+v", obs)
	}
	s.jira.sim.SetFaults(jira.Faults{NotFound: true})
	obs := d.jiraComment(t, sim.JiraIssue, "Unreadable")
	s.jira.sim.SetFaults(jira.Faults{})
	if obs.Outcome != domain.OutcomeDeny || !slices.Contains(obs.Reasons, "FACT_MISSING") {
		t.Fatalf("unreadable issue: %+v", obs)
	}
	if is, _ := s.jira.sim.Issue(sim.JiraTicket); len(is.Comments) != 0 {
		t.Fatalf("the help desk ticket was commented: %+v", is)
	}
	for _, sec := range s.jira.sim.Secrets() {
		if sec != jiraSecret {
			t.Fatalf("Jira saw another credential: %q", sec)
		}
	}
}

// TestHR521_AGitLabMergeIsBoundToItsHead: on the real stack an agent merges
// a merge request through pc.gitlab under a grant, at the head the gateway
// read, with the token only the gateway holds; a merge naming a head that
// has moved is never sent (HR-521).
//
// Covers: F756
func TestHR521_AGitLabMergeIsBoundToItsHead(t *testing.T) {
	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", people: &p, gitlab: true})
	d := newRangeDriver(t)
	d.s, d.people = s, &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p}
	d.sc = domain.Scenario{ID: "M20-GITLAB", Requires: []string{string(capGitLabMerge)}}
	d.setupM20Connectors()
	s.gitlab.sim.Approve(sim.GitLabProject, sim.GitLabMergeRequest, "reviewer")
	stale := "1111111111111111111111111111111111111111"
	if obs := d.gitlabMerge(t, stale); obs.Outcome == domain.OutcomeAllow {
		t.Fatalf("a merge at a moved head: %+v", obs)
	}
	if m, _ := s.gitlab.sim.MergeRequest(sim.GitLabProject, sim.GitLabMergeRequest); m.Merges != 0 {
		t.Fatalf("merged at a moved head: %+v", m)
	}
	if obs := d.gitlabMerge(t, sim.GitLabHead); obs.Outcome != domain.OutcomeAllow {
		t.Fatalf("merge: %+v", obs)
	}
	if m, _ := s.gitlab.sim.MergeRequest(sim.GitLabProject, sim.GitLabMergeRequest); m.State != "merged" || m.Merges != 1 {
		t.Fatalf("not merged: %+v", m)
	}
	for _, tok := range s.gitlab.sim.Tokens() {
		if tok != gitlabToken {
			t.Fatalf("GitLab saw another token: %q", tok)
		}
	}
}

// Jira and GitLab range capabilities (G0 M20 D254): an agent commenting
// through pc.jira and merging through pc.gitlab.
const (
	capJiraComment app.Capability = "jira.comment"
	capGitLabMerge app.Capability = "gitlab.merge"
)

func m20ConnectorCapabilities() map[app.Capability]bool {
	return map[app.Capability]bool{capJiraComment: true, capGitLabMerge: true}
}

// setupM20Connectors gives the scenario's agent a grant of its own for
// what it requires: comments on the internal issue and the help desk
// ticket, whose disclosure it is not granted (HR-522), and merges of the
// simulated merge request (HR-521).
func (d *rangeDriver) setupM20Connectors() {
	if requires(d.sc, string(capJiraComment)) {
		d.ownGrant(`{"operations": ["jira.issue.comment", "jira.issue.read"],
			"targets": {"jira_issue": {"ids": ["`+sim.JiraIssue+`", "`+sim.JiraTicket+`"]}},
			"destinations": {"ids": ["`+sim.JiraIssue+`", "`+sim.JiraTicket+`"]}}`, "")
	}
	if requires(d.sc, string(capGitLabMerge)) {
		target := strconv.Itoa(sim.GitLabProject) + "!" + strconv.Itoa(sim.GitLabMergeRequest)
		d.ownGrant(`{"operations": ["gitlab.merge_request.merge", "gitlab.merge_request.read"],
			"targets": {"gitlab_merge_request": {"ids": ["`+target+`"]}}}`, "")
	}
}
