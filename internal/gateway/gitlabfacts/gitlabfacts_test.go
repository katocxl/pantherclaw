// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gitlabfacts

import (
	"strings"
	"testing"
)

const (
	head = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
	old  = "1111111111111111111111111111111111111111"
)

func mr(sha, pipeline string) []byte {
	return []byte(`{"iid":7,"project_id":42,"state":"opened","sha":"` + head + `","source_branch":"fix","target_branch":"main",` +
		`"head_pipeline":{"id":900,"sha":"` + sha + `","status":"` + pipeline + `"}}`)
}

// TestT229_ADeploymentNeedsAPipelineThatPassedAtTheHead: the fact has a state
// only when the head pipeline passed at the head, and anything else is
// unread, so the consequence is unknown and the merge at least held (HR-521,
// T-229).
//
// Covers: F756
func TestT229_ADeploymentNeedsAPipelineThatPassedAtTheHead(t *testing.T) {
	envs := []any{"production"}
	v := Deployment(envs, map[string]any{"id": "900", "passed": true})
	if e, _ := v["environments"].([]any); v["state"] != "verified" || len(e) != 1 || e[0] != "production" || v["pipeline"] != "900" {
		t.Fatalf("verified: %v", v)
	}
	for name, pipeline := range map[string]map[string]any{
		"running":         {"id": "901", "passed": false},
		"unread pipeline": Unread("no"),
	} {
		if got := Deployment(envs, pipeline); got["unread"] == nil {
			t.Errorf("%s: %v", name, got)
		}
	}
}

// TestT229_EnvironmentsNeverGuess: a stopped environment counts, because a
// deploying job restarts it, and an answer that is not clearly a whole list
// of environments is no list (HR-160, D287).
//
// Covers: F756
func TestT229_EnvironmentsNeverGuess(t *testing.T) {
	got, why := Environments(200, []byte(`[{"id":1,"name":"production","state":"stopped"}]`))
	if why != "" || len(got) != 1 || got[0] != "production" {
		t.Fatalf("stopped: %v %q", got, why)
	}
	if got, why = Environments(200, []byte(`[]`)); why != "" || len(got) != 0 {
		t.Fatalf("none: %v %q", got, why)
	}
	full := []byte(`[` + strings.Repeat(`{"name":"e"},`, EnvironmentsPageSize-1) + `{"name":"e"}]`)
	for name, c := range map[string]struct {
		status int
		body   []byte
	}{
		"refused":     {403, []byte(`[]`)},
		"not JSON":    {200, []byte(`{`)},
		"bad name":    {200, []byte(`[{"name":"a\nb"}]`)},
		"a full page": {200, full},
	} {
		if _, why := Environments(c.status, c.body); why == "" {
			t.Errorf("%s: read", name)
		}
	}
}

// TestT229_AProjectThatDeploysFromElsewhereIsNotReadAsNone: a custom CI path
// or Auto DevOps may deploy without .gitlab-ci.yml, and an answer that does
// not state both settings says neither (D289, T-229).
//
// Covers: F756
func TestT229_AProjectThatDeploysFromElsewhereIsNotReadAsNone(t *testing.T) {
	for name, body := range map[string]string{
		"no setting": `{"id":42,"ci_config_path":"","auto_devops_enabled":false}`,
		"null path":  `{"id":42,"ci_config_path":null,"auto_devops_enabled":false}`,
	} {
		if why := ProjectCI(200, []byte(body), 42); why != "" {
			t.Errorf("%s: %s", name, why)
		}
	}
	for name, c := range map[string]struct {
		status int
		body   string
	}{
		"custom path":   {200, `{"id":42,"ci_config_path":"ci/deploy.yml","auto_devops_enabled":false}`},
		"auto devops":   {200, `{"id":42,"ci_config_path":"","auto_devops_enabled":true}`},
		"no path key":   {200, `{"id":42,"auto_devops_enabled":false}`},
		"no devops key": {200, `{"id":42,"ci_config_path":""}`},
		"null devops":   {200, `{"id":42,"ci_config_path":"","auto_devops_enabled":null}`},
		"other project": {200, `{"id":43,"ci_config_path":"","auto_devops_enabled":false}`},
		"not JSON":      {200, `{`},
		"refused":       {403, ""},
	} {
		if ProjectCI(c.status, []byte(c.body), 42) == "" {
			t.Errorf("%s: read", name)
		}
	}
}

// TestT229_ANewProjectIsReadForItsPipelineConfiguration: no file deploys
// nothing, and a file that mentions environment or include, in any case, or
// one that could not be read, is unread (D287, T-229).
//
// Covers: F756
func TestT229_ANewProjectIsReadForItsPipelineConfiguration(t *testing.T) {
	if v := NoEnvironments(404, nil); v["state"] != "none" {
		t.Fatalf("no file: %v", v)
	}
	if v := NoEnvironments(200, []byte("test:\n  script: go test\n")); v["state"] != "none" {
		t.Fatalf("no deploy: %v", v)
	}
	for name, c := range map[string]struct {
		status int
		body   string
	}{
		"environment": {200, "deploy:\n  environment: production\n"},
		"include":     {200, "include:\n  - project: acme/ci\n"},
		"upper case":  {200, "ENVIRONMENT: x\n"},
		"a comment":   {200, "# no environment here\n"},
		"refused":     {403, ""},
		"failed":      {500, ""},
		"no answer":   {0, ""},
	} {
		if got := NoEnvironments(c.status, []byte(c.body)); got["unread"] == nil {
			t.Errorf("%s: %v", name, got)
		}
	}
}

// TestHR521_GitLabFactsNeverGuess: a pipeline passed only when it succeeded
// at the merge request's own head, approvals count only when none are left,
// a branch without a rule is unprotected, and anything GitLab did not
// clearly answer is unread (HR-160, HR-521).
//
// Covers: F756
func TestHR521_GitLabFactsNeverGuess(t *testing.T) {
	got := ParseMergeRequest(200, mr(head, "success"), 42, 7)
	if got.Head["sha"] != head || got.TargetBranch != "main" || got.Pipeline["passed"] != true {
		t.Fatalf("passed: %+v", got)
	}
	for name, c := range map[string]struct {
		body   []byte
		passed any
	}{
		"old commit": {mr(old, "success"), false},
		"running":    {mr(head, "running"), false},
		"failed":     {mr(head, "failed"), false},
		"no pipeline": {[]byte(`{"iid":7,"project_id":42,"state":"opened","sha":"` + head +
			`","source_branch":"fix","target_branch":"main","head_pipeline":null}`), false},
	} {
		if v := ParseMergeRequest(200, c.body, 42, 7).Pipeline; v["passed"] != c.passed {
			t.Errorf("%s: %v", name, v)
		}
	}
	for name, v := range map[string]MergeRequest{
		"other merge request": ParseMergeRequest(200, mr(head, "success"), 42, 8),
		"other project":       ParseMergeRequest(200, mr(head, "success"), 43, 7),
		"refused":             ParseMergeRequest(401, nil, 42, 7),
		"not json":            ParseMergeRequest(200, []byte(`<html>`), 42, 7),
		"bad state":           ParseMergeRequest(200, []byte(`{"iid":7,"project_id":42,"state":"x","sha":"`+head+`","source_branch":"a","target_branch":"b"}`), 42, 7),
	} {
		if v.Head["unread"] == nil || v.Pipeline["unread"] == nil || v.TargetBranch != "" {
			t.Errorf("%s: %+v", name, v)
		}
	}
	for name, c := range map[string]struct {
		got      map[string]any
		approved any
	}{
		"approved":      {Approvals(200, []byte(`{"iid":7,"project_id":42,"approved":true,"approvals_left":0,"approved_by":[{"user":{"username":"rev"}}]}`), 42, 7), true},
		"one left":      {Approvals(200, []byte(`{"iid":7,"project_id":42,"approved":true,"approvals_left":1,"approved_by":[]}`), 42, 7), false},
		"not approved":  {Approvals(200, []byte(`{"iid":7,"project_id":42,"approved":false,"approvals_left":0,"approved_by":[]}`), 42, 7), false},
		"no left":       {Approvals(200, []byte(`{"iid":7,"project_id":42,"approved":true,"approved_by":[]}`), 42, 7), nil},
		"other request": {Approvals(200, []byte(`{"iid":8,"project_id":42,"approved":true,"approvals_left":0}`), 42, 7), nil},
		"forbidden":     {Approvals(403, nil, 42, 7), nil},
	} {
		if c.approved == nil {
			if c.got["unread"] == nil {
				t.Errorf("%s: %v", name, c.got)
			}
		} else if c.got["approved"] != c.approved {
			t.Errorf("%s: %v", name, c.got)
		}
	}
	if v := Protection(404, nil, "main"); v["protected"] != false {
		t.Fatalf("unprotected: %v", v)
	}
	if v := Protection(200, []byte(`{"name":"main","allow_force_push":false,"code_owner_approval_required":true}`), "main"); v["protected"] != true ||
		v["code_owner_approval"] != true {
		t.Fatalf("protected: %v", v)
	}
	for name, v := range map[string]map[string]any{
		"other branch": Protection(200, []byte(`{"name":"dev","allow_force_push":false}`), "main"),
		"refused":      Protection(401, nil, "main"),
		"no force":     Protection(200, []byte(`{"name":"main"}`), "main"),
	} {
		if v["unread"] == nil {
			t.Errorf("%s: %v", name, v)
		}
	}
}
