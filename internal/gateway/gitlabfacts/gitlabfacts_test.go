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

// TestT229_ADeploymentNeedsAPipelineThatPassedAtTheHead: a project with no
// environment deploys nothing; with one, the fact has a state only when the
// head pipeline passed at the head, and anything else is unread, so the
// consequence is unknown and the merge at least held (HR-521, T-229).
//
// Covers: F756
func TestT229_ADeploymentNeedsAPipelineThatPassedAtTheHead(t *testing.T) {
	envs, passed, running := []byte(`[{"id":1,"name":"production"}]`), map[string]any{"id": "900", "passed": true}, map[string]any{"id": "901", "passed": false}
	if v := Deployment(200, []byte(`[]`), running); v["state"] != "none" {
		t.Fatalf("no environment: %v", v)
	}
	v := Deployment(200, envs, passed)
	if e, _ := v["environments"].([]any); v["state"] != "verified" || len(e) != 1 || e[0] != "production" || v["pipeline"] != "900" {
		t.Fatalf("verified: %v", v)
	}
	full := []byte(`[` + strings.Repeat(`{"name":"e"},`, EnvironmentsPageSize-1) + `{"name":"e"}]`)
	for name, got := range map[string]map[string]any{
		"running":         Deployment(200, envs, running),
		"unread pipeline": Deployment(200, envs, Unread("no")),
		"refused":         Deployment(403, envs, passed),
		"not JSON":        Deployment(200, []byte(`{`), passed),
		"bad name":        Deployment(200, []byte(`[{"name":"a\nb"}]`), passed),
		"a full page":     Deployment(200, full, passed),
	} {
		if _, unread := got["unread"]; !unread {
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
