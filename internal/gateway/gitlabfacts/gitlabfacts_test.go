// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gitlabfacts

import "testing"

const (
	head = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
	old  = "1111111111111111111111111111111111111111"
)

func mr(sha, pipeline string) []byte {
	return []byte(`{"iid":7,"project_id":42,"state":"opened","sha":"` + head + `","source_branch":"fix","target_branch":"main",` +
		`"head_pipeline":{"id":900,"sha":"` + sha + `","status":"` + pipeline + `"}}`)
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
