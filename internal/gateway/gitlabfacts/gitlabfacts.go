// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package gitlabfacts reads the GitLab facts pc.gitlab names (G0 M20
// D254): a merge request's head, its approvals, its head pipeline and its
// target branch's protection, and the deployment a merge starts. It parses
// GitLab's answers and never
// guesses: what it cannot read is unread, so the decision sees the fact
// missing (HR-160), never an approved merge request or a passed pipeline.
package gitlabfacts

import (
	"encoding/json/v2"
	"regexp"
	"slices"
	"strconv"
)

// Facts a merge's prerequisites name.
const (
	MergeRequestHead      = "gitlab.merge_request.head"
	MergeRequestApprovals = "gitlab.merge_request.approvals"
	MergeRequestPipeline  = "gitlab.merge_request.pipeline"
	BranchProtection      = "gitlab.branch.protection"
)

// Names are every fact this package reads.
var Names = []string{MergeRequestHead, MergeRequestApprovals, MergeRequestPipeline, BranchProtection, MergeRequestDeployment}

var (
	shaRe    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	branchRe = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,255}$`)
	userRe   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,255}$`)
	statusRe = regexp.MustCompile(`^[a-z_]{1,32}$`)
	states   = []string{"opened", "closed", "locked", "merged"}
)

// MergeRequest is a parsed merge request answer: the head and pipeline
// facts' values, and the target branch to read the protection of ("" when
// unread).
type MergeRequest struct {
	Head, Pipeline map[string]any
	TargetBranch   string
}

// ParseMergeRequest parses GET /projects/:id/merge_requests/:iid for
// project and iid.
func ParseMergeRequest(status int, body []byte, project, iid int) MergeRequest {
	if why := refused(status); why != "" {
		return MergeRequest{Head: Unread(why), Pipeline: Unread(why)}
	}
	var a struct {
		IID     int    `json:"iid"`
		Project int    `json:"project_id"`
		State   string `json:"state"`
		SHA     string `json:"sha"`
		Source  string `json:"source_branch"`
		Target  string `json:"target_branch"`
		Head    *struct {
			ID     int    `json:"id"`
			SHA    string `json:"sha"`
			Status string `json:"status"`
		} `json:"head_pipeline"`
	}
	if json.Unmarshal(body, &a) != nil {
		return MergeRequest{Head: Unread("GitLab's answer could not be read"), Pipeline: Unread("GitLab's answer could not be read")}
	}
	if a.IID != iid || a.Project != project || !shaRe.MatchString(a.SHA) || !branchRe.MatchString(a.Source) || !branchRe.MatchString(a.Target) ||
		!slices.Contains(states, a.State) {
		why := Unread("GitLab's answer does not describe the merge request")
		return MergeRequest{Head: why, Pipeline: why}
	}
	out := MergeRequest{
		Head:         map[string]any{"sha": a.SHA, "state": a.State, "source_branch": a.Source, "target_branch": a.Target},
		TargetBranch: a.Target,
	}
	switch h := a.Head; {
	case h == nil:
		out.Pipeline = map[string]any{"status": "none", "passed": false}
	case h.ID <= 0 || !statusRe.MatchString(h.Status) || !shaRe.MatchString(h.SHA):
		out.Pipeline = Unread("GitLab's answer does not describe the head pipeline")
	default:
		// A pipeline passed only when it succeeded at the merge request's
		// own head: one for an older commit proves nothing about this one.
		out.Pipeline = map[string]any{
			"id": strconv.Itoa(h.ID), "sha": h.SHA, "status": h.Status, "passed": h.Status == "success" && h.SHA == a.SHA,
		}
	}
	return out
}

// Approvals parses GET /projects/:id/merge_requests/:iid/approvals.
func Approvals(status int, body []byte, project, iid int) map[string]any {
	if why := refused(status); why != "" {
		return Unread(why)
	}
	var a struct {
		IID      int   `json:"iid"`
		Project  int   `json:"project_id"`
		Approved *bool `json:"approved"`
		Left     *int  `json:"approvals_left"`
		By       []struct {
			User struct {
				Username string `json:"username"`
			} `json:"user"`
		} `json:"approved_by"`
	}
	if json.Unmarshal(body, &a) != nil {
		return Unread("GitLab's answer could not be read")
	}
	if a.IID != iid || a.Project != project || a.Approved == nil || a.Left == nil || *a.Left < 0 {
		return Unread("GitLab's answer does not describe the approvals")
	}
	by := make([]any, 0, len(a.By))
	for _, u := range a.By {
		if !userRe.MatchString(u.User.Username) {
			return Unread("GitLab's answer names an approver it does not identify")
		}
		by = append(by, u.User.Username)
	}
	return map[string]any{"approved": *a.Approved && *a.Left == 0, "approvals_left": int64(*a.Left), "approved_by": by}
}

// Protection parses GET /projects/:id/protected_branches/:name: a 404 is
// an unprotected branch, which GitLab answers for a branch no rule names.
func Protection(status int, body []byte, branch string) map[string]any {
	if status == 404 {
		return map[string]any{"protected": false, "allow_force_push": true, "code_owner_approval": false}
	}
	if why := refused(status); why != "" {
		return Unread(why)
	}
	var a struct {
		Name      string `json:"name"`
		Force     *bool  `json:"allow_force_push"`
		CodeOwner *bool  `json:"code_owner_approval_required"`
	}
	if json.Unmarshal(body, &a) != nil {
		return Unread("GitLab's answer could not be read")
	}
	if a.Name != branch || a.Force == nil {
		return Unread("GitLab's answer does not describe the branch")
	}
	return map[string]any{"protected": true, "allow_force_push": *a.Force, "code_owner_approval": a.CodeOwner != nil && *a.CodeOwner}
}

func refused(status int) string {
	switch {
	case status == 0:
		return "GitLab answered nothing"
	case status < 200 || status >= 300:
		return "GitLab answered HTTP " + strconv.Itoa(status)
	}
	return ""
}

// Unread is the value of a fact that was not read, with why.
func Unread(why string) map[string]any { return map[string]any{"unread": why} }
