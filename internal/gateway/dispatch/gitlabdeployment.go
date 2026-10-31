// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"net/url"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/gateway/gitlabfacts"
)

// readGitLabDeployment reads the deployment a merge may start: the project's
// environments, stopped ones included, and for a project with none how its
// pipeline is configured and its configuration at the head and at the target
// branch (G0 M20 D287, D289, T-229). Its second result says why GitLab could
// not be asked, "" when it could.
func (e *Engine) readGitLabDeployment(get func(string) (int, []byte, string), base string, project int, mr gitlabfacts.MergeRequest) (map[string]any, string) {
	status, body, why := get(base + "/environments?" + url.Values{"per_page": {strconv.Itoa(gitlabfacts.EnvironmentsPageSize)}}.Encode())
	if why != "" {
		return nil, why
	}
	envs, unread := gitlabfacts.Environments(status, body)
	if unread != "" {
		return gitlabfacts.Unread(unread), ""
	}
	if len(envs) > 0 {
		return gitlabfacts.Deployment(envs, mr.Pipeline), ""
	}
	head, ok := mr.Head["sha"].(string)
	if !ok {
		return gitlabfacts.Unread("the merge request's head was not read"), ""
	}
	if status, body, why = get(base); why != "" {
		return nil, why
	}
	if unread = gitlabfacts.ProjectCI(status, body, project); unread != "" {
		return gitlabfacts.Unread(unread), ""
	}
	if mr.TargetBranch == "" {
		return gitlabfacts.Unread("the merge request's target branch was not read"), ""
	}
	// The head and the target branch: the merge result holds both, and a job
	// on the target branch may deploy with none at the head.
	var deployment map[string]any
	for _, ref := range []string{head, mr.TargetBranch} {
		status, body, why = get(base + "/repository/files/" + gitlabfacts.CIConfigFile + "/raw?" + url.Values{"ref": {ref}}.Encode())
		if why != "" {
			return nil, why
		}
		if deployment = gitlabfacts.NoEnvironments(status, body); deployment["state"] != "none" {
			return deployment, ""
		}
	}
	return deployment, ""
}
