// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gitlabfacts

import (
	"encoding/json/v2"
	"regexp"
)

// MergeRequestDeployment is the fact a merge's consequence rule reads
// (G0 M20 D258, HR-521, T-229).
const MergeRequestDeployment = "gitlab.merge_request.deployment"

// EnvironmentsPageSize is how many environments one read asks for. A full
// page may hide more, so it is unread.
const EnvironmentsPageSize = 100

var environmentRe = regexp.MustCompile(`^[A-Za-z0-9_.-][A-Za-z0-9 _./-]{0,254}$`)

// Deployment parses GET /projects/:id/environments and the merge request's
// pipeline fact into the value of MergeRequestDeployment. A project with no
// environment deploys nothing (state none). With some, a merge may deploy
// to each of them, and the state is verified only when the head pipeline
// passed at the head. Anything else is unread: the consequence rule is then
// unknown, at least a hold, so a deploy never starts from a pipeline that
// was not verified.
func Deployment(status int, body []byte, pipeline map[string]any) map[string]any {
	if why := refused(status); why != "" {
		return Unread(why)
	}
	var a []struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &a) != nil {
		return Unread("GitLab's answer could not be read")
	}
	if len(a) >= EnvironmentsPageSize {
		return Unread("the project has too many environments to read")
	}
	envs := make([]any, 0, len(a))
	for _, e := range a {
		if !environmentRe.MatchString(e.Name) {
			return Unread("GitLab's answer does not name an environment")
		}
		envs = append(envs, e.Name)
	}
	if len(envs) == 0 {
		return map[string]any{"state": "none", "environments": envs}
	}
	if pipeline["passed"] != true {
		return Unread("the head pipeline did not pass at the head")
	}
	return map[string]any{"state": "verified", "environments": envs, "pipeline": pipeline["id"]}
}
