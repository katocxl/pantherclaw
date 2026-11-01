// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gitlabfacts

import (
	"encoding/json/v2"
	"regexp"
	"strings"
)

// MergeRequestDeployment is the fact a merge's consequence rule reads
// (G0 M20 D258, D287, HR-521, T-229).
const MergeRequestDeployment = "gitlab.merge_request.deployment"

// EnvironmentsPageSize is how many environments one read asks for. A full
// page may hide more, so it is unread.
const EnvironmentsPageSize = 100

// CIConfigFile is the pipeline configuration a project without environments
// is read for.
const CIConfigFile = ".gitlab-ci.yml"

var environmentRe = regexp.MustCompile(`^[A-Za-z0-9_.-][A-Za-z0-9 _./-]{0,254}$`)

// quotedEscapeRe finds a backslash in a double-quoted YAML scalar, where an
// escape can spell a word a text check looks for (D294).
var quotedEscapeRe = regexp.MustCompile(`"[^"\n]*\\`)

// Environments parses GET /projects/:id/environments, stopped ones included:
// a job that deploys restarts a stopped environment. Its second result says
// why the answer could not be read, "" when it could.
func Environments(status int, body []byte) ([]any, string) {
	if why := refused(status); why != "" {
		return nil, why
	}
	var a []struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &a) != nil {
		return nil, "GitLab's answer could not be read"
	}
	if len(a) >= EnvironmentsPageSize {
		return nil, "the project has too many environments to read"
	}
	envs := make([]any, 0, len(a))
	for _, e := range a {
		if !environmentRe.MatchString(e.Name) {
			return nil, "GitLab's answer does not name an environment"
		}
		envs = append(envs, e.Name)
	}
	return envs, ""
}

// Deployment is the value of MergeRequestDeployment for a project with
// environments: a merge may deploy to each of them, so the state is verified
// only when the head pipeline passed at the head. Anything else is unread:
// the consequence rule is then unknown, at least a hold, so a deploy never
// starts from a pipeline that was not verified.
func Deployment(envs []any, pipeline map[string]any) map[string]any {
	if pipeline["passed"] != true {
		return Unread("the head pipeline did not pass at the head")
	}
	return map[string]any{"state": "verified", "environments": envs, "pipeline": pipeline["id"]}
}

// ProjectCI parses GET /projects/:id for a project with no environment
// (D289). Its result says why the project's pipeline cannot be read from
// .gitlab-ci.yml, "" when it can: a custom configuration path or Auto DevOps
// may deploy from elsewhere, and an answer that does not state both settings
// says neither, which a token without the rights to see them gets.
func ProjectCI(status int, body []byte, project int) string {
	if why := refused(status); why != "" {
		return why
	}
	var a struct {
		ID         int     `json:"id"`
		Path       *string `json:"ci_config_path"`
		AutoDevOps *bool   `json:"auto_devops_enabled"`
	}
	var keys map[string]any
	if json.Unmarshal(body, &a) != nil || json.Unmarshal(body, &keys) != nil {
		return "GitLab's answer could not be read"
	}
	_, hasPath := keys["ci_config_path"]
	switch {
	case a.ID != project || !hasPath || a.AutoDevOps == nil:
		return "GitLab's answer does not state how the project's pipeline is configured"
	case a.Path != nil && *a.Path != "":
		return "the project has a custom CI configuration path"
	case *a.AutoDevOps:
		return "the project uses Auto DevOps"
	}
	return ""
}

// NoEnvironments is the value of MergeRequestDeployment for a project with
// no environment yet, which its first deployment creates, from GET
// /projects/:id/repository/files/.gitlab-ci.yml/raw at one ref (D287): the
// gateway reads the head and the target branch, and both must read none. No
// file deploys nothing (state none). A file that mentions environment or
// include may deploy, a double-quoted scalar holding a backslash may spell
// either (D294), and one that could not be read may too: all are unread, so
// the merge is held. This is a text check, not a YAML parse: a comment that
// mentions either word, or a script with an escape, holds a merge too.
func NoEnvironments(status int, body []byte) map[string]any {
	none := map[string]any{"state": "none", "environments": []any{}}
	if status == 404 {
		return none
	}
	if why := refused(status); why != "" {
		return Unread(why)
	}
	text := strings.ToLower(string(body))
	if strings.Contains(text, "environment") || strings.Contains(text, "include") || quotedEscapeRe.MatchString(text) {
		return Unread("the pipeline configuration may deploy to a new environment")
	}
	return none
}
