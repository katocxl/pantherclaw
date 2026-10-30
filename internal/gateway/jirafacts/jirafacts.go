// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package jirafacts reads the Jira facts pc.jira names (G0 M20 D254):
// whether a write lands in a customer-visible project, a service desk whose
// customers read what is written there. It parses Jira's project and issue
// answers and never guesses: a project or issue it cannot read is unread,
// so the decision sees the fact missing (HR-160), never an internal
// project.
package jirafacts

import (
	"encoding/json/v2"
	"regexp"
	"strconv"
	"strings"
)

// Target types the facts are about, each with its own fact: the fact store
// keeps one subject type per fact name and connection (G0 M20 D275).
const (
	IssueTarget   = "jira_issue"
	ProjectTarget = "jira_project"
)

// IssueExternal and ProjectExternal are the facts a write's prerequisite and
// its consequence rule name: the same value, about an issue or a project.
const (
	IssueExternal   = "jira.issue.external"
	ProjectExternal = "jira.project.external"
)

// ServiceDesk is the project type whose customers read the project.
const ServiceDesk = "service_desk"

var (
	projectRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,9}$`)
	typeRe    = regexp.MustCompile(`^[a-z_]{1,32}$`)
)

type project struct {
	Key  string  `json:"key"`
	Type *string `json:"projectTypeKey"`
}

// Project parses a project answer for key into the fact's value:
// {external, project, project_type}.
func Project(status int, body []byte, key string) map[string]any {
	if why := refused(status); why != "" {
		return Unread(why)
	}
	var p project
	if json.Unmarshal(body, &p) != nil {
		return Unread("Jira's answer could not be read")
	}
	if p.Key != key {
		return Unread("Jira's answer does not describe the project")
	}
	return value(p, nil)
}

// Issue parses an issue answer for key into the fact's value: the issue's
// project as Project gives it, and the issue's security level (its name,
// or "" for none).
func Issue(status int, body []byte, key string) map[string]any {
	if why := refused(status); why != "" {
		return Unread(why)
	}
	var a struct {
		Key    string `json:"key"`
		Fields *struct {
			Project  *project `json:"project"`
			Security *struct {
				Name string `json:"name"`
			} `json:"security"`
		} `json:"fields"`
	}
	if json.Unmarshal(body, &a) != nil {
		return Unread("Jira's answer could not be read")
	}
	proj, _, _ := strings.Cut(key, "-")
	if a.Key != key || a.Fields == nil || a.Fields.Project == nil || a.Fields.Project.Key != proj {
		return Unread("Jira's answer does not describe the issue")
	}
	level := ""
	if a.Fields.Security != nil {
		level = a.Fields.Security.Name
		if level == "" || len(level) > 255 {
			return Unread("Jira's answer does not name the issue's security level")
		}
	}
	return value(*a.Fields.Project, &level)
}

func value(p project, level *string) map[string]any {
	if !projectRe.MatchString(p.Key) || p.Type == nil || !typeRe.MatchString(*p.Type) {
		return Unread("Jira's answer does not give the project's type")
	}
	v := map[string]any{"external": *p.Type == ServiceDesk, "project": p.Key, "project_type": *p.Type}
	if level != nil {
		v["security_level"] = *level
	}
	return v
}

func refused(status int) string {
	switch {
	case status == 0:
		return "Jira answered nothing"
	case status == 401 || status == 403:
		return "Jira refused the read: HTTP " + strconv.Itoa(status)
	case status == 404:
		return "Jira could not find it or the credential may not see it"
	case status < 200 || status >= 300:
		return "Jira answered HTTP " + strconv.Itoa(status)
	}
	return ""
}

// Unread is the value of a fact that was not read, with why.
func Unread(why string) map[string]any { return map[string]any{"unread": why} }

// Fact is the fact about a target of targetType, "" for any other type.
func Fact(targetType string) string {
	switch targetType {
	case IssueTarget:
		return IssueExternal
	case ProjectTarget:
		return ProjectExternal
	}
	return ""
}
