// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package jirafacts

import "testing"

// TestHR522_JiraFactsNeverGuess: a service desk is external, other project
// types are not, and anything Jira did not clearly answer is unread, never
// internal (HR-160, HR-522).
//
// Covers: F756
func TestHR522_JiraFactsNeverGuess(t *testing.T) {
	for name, c := range map[string]struct {
		got      map[string]any
		external any
	}{
		"service desk project": {Project(200, []byte(`{"key":"HELP","projectTypeKey":"service_desk"}`), "HELP"), true},
		"software project":     {Project(200, []byte(`{"key":"ENG","projectTypeKey":"software"}`), "ENG"), false},
		"service desk issue": {Issue(200, []byte(`{"key":"HELP-1","fields":{"project":{"key":"HELP","projectTypeKey":"service_desk"},"security":null}}`),
			"HELP-1"), true},
		"restricted issue": {Issue(200, []byte(`{"key":"ENG-2","fields":{"project":{"key":"ENG","projectTypeKey":"software"},"security":{"name":"Internal"}}}`),
			"ENG-2"), false},
		"no type":           {Project(200, []byte(`{"key":"ENG"}`), "ENG"), nil},
		"other project":     {Project(200, []byte(`{"key":"OPS","projectTypeKey":"software"}`), "ENG"), nil},
		"other issue":       {Issue(200, []byte(`{"key":"ENG-3","fields":{"project":{"key":"ENG","projectTypeKey":"software"}}}`), "ENG-1"), nil},
		"issue moved":       {Issue(200, []byte(`{"key":"ENG-1","fields":{"project":{"key":"HELP","projectTypeKey":"service_desk"}}}`), "ENG-1"), nil},
		"no project fields": {Issue(200, []byte(`{"key":"ENG-1","fields":{}}`), "ENG-1"), nil},
		"empty level":       {Issue(200, []byte(`{"key":"ENG-1","fields":{"project":{"key":"ENG","projectTypeKey":"software"},"security":{}}}`), "ENG-1"), nil},
		"not found":         {Project(404, []byte(`{"errorMessages":["No project"]}`), "ENG"), nil},
		"unauthorized":      {Issue(401, nil, "ENG-1"), nil},
		"rate limited":      {Issue(429, nil, "ENG-1"), nil},
		"nothing":           {Issue(0, nil, "ENG-1"), nil},
		"not json":          {Project(200, []byte(`<html>`), "ENG"), nil},
	} {
		ext, ok := c.got["external"]
		if c.external == nil {
			if ok || c.got["unread"] == nil {
				t.Errorf("%s: %v", name, c.got)
			}
			continue
		}
		if !ok || ext != c.external {
			t.Errorf("%s: %v", name, c.got)
		}
	}
	if v := Issue(200, []byte(`{"key":"ENG-2","fields":{"project":{"key":"ENG","projectTypeKey":"software"},"security":{"name":"Internal"}}}`), "ENG-2"); v["security_level"] != "Internal" {
		t.Fatalf("security level: %v", v)
	}
}
