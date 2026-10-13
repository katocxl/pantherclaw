// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package githubfacts

import (
	"slices"
	"strings"
	"testing"
)

const deployMain = `name: deploy
on:
  push:
    branches: [main, 'release/**']
  workflow_dispatch:
jobs:
  test:
    runs-on: ubuntu-latest
    steps: [{run: make test}]
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps: [{run: make deploy}]
`

// TestHR206_DeployTriggers: a push to a branch a workflow deploys on push
// is triggered with its environments; other branches are none; anything
// the parser does not evaluate is unknown, never none.
func TestHR206_DeployTriggers(t *testing.T) {
	files := map[string][]byte{".github/workflows/deploy.yml": []byte(deployMain), ".github/workflows/ci.yml": []byte("on: [push]\njobs:\n  t: {runs-on: x}\n")}
	for branch, want := range map[string]string{"main": "triggered", "release/2026/10": "triggered", "fix/a": "none", "mainline": "none"} {
		got := DeployTriggers(files, branch, "abc")
		if got.State != want {
			t.Errorf("%s: %+v", branch, got)
		}
	}
	got := DeployTriggers(files, "main", "abc")
	if !slices.Equal(got.Environments, []string{"production"}) || len(got.Workflows) != 2 || got.Unknown != "" {
		t.Fatalf("main: %+v", got)
	}
	for name, wf := range map[string]string{
		"workflow_run":         "on:\n  workflow_run: {workflows: [x]}\njobs: {d: {environment: production}}\n",
		"repository_dispatch":  "on: [push, repository_dispatch]\njobs: {d: {environment: production}}\n",
		"expression branch":    "on:\n  push:\n    branches: ['${{ vars.B }}']\njobs: {d: {runs-on: x}}\n",
		"expression env":       "on: push\njobs: {d: {environment: '${{ inputs.env }}'}}\n",
		"reusable workflow":    "on: push\njobs: {d: {uses: org/repo/.github/workflows/deploy.yml@main}}\n",
		"character class":      "on:\n  push:\n    branches: ['ma[i]n']\njobs: {d: {runs-on: x}}\n",
		"anchor":               "on: &p push\njobs: {d: {runs-on: x}}\n",
		"merge key":            "x: &a {environment: production}\non: push\njobs:\n  d:\n    <<: *a\n",
		"tag":                  "on: !!str push\njobs: {d: {runs-on: x}}\n",
		"not YAML":             "on: [push\n",
		"duplicate key":        "on: push\non: pull_request\njobs: {}\n",
		"environment, no name": "on: push\njobs: {d: {environment: {url: x}}}\n",
		"branches and ignore":  "on:\n  push:\n    branches: [main]\n    branches-ignore: [x]\njobs: {d: {runs-on: x}}\n",
		"no jobs":              "on: push\n",
		// Events a merge, a write or a branch creation can start besides
		// push, and events chained from one (HR-206).
		"merge deploys":        "on:\n  pull_request:\n    types: [closed]\n    branches: [main]\njobs:\n  d:\n    if: github.event.pull_request.merged == true\n    environment: production\n",
		"pull_request_target":  "on:\n  pull_request_target: {types: [closed]}\njobs: {d: {environment: production}}\n",
		"create":               "on: create\njobs: {d: {environment: preview}}\n",
		"delete":               "on: [delete]\njobs: {d: {environment: preview}}\n",
		"merge_group":          "on: merge_group\njobs: {d: {environment: production}}\n",
		"check_suite":          "on: {check_suite: {types: [completed]}}\njobs: {d: {environment: production}}\n",
		"status":               "on: status\njobs: {d: {environment: production}}\n",
		"deployment":           "on: [deployment, deployment_status]\njobs: {d: {runs-on: x}}\n",
		"release":              "on: {release: {types: [published]}}\njobs: {d: {environment: production}}\n",
		"page_build":           "on: page_build\njobs: {d: {runs-on: x}}\n",
		"an event GitHub adds": "on: future_event\njobs: {d: {runs-on: x}}\n",
	} {
		got := DeployTriggers(map[string][]byte{".github/workflows/x.yml": []byte(wf)}, "main", "abc")
		if got.State != "unknown" || got.Unknown == "" {
			t.Errorf("%s: %+v", name, got)
		}
	}
	many := map[string][]byte{}
	for i := range MaxWorkflowFiles + 1 {
		many[".github/workflows/"+strings.Repeat("a", i+1)+".yml"] = []byte("on: pull_request\njobs: {}\n")
	}
	if got := DeployTriggers(many, "main", "abc"); got.State != "unknown" {
		t.Fatalf("too many files: %+v", got)
	}
	big := map[string][]byte{".github/workflows/x.yml": []byte("on: push\n# " + strings.Repeat("x", MaxWorkflowBytes))}
	if got := DeployTriggers(big, "main", "abc"); got.State != "unknown" {
		t.Fatalf("a file too large: %+v", got)
	}
}

// TestDeployTriggerFilters: branch filters follow GitHub's order with
// negations, ignore lists, and tag-only pushes.
func TestDeployTriggerFilters(t *testing.T) {
	for wf, cases := range map[string]map[string]string{
		"on:\n  push:\n    branches: ['**', '!wip/*']\njobs: {d: {environment: prod}}\n": {"main": "triggered", "wip/x": "none", "wip/x/y": "triggered"},
		"on:\n  push:\n    branches-ignore: [docs/*]\njobs: {d: {environment: prod}}\n":  {"main": "triggered", "docs/a": "none"},
		"on:\n  push:\n    tags: [v*]\njobs: {d: {environment: prod}}\n":                 {"main": "none"},
		"on:\n  push:\n    paths: [src/**]\njobs: {d: {environment: {name: prod}}}\n":    {"main": "triggered"},
		"on:\n  pull_request:\n    branches: [main]\njobs: {d: {environment: prod}}\n":   {"main": "unknown"}, // it runs when the merge closes it
		"on: [schedule, workflow_dispatch, issues]\njobs: {d: {environment: prod}}\n":    {"main": "none"},
		"on:\n  push:\n    branches: main\njobs: {d: {environment: prod}}\n":             {"main": "triggered", "maint": "none"},
		// ? and + apply to the character before them, as GitHub's filters do.
		"on:\n  push:\n    branches: ['release-?']\njobs: {d: {environment: prod}}\n": {"release": "triggered", "release-": "triggered", "release-1": "none"},
		"on:\n  push:\n    branches: [v+1]\njobs: {d: {environment: prod}}\n":         {"v1": "triggered", "vv1": "triggered", "1": "none"},
		"on:\n  push:\n    branches: ['*?']\njobs: {d: {environment: prod}}\n":        {"main": "unknown"},
	} {
		for branch, want := range cases {
			if got := DeployTriggers(map[string][]byte{"w.yml": []byte(wf)}, branch, "abc"); got.State != want {
				t.Errorf("%q on %s: %+v, want %s", wf, branch, got, want)
			}
		}
	}
}

// FuzzWorkflowTriggers: whatever the files hold, the parser never panics
// and answers one of its three states; a file it cannot read, or one
// naming an event other than push that a ref move can start, is never
// "none" (HR-206).
func FuzzWorkflowTriggers(f *testing.F) {
	f.Add([]byte(deployMain), "main")
	f.Add([]byte("on: [push, workflow_run]\njobs: {}\n"), "main")
	f.Add([]byte("on: push\njobs: {d: {uses: a/b/c.yml@v1}}\n"), "x")
	f.Add([]byte("on: &a push\njobs: {}\n"), "main")
	f.Add([]byte("on:\n  push:\n    branches: ['re?l+', '!x*']\njobs: {d: {environment: p}}\n"), "rel")
	f.Add([]byte("on:\n  pull_request:\n    types: [closed]\njobs: {d: {if: github.event.pull_request.merged, environment: p}}\n"), "main")
	f.Add([]byte("on: [create, schedule]\njobs: {d: {environment: p}}\n"), "feature")
	f.Add([]byte("on: {workflow_dispatch: {}, check_run: {}}\njobs: {}\n"), "main")
	f.Fuzz(func(t *testing.T, raw []byte, branch string) {
		got := DeployTriggers(map[string][]byte{".github/workflows/f.yml": raw}, branch, "abc")
		if !slices.Contains([]string{"triggered", "none", "unknown"}, got.State) || (got.State == "unknown") != (got.Unknown != "") {
			t.Fatalf("state %+v", got)
		}
		doc, err := ParseWorkflowYAML(raw)
		if err != nil && got.State != "unknown" {
			t.Fatalf("an unreadable file gave %s: %q", got.State, raw)
		}
		root, ok := doc.(map[string]any)
		if err != nil || !ok {
			return
		}
		if on, ok := root["on"].(map[string]any); ok {
			for name := range on {
				if name != "push" && !unmoved[name] && got.State == "none" {
					t.Fatalf("a %s trigger gave none: %q", name, raw)
				}
			}
		}
	})
}
