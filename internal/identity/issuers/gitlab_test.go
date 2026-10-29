// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package issuers_test

import (
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

const glRef = "gitlab.com/acme/agents/runner//.gitlab-ci.yml@refs/heads/main"

func glBinding() issuers.GitLabBinding {
	return issuers.GitLabBinding{
		Issuer: issuers.GitLabDefaultIssuer, ProjectID: "20", NamespaceID: "72", CIConfigRefURIs: []string{glRef},
	}
}

func glClaims(t *testing.T, mutate func(*string)) issuers.GitLabClaims {
	t.Helper()
	payload := `{"iss":"https://gitlab.com","aud":"pantherclaw:` + org.String() + `","jti":"235b3a54",
		"project_id":"20","project_path":"acme/agents/runner","namespace_id":"72","namespace_path":"acme/agents",
		"ref":"main","ref_type":"branch","ref_path":"refs/heads/main","ref_protected":"true","pipeline_source":"push",
		"runner_environment":"gitlab-hosted","sha":"` + sha + `","ci_config_ref_uri":"` + glRef + `","ci_config_sha":"` + sha + `",
		"job_source":"push","future_claim":{"x":1}}`
	if mutate != nil {
		mutate(&payload)
	}
	c, err := issuers.ParseGitLabClaims([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGitLabMatchesAPushOnAProtectedBranch(t *testing.T) {
	m, err := issuers.MatchGitLab(glBinding(), org, glClaims(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	want := issuers.Binding{"project_id": "20", "namespace_id": "72", "ci_config_ref_uri": glRef}
	if !m.Binding.Equal(want) || m.ReleaseDigest != "" {
		t.Fatalf("match = %+v", m)
	}
	// ref_protected may arrive as a JSON boolean, ids as JSON integers.
	c := glClaims(t, replace(`"ref_protected":"true"`, `"ref_protected":true`))
	c2 := glClaims(t, replace(`"project_id":"20"`, `"project_id":20`))
	for _, c := range []issuers.GitLabClaims{c, c2} {
		if _, err := issuers.MatchGitLab(glBinding(), org, c); err != nil {
			t.Errorf("equivalent encoding refused: %v", err)
		}
	}
	tag := glBinding()
	tag.CIConfigRefURIs = []string{"gitlab.com/acme/agents/runner//.gitlab-ci.yml@refs/tags/v1"}
	if _, err := issuers.MatchGitLab(tag, org, glClaims(t, func(s *string) {
		replace(`"ref_type":"branch"`, `"ref_type":"tag"`)(s)
		replace(glRef, tag.CIConfigRefURIs[0])(s)
	})); err != nil {
		t.Errorf("protected tag: %v", err)
	}
}

// TestHR461_GitLabPresetRules: protected refs only, no merge-request or
// external pull-request pipelines, numeric ids, the entry's own issuer and
// the org's exact audience — whatever the entry says.
// Covers: PN-002.3
func TestHR461_GitLabPresetRules(t *testing.T) {
	for name, mutate := range map[string]func(*string){
		"merge request pipeline":           replace(`"pipeline_source":"push"`, `"pipeline_source":"merge_request_event"`),
		"external pull request pipeline":   replace(`"pipeline_source":"push"`, `"pipeline_source":"external_pull_request_event"`),
		"unprotected ref":                  replace(`"ref_protected":"true"`, `"ref_protected":"false"`),
		"missing ref_protected":            replace(`"ref_protected":"true",`, ``),
		"ref type missing":                 replace(`"ref_type":"branch",`, ``),
		"ref type other":                   replace(`"ref_type":"branch"`, `"ref_type":"merge_request"`),
		"project recreated with new id":    replace(`"project_id":"20"`, `"project_id":"21"`),
		"namespace transferred":            replace(`"namespace_id":"72"`, `"namespace_id":"73"`),
		"project id missing":               replace(`"project_id":"20",`, ``),
		"other org's audience":             replace(org.String(), ids.New[ids.Org]().String()),
		"audience list with another value": replace(`"aud":"pantherclaw:`+org.String()+`"`, `"aud":["pantherclaw:`+org.String()+`","vault"]`),
		"rogue self-managed issuer":        replace(`"iss":"https://gitlab.com"`, `"iss":"https://gitlab.evil.test"`),
		"definition on an unpinned branch": replace(`"ci_config_ref_uri":"`+glRef, `"ci_config_ref_uri":"gitlab.com/acme/agents/runner//.gitlab-ci.yml@refs/heads/dev`),
		"definition from another project":  replace(`"ci_config_ref_uri":"`+glRef, `"ci_config_ref_uri":null,"x":"`),
	} {
		if _, err := issuers.MatchGitLab(glBinding(), org, glClaims(t, mutate)); !errors.Is(err, issuers.ErrRejected) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	pinned := glBinding()
	pinned.CIConfigSHAs, pinned.Environment, pinned.RunnerEnvironment = []string{"f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0"}, "production", "self-hosted"
	for name, b := range map[string]issuers.GitLabBinding{"sha": pinned} {
		if _, err := issuers.MatchGitLab(b, org, glClaims(t, nil)); !errors.Is(err, issuers.ErrRejected) {
			t.Errorf("%s pin did not bind", name)
		}
	}

	// Entries pin numeric ids and definitions on the issuer's own host.
	for name, mutate := range map[string]func(*issuers.GitLabBinding){
		"project path, not id": func(b *issuers.GitLabBinding) { b.ProjectID = "acme/agents/runner" },
		"no namespace id":      func(b *issuers.GitLabBinding) { b.NamespaceID = "" },
		"no definition":        func(b *issuers.GitLabBinding) { b.CIConfigRefURIs = nil },
		"wildcard ref": func(b *issuers.GitLabBinding) {
			b.CIConfigRefURIs = []string{"gitlab.com/acme/agents/runner//.gitlab-ci.yml@refs/heads/*"}
		},
		"merge request ref": func(b *issuers.GitLabBinding) {
			b.CIConfigRefURIs = []string{"gitlab.com/acme/agents/runner//.gitlab-ci.yml@refs/merge-requests/1/head"}
		},
		"other host": func(b *issuers.GitLabBinding) {
			b.CIConfigRefURIs = []string{"gitlab.evil.test/acme/agents/runner//.gitlab-ci.yml@refs/heads/main"}
		},
		"http issuer":      func(b *issuers.GitLabBinding) { b.Issuer = "http://gitlab.com" },
		"issuer with path": func(b *issuers.GitLabBinding) { b.Issuer = "https://gitlab.com/evil" },
		"bad runner":       func(b *issuers.GitLabBinding) { b.RunnerEnvironment = "any" },
	} {
		b := glBinding()
		mutate(&b)
		if err := b.Validate(); !errors.Is(err, issuers.ErrInvalidEntry) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// TestHR141_GitLabWideningIsDetected: added definitions, removed pins and
// a moved project widen; dropping a definition narrows.
func TestHR141_GitLabWideningIsDetected(t *testing.T) {
	base := glBinding()
	base.Environment = "production"
	if w := base.Widening(nil); len(w) != 1 {
		t.Fatalf("new entry: %v", w)
	}
	for name, mutate := range map[string]func(*issuers.GitLabBinding){
		"definition added": func(b *issuers.GitLabBinding) {
			b.CIConfigRefURIs = append(b.CIConfigRefURIs, "gitlab.com/acme/agents/runner//.gitlab-ci.yml@refs/tags/v1")
		},
		"environment pin removed": func(b *issuers.GitLabBinding) { b.Environment = "" },
		"project changed":         func(b *issuers.GitLabBinding) { b.ProjectID = "99" },
		"issuer changed":          func(b *issuers.GitLabBinding) { b.Issuer = "https://gitlab.example.com" },
	} {
		next := base
		next.CIConfigRefURIs = append([]string(nil), base.CIConfigRefURIs...)
		mutate(&next)
		if len(next.Widening(&base)) == 0 {
			t.Errorf("%s: not widening", name)
		}
	}
	narrower := base
	narrower.CIConfigSHAs = []string{sha}
	if w := narrower.Widening(&base); len(w) != 0 {
		t.Errorf("pinning a sha widened: %v", w)
	}
}
