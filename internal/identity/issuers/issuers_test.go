// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package issuers_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var org = ids.New[ids.Org]()

const (
	repoRef  = "octo-org/agent-repo/.github/workflows/agent.yml@refs/heads/main"
	sharedWF = "octo-org/workflows/.github/workflows/agent.yml@refs/tags/v1"
	sha      = "0123456789abcdef0123456789abcdef01234567"
)

func ghBinding() issuers.GitHubBinding {
	return issuers.GitHubBinding{
		RepositoryID: "123456", RepositoryOwnerID: "7890", JobType: issuers.JobWorkflow, WorkflowRefs: []string{repoRef},
	}
}

func ghClaims(t *testing.T, mutate func(*string)) issuers.GitHubClaims {
	t.Helper()
	payload := `{"iss":"https://token.actions.githubusercontent.com","aud":"pantherclaw:` + org.String() + `",
		"jti":"j1","repository_id":"123456","repository_owner_id":"7890","ref":"refs/heads/main",
		"ref_protected":"true","event_name":"push","workflow_ref":"` + repoRef + `","workflow_sha":"` + sha + `",
		"job_workflow_ref":"` + repoRef + `","job_workflow_sha":"` + sha + `","runner_environment":"github-hosted",
		"repository":"octo-org/agent-repo","future_claim":{"x":1}}`
	if mutate != nil {
		mutate(&payload)
	}
	c, err := issuers.ParseGitHubClaims([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func replace(from, to string) func(*string) {
	return func(s *string) { *s = strings.Replace(*s, from, to, 1) }
}

func TestGitHubMatchesAPushOnAProtectedBranch(t *testing.T) {
	m, err := issuers.MatchGitHub(ghBinding(), org, ghClaims(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	want := issuers.Binding{"repository_id": "123456", "repository_owner_id": "7890", "workflow": repoRef}
	if !m.Binding.Equal(want) || m.ReleaseDigest != "" {
		t.Fatalf("match = %+v", m)
	}
}

// TestHR093_GitHubPresetRules: the rules no configuration can disable.
func TestHR093_GitHubPresetRules(t *testing.T) {
	for name, mutate := range map[string]func(*string){
		"pull_request from a fork":          replace(`"event_name":"push"`, `"event_name":"pull_request"`),
		"pull_request in the same repo":     replace(`"ref":"refs/heads/main"`, `"ref":"refs/heads/main","head_ref":"feature"`),
		"pull_request_target":               replace(`"event_name":"push"`, `"event_name":"pull_request_target"`),
		"pull_request_review (refs/pull/)":  replace(`"ref":"refs/heads/main"`, `"ref":"refs/pull/42/merge"`),
		"unprotected ref":                   replace(`"ref_protected":"true"`, `"ref_protected":"false"`),
		"missing ref_protected":             replace(`"ref_protected":"true",`, ``),
		"repository recreated with new id":  replace(`"repository_id":"123456"`, `"repository_id":"999999"`),
		"owner transferred":                 replace(`"repository_owner_id":"7890"`, `"repository_owner_id":"1111"`),
		"other org's audience":              replace(org.String(), ids.New[ids.Org]().String()),
		"audience list with another value":  replace(`"aud":"pantherclaw:`+org.String()+`"`, `"aud":["pantherclaw:`+org.String()+`","sts.amazonaws.com"]`),
		"unconfigured issuer":               replace(`https://token.actions.githubusercontent.com`, `https://token.actions.githubusercontent.com/evil-enterprise`),
		"workflow on an unpinned branch":    replace(`"workflow_ref":"`+repoRef, `"workflow_ref":"octo-org/agent-repo/.github/workflows/agent.yml@refs/heads/dev`),
		"ordinary entry, reusable workflow": replace(`"job_workflow_ref":"`+repoRef, `"job_workflow_ref":"`+sharedWF),
	} {
		c := ghClaims(t, mutate)
		if name == "pull_request in the same repo" {
			c.EventName = "pull_request"
		}
		if _, err := issuers.MatchGitHub(ghBinding(), org, c); !errors.Is(err, issuers.ErrRejected) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// TestHR093_JobTypesBindOnTheirOwnClaim: an ordinary job binds on
// workflow_ref, a reusable-workflow job on job_workflow_ref; pinned shas
// must match.
func TestHR093_JobTypesBindOnTheirOwnClaim(t *testing.T) {
	reusable := ghBinding()
	reusable.JobType, reusable.WorkflowRefs, reusable.WorkflowSHAs = issuers.JobReusable, []string{sharedWF}, []string{sha}
	c := ghClaims(t, replace(`"job_workflow_ref":"`+repoRef, `"job_workflow_ref":"`+sharedWF))
	m, err := issuers.MatchGitHub(reusable, org, c)
	if err != nil || m.Binding["workflow"] != sharedWF {
		t.Fatalf("reusable job: %+v, %v", m, err)
	}
	if _, err := issuers.MatchGitHub(ghBinding(), org, c); !errors.Is(err, issuers.ErrRejected) {
		t.Error("an ordinary-job entry accepted a reusable-workflow job")
	}
	pinned := ghBinding()
	pinned.WorkflowSHAs = []string{strings.Repeat("f", 40)}
	if _, err := issuers.MatchGitHub(pinned, org, ghClaims(t, nil)); !errors.Is(err, issuers.ErrRejected) {
		t.Error("a pinned sha did not bind")
	}
}

// TestHR140_EntriesPinImmutableClaims: names, wildcards, pull refs and
// missing ids are refused.
func TestHR140_EntriesPinImmutableClaims(t *testing.T) {
	for name, mutate := range map[string]func(*issuers.GitHubBinding){
		"no repository id":      func(b *issuers.GitHubBinding) { b.RepositoryID = "" },
		"repository name as id": func(b *issuers.GitHubBinding) { b.RepositoryID = "octo-org/agent-repo" },
		"no owner id":           func(b *issuers.GitHubBinding) { b.RepositoryOwnerID = "" },
		"no workflow refs":      func(b *issuers.GitHubBinding) { b.WorkflowRefs = nil },
		"wildcard ref": func(b *issuers.GitHubBinding) {
			b.WorkflowRefs = []string{"octo-org/agent-repo/.github/workflows/*@refs/heads/main"}
		},
		"pull ref": func(b *issuers.GitHubBinding) {
			b.WorkflowRefs = []string{"octo-org/agent-repo/x.yml@refs/pull/1/merge"}
		},
		"ref without branch":       func(b *issuers.GitHubBinding) { b.WorkflowRefs = []string{"octo-org/agent-repo/x.yml@main"} },
		"unknown job type":         func(b *issuers.GitHubBinding) { b.JobType = "any" },
		"short sha":                func(b *issuers.GitHubBinding) { b.WorkflowSHAs = []string{"abc"} },
		"unknown runner env value": func(b *issuers.GitHubBinding) { b.RunnerEnvironment = "laptop" },
	} {
		b := ghBinding()
		mutate(&b)
		if err := b.Validate(); !errors.Is(err, issuers.ErrInvalidEntry) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	kb := k8sBinding()
	kb.ServiceAccountUID = ""
	if err := kb.Validate(); !errors.Is(err, issuers.ErrInvalidEntry) {
		t.Error("a Kubernetes entry without the service-account UID was accepted")
	}
}

// TestHR141_WideningIsDetected: added refs, removed pins and removed sha
// lists widen; removing refs or adding pins narrows.
func TestHR141_WideningIsDetected(t *testing.T) {
	base := ghBinding()
	base.WorkflowSHAs, base.Environment = []string{sha}, "agents"
	if w := base.Widening(nil); len(w) != 1 {
		t.Errorf("a new entry must widen: %v", w)
	}
	for name, tc := range map[string]struct {
		mutate func(*issuers.GitHubBinding)
		widens bool
	}{
		"same":                 {func(*issuers.GitHubBinding) {}, false},
		"add a ref":            {func(b *issuers.GitHubBinding) { b.WorkflowRefs = append(b.WorkflowRefs, sharedWF) }, true},
		"drop all sha pins":    {func(b *issuers.GitHubBinding) { b.WorkflowSHAs = nil }, true},
		"add a sha":            {func(b *issuers.GitHubBinding) { b.WorkflowSHAs = append(b.WorkflowSHAs, strings.Repeat("f", 40)) }, true},
		"remove environment":   {func(b *issuers.GitHubBinding) { b.Environment = "" }, true},
		"change environment":   {func(b *issuers.GitHubBinding) { b.Environment = "prod" }, true},
		"change repository id": {func(b *issuers.GitHubBinding) { b.RepositoryID = "1" }, true},
		"pin runner":           {func(b *issuers.GitHubBinding) { b.RunnerEnvironment = "github-hosted" }, false},
	} {
		next := base
		next.WorkflowRefs = append([]string(nil), base.WorkflowRefs...)
		next.WorkflowSHAs = append([]string(nil), base.WorkflowSHAs...)
		tc.mutate(&next)
		if got := len(next.Widening(&base)) > 0; got != tc.widens {
			t.Errorf("%s: widens = %v (%v)", name, got, next.Widening(&base))
		}
	}
	k := k8sBinding()
	k.ImageDigests = []string{digest}
	k2 := k
	k2.ImageDigests = nil
	if len(k2.Widening(&k)) == 0 {
		t.Error("dropping Kubernetes digest pins must widen")
	}
}

// TestHR143_AttestationLifetimeAndReplayKeys: tokens must be current and
// live at most an hour; replay keys separate jti and whole-token keys.
func TestHR143_AttestationLifetimeAndReplayKeys(t *testing.T) {
	now := time.Unix(1791457200, 0)
	if err := issuers.Lifetime(now.Add(-time.Minute), time.Time{}, now.Add(9*time.Minute), now); err != nil {
		t.Fatalf("valid token: %v", err)
	}
	for name, tc := range map[string][3]time.Time{
		"expired":          {now.Add(-20 * time.Minute), {}, now.Add(-10 * time.Minute)},
		"over one hour":    {now.Add(-time.Minute), {}, now.Add(2 * time.Hour)},
		"issued in future": {now.Add(10 * time.Minute), {}, now.Add(20 * time.Minute)},
		"no exp":           {now, {}, {}},
	} {
		if err := issuers.Lifetime(tc[0], tc[1], tc[2], now); !errors.Is(err, issuers.ErrRejected) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	w, err := issuers.ParseWindow([]byte(`{"iat":1791457140,"exp":1791457740,"jti":"j1","nbf":1791457140}`))
	if err != nil || w.JTI != "j1" || !w.ExpiresAt.Equal(now.Add(9*time.Minute)) || w.Check(now) != nil {
		t.Fatalf("window: %+v, %v", w, err)
	}
	for _, p := range []string{`{"iat":1791457140}`, `{"iat":1791457140,"exp":1791464400}`, `{"iat":1.5,"exp":2}`, `{"exp":1,"exp":2}`} {
		if w, err := issuers.ParseWindow([]byte(p)); err == nil && w.Check(now) == nil {
			t.Errorf("%s: accepted", p)
		}
	}
	if issuers.ReplayKey("abc", "") == issuers.ReplayKey("", "abc") || issuers.ReplayKey("", "t1") == issuers.ReplayKey("", "t2") {
		t.Fatal("replay keys collide")
	}
	// "sig" and "sih" differ only in unused bits: both decode to the same
	// two bytes, so a token without a jti keeps its key (no second use).
	if issuers.ReplayKey("", "e30.e30.sig") != issuers.ReplayKey("", "e30.e30.sih") {
		t.Fatal("a non-canonical encoding of a token got its own replay key")
	}
}

func k8sBinding() issuers.KubernetesBinding {
	return issuers.KubernetesBinding{
		Cluster: "prod", Namespace: "agents", ServiceAccountName: "coder",
		ServiceAccountUID: "6f1d2c3b-4a59-4e2b-9c1d-0a1b2c3d4e5f",
	}
}

const digest = "sha256:" + "ab" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd"

func review() issuers.TokenReview {
	return issuers.TokenReview{
		Authenticated: true, Audiences: []string{issuers.Audience(org)},
		Username: "system:serviceaccount:agents:coder", UID: "6f1d2c3b-4a59-4e2b-9c1d-0a1b2c3d4e5f",
		PodName: "coder-7d9f", PodUID: "11111111-2222-4333-8444-555555555555",
	}
}

func pod() issuers.Pod {
	return issuers.Pod{
		Namespace: "agents", Name: "coder-7d9f", UID: "11111111-2222-4333-8444-555555555555", Phase: "Running",
		ImageIDs: []string{"docker-pullable://ghcr.io/acme/agent@" + digest},
	}
}

// TestHR144_KubernetesPresetRules: the token must be for this org, this
// service account (by UID) and a live pod; the digest comes from the pod.
func TestHR144_KubernetesPresetRules(t *testing.T) {
	m, err := issuers.MatchKubernetes(k8sBinding(), org, review(), pod())
	if err != nil || m.ReleaseDigest != digest || m.Binding["service_account_uid"] == "" {
		t.Fatalf("match = %+v, %v", m, err)
	}
	pinned := k8sBinding()
	pinned.ImageRepositories, pinned.ImageDigests = []string{"ghcr.io/acme/agent"}, []string{digest}
	if _, err := issuers.MatchKubernetes(pinned, org, review(), pod()); err != nil {
		t.Fatalf("pinned image: %v", err)
	}
	for name, tc := range map[string]struct {
		b issuers.KubernetesBinding
		r func(*issuers.TokenReview)
		p func(*issuers.Pod)
	}{
		"not authenticated":        {k8sBinding(), func(r *issuers.TokenReview) { r.Authenticated = false }, nil},
		"other org's audience":     {k8sBinding(), func(r *issuers.TokenReview) { r.Audiences = []string{issuers.Audience(ids.New[ids.Org]())} }, nil},
		"other namespace":          {k8sBinding(), func(r *issuers.TokenReview) { r.Username = "system:serviceaccount:other:coder" }, nil},
		"recreated account":        {k8sBinding(), func(r *issuers.TokenReview) { r.UID = "aaaaaaaa-4a59-4e2b-9c1d-0a1b2c3d4e5f" }, nil},
		"token not bound to a pod": {k8sBinding(), func(r *issuers.TokenReview) { r.PodUID = "" }, nil},
		"pod deleted and replaced": {k8sBinding(), nil, func(p *issuers.Pod) { p.UID = "99999999-2222-4333-8444-555555555555" }},
		"pod not running":          {k8sBinding(), nil, func(p *issuers.Pod) { p.Phase = "Succeeded" }},
		"sidecar makes two images": {k8sBinding(), nil, func(p *issuers.Pod) { p.ImageIDs = append(p.ImageIDs, p.ImageIDs[0]) }},
		"image by tag only":        {k8sBinding(), nil, func(p *issuers.Pod) { p.ImageIDs = []string{"ghcr.io/acme/agent:latest"} }},
		"unlisted image":           {pinned, nil, func(p *issuers.Pod) { p.ImageIDs = []string{"ghcr.io/evil/agent@" + digest} }},
		"unlisted digest": {pinned, nil, func(p *issuers.Pod) {
			p.ImageIDs = []string{"ghcr.io/acme/agent@sha256:" + strings.Repeat("0", 64)}
		}},
	} {
		r, p := review(), pod()
		if tc.r != nil {
			tc.r(&r)
		}
		if tc.p != nil {
			tc.p(&p)
		}
		if _, err := issuers.MatchKubernetes(tc.b, org, r, p); !errors.Is(err, issuers.ErrRejected) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// TestHR147_BindingsCompareExactly: a re-attestation must carry exactly the
// enrolled binding.
func TestHR147_BindingsCompareExactly(t *testing.T) {
	a := issuers.Binding{"repository_id": "1", "workflow": repoRef}
	for _, b := range []issuers.Binding{
		{"repository_id": "1"},
		{"repository_id": "1", "workflow": sharedWF},
		{"repository_id": "1", "workflow": repoRef, "extra": "x"},
	} {
		if a.Equal(b) || b.Equal(a) {
			t.Errorf("%v equals %v", a, b)
		}
	}
	if !a.Equal(issuers.Binding{"workflow": repoRef, "repository_id": "1"}) {
		t.Error("equal bindings differ")
	}
}

// FuzzGitHubClaims: arbitrary payloads never panic and never match.
func FuzzGitHubClaims(f *testing.F) {
	f.Add(`{"iss":"x"}`)
	f.Fuzz(func(t *testing.T, payload string) {
		c, err := issuers.ParseGitHubClaims([]byte(payload))
		if err != nil {
			return
		}
		b := ghBinding()
		if _, err := issuers.MatchGitHub(b, org, c); err == nil && (c.RepositoryID != b.RepositoryID ||
			c.RepositoryOwnerID != b.RepositoryOwnerID || c.WorkflowRef != repoRef || c.EventName == "pull_request") {
			t.Fatalf("payload %q matched", payload)
		}
	})
}
