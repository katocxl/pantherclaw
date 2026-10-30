// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pcgitlab_test

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	pcgitlab "github.com/katocxl/pantherclaw/packages/pc-gitlab"
)

const head = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

var tc = mapping.Context{
	Org: "01920000-0000-7000-8000-000000000001", Env: "01920000-0000-7000-8000-000000000002",
	RunID: "01920000-0000-7000-8000-000000000003", ActionID: "01920000-0000-7000-8000-000000000004",
	AgentInstance: "01920000-0000-7000-8000-000000000005",
}

func decode(t *testing.T) *domain.Package {
	t.Helper()
	p, err := manifest.Decode(pcgitlab.Package)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestHR521_GitLabMergeIsOneActionOnEveryRoute: a merge through the REST API
// and through the MCP tool is the same action on the same merge request,
// bound to the same head, so a grant or policy that bounds merge requests
// bounds both routes; a project named by its encoded path is not mapped
// (F756, route and tool parity).
//
// Covers: F756
func TestHR521_GitLabMergeIsOneActionOnEveryRoute(t *testing.T) {
	m, err := mapping.New(decode(t), celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	h, err := m.HTTPRequest(ctx, tc, "PUT", "/api/v4/projects/42/merge_requests/7/merge", "", "application/json",
		[]byte(`{"sha":"`+head+`","squash":true}`))
	if err != nil {
		t.Fatal(err)
	}
	c, err := m.MCP(ctx, tc, "gitlab_merge_merge_request", []byte(`{"project_id":42,"merge_request_iid":7,"sha":"`+head+`","squash":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if h.Action.DedupeKey != c.Action.DedupeKey || h.Action.Route != c.Action.Route || string(h.Action.Params) != string(c.Action.Params) ||
		h.Action.Target != c.Action.Target {
		t.Fatalf("routes differ:\n%s\n%s", h.Canonical, c.Canonical)
	}
	if a := h.Action; a.Operation != "gitlab.merge_request.merge" || a.Target.ID != "42!7" || a.Target.Type != "gitlab_merge_request" {
		t.Fatalf("action: %s", h.Canonical)
	}
	r, err := m.MCP(ctx, tc, "gitlab_get_merge_request", []byte(`{"project_id":42,"merge_request_iid":7}`))
	hr, herr := m.HTTPRequest(ctx, tc, "GET", "/api/v4/projects/42/merge_requests/7", "", "", nil)
	if err != nil || herr != nil || r.Action.Target != hr.Action.Target || r.Action.Route != hr.Action.Route {
		t.Fatalf("read: %v %v", err, herr)
	}
	for name, path := range map[string]string{
		"encoded path": "/api/v4/projects/acme%2Fpayments/merge_requests/7/merge",
		"plain path":   "/api/v4/projects/acme/payments/merge_requests/7/merge",
	} {
		if _, err := m.HTTPRequest(ctx, tc, "PUT", path, "", "application/json", []byte(`{"sha":"`+head+`"}`)); err == nil {
			t.Errorf("%s: mapped", name)
		}
	}
	for name, body := range map[string]string{
		"no sha":        `{}`,
		"short sha":     `{"sha":"4b825dc"}`,
		"unknown field": `{"sha":"` + head + `","merge_when_pipeline_succeeds":true}`,
	} {
		if _, err := m.HTTPRequest(ctx, tc, "PUT", "/api/v4/projects/42/merge_requests/7/merge", "", "application/json", []byte(body)); err == nil {
			t.Errorf("%s: mapped", name)
		}
	}
}

// TestHR521_AGitLabMergeWaitsForItsHeadApprovalsPipelineAndProtection: a
// merge is bound to the head the agent names, waits for fresh head,
// approval, pipeline and protection facts, is verified merged at that head,
// and sends only an access token shape (HR-301, HR-521).
//
// Covers: F756
func TestHR521_AGitLabMergeWaitsForItsHeadApprovalsPipelineAndProtection(t *testing.T) {
	p := decode(t)
	merge, ok := p.Definition("gitlab.merge_request.merge")
	if !ok {
		t.Fatal("no merge")
	}
	want := []string{"gitlab.merge_request.head", "gitlab.merge_request.approvals", "gitlab.merge_request.pipeline", "gitlab.branch.protection"}
	if len(merge.Prerequisites) != len(want) {
		t.Fatalf("prerequisites: %+v", merge.Prerequisites)
	}
	for i, f := range want {
		if pr := merge.Prerequisites[i]; pr.Fact != f || pr.MaxAgeSeconds != 30 {
			t.Fatalf("prerequisite %d: %+v", i, pr)
		}
	}
	if b := merge.Prerequisites[0].Binds; b == nil || b.Member != "sha" || b.Param != "sha" {
		t.Fatalf("head binding: %+v", merge.Prerequisites[0].Binds)
	}
	if v := merge.Verifier; v == nil || v.Operation != "gitlab.merge_request.read" || v.Establishes != "merge_request.merged" {
		t.Fatalf("verifier: %+v", merge.Verifier)
	}
	if merge.Dispatch.HTTP.Body["sha"] != "params.sha" {
		t.Fatalf("the merge does not send its head: %+v", merge.Dispatch.HTTP.Body)
	}
	re := regexp.MustCompile(`^glpat-[A-Za-z0-9_.-]{20,300}$`)
	for _, d := range p.Definitions {
		if d.Dispatch != nil && d.Dispatch.CredentialPattern != re.String() {
			t.Fatalf("%s credential pattern %q", d.Operation, d.Dispatch.CredentialPattern)
		}
	}
	for tok, ok := range map[string]bool{
		"glpat-" + "0123456789abcdefghij":           true,
		"glpat-" + "0123456789abcdefghij.01.0x1abc": true,
		"xoxb-0123456789abcdefghij":                 false,
		"glpat-" + "short":                          false,
		"Bearer glpat-" + "0123456789abcdefghij":    false,
	} {
		if re.MatchString(tok) != ok {
			t.Errorf("%q: %v", tok, !ok)
		}
	}
	if test, ok := p.TestRead(); !ok || test.Operation != "gitlab.project.read" {
		t.Fatalf("connection test: %+v", test)
	}
}

// TestHR521_TheGitLabTokenGoesOnlyToItsBoundHost: the sealed token is placed
// only on a request to the host the connection binds, gitlab.com or a
// self-managed instance, and a request to any other host is refused before
// anything is sent (HR-060, HR-521).
//
// Covers: F756
func TestHR521_TheGitLabTokenGoesOnlyToItsBoundHost(t *testing.T) {
	for bound, urls := range map[string]map[string]bool{
		"gitlab.com": {
			"https://gitlab.com/api/v4/projects/42/merge_requests/7/merge":        true,
			"https://gitlab.com.evil.test/api/v4/projects/42/merge_requests/7":    false,
			"https://gitlab.acme.internal/api/v4/projects/42/merge_requests/7":    false,
			"https://evil.test/api/v4/projects/42/merge_requests/7?u=gitlab.com/": false,
		},
		"gitlab.acme.internal:8443": {
			"https://gitlab.acme.internal:8443/api/v4/projects/42/merge_requests/7": true,
			"https://gitlab.acme.internal/api/v4/projects/42/merge_requests/7":      false,
			"https://gitlab.com/api/v4/projects/42/merge_requests/7":                false,
		},
	} {
		for url, ok := range urls {
			r, err := http.NewRequestWithContext(context.Background(), http.MethodPut, url, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = broker.Place(r, []string{bound}, "Authorization", "Bearer", []byte("glpat-"+"0123456789abcdefghij"))
			if ok != (err == nil) || (!ok && (!errors.Is(err, broker.ErrNotBound) || r.Header.Get("Authorization") != "")) {
				t.Errorf("%s via %s: %v", url, bound, err)
			}
		}
	}
}

// TestHR523_PCGitLabDeclaresItsCoverage: pc.gitlab declares its records
// scoped by merge request and its two channels (F756).
//
// Covers: F756
func TestHR523_PCGitLabDeclaresItsCoverage(t *testing.T) {
	c := decode(t).Coverage
	if c == nil || len(c.RecordScope) != 1 || c.RecordScope[0] != "gitlab_merge_request" || len(c.Channels) != 2 {
		t.Fatalf("coverage: %+v", c)
	}
}
