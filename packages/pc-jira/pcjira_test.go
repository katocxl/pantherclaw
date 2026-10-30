// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pcjira_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/consequences"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	pcjira "github.com/katocxl/pantherclaw/packages/pc-jira"
)

var tc = mapping.Context{
	Org: "01920000-0000-7000-8000-000000000001", Env: "01920000-0000-7000-8000-000000000002",
	RunID: "01920000-0000-7000-8000-000000000003", ActionID: "01920000-0000-7000-8000-000000000004",
	AgentInstance: "01920000-0000-7000-8000-000000000005",
}

func decode(t *testing.T) *domain.Package {
	t.Helper()
	p, err := manifest.Decode(pcjira.Package)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func mapper(t *testing.T) *mapping.Mapper {
	t.Helper()
	m, err := mapping.New(decode(t), celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestHR522_JiraRoutesAreOneActionOnEveryRoute: a comment through the REST
// API and through the MCP tool is the same action, whose target and
// destination are the issue, so a grant or policy that bounds issues bounds
// both routes; so is a read (F756, route and tool parity).
//
// Covers: F756
func TestHR522_JiraRoutesAreOneActionOnEveryRoute(t *testing.T) {
	m := mapper(t)
	ctx := context.Background()
	h, err := m.HTTPRequest(ctx, tc, "POST", "/rest/api/2/issue/HELP-1/comment", "", "application/json",
		[]byte(`{"body":"Your refund was sent"}`))
	if err != nil {
		t.Fatal(err)
	}
	c, err := m.MCP(ctx, tc, "jira_add_comment", []byte(`{"issue_key":"HELP-1","body":"Your refund was sent"}`))
	if err != nil {
		t.Fatal(err)
	}
	if h.Action.DedupeKey != c.Action.DedupeKey || h.Action.Route != c.Action.Route || string(h.Action.Params) != string(c.Action.Params) ||
		h.Action.Target != c.Action.Target {
		t.Fatalf("routes differ:\n%s\n%s", h.Canonical, c.Canonical)
	}
	a := h.Action
	if a.Operation != "jira.issue.comment" || a.Target.ID != "HELP-1" || len(a.Destinations) != 1 || a.Destinations[0].ID != "HELP-1" ||
		a.Destinations[0].Kind != "external" {
		t.Fatalf("action: %s", h.Canonical)
	}
	hr, err := m.HTTPRequest(ctx, tc, "GET", "/rest/api/2/issue/ENG-1", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	cr, err := m.MCP(ctx, tc, "jira_get_issue", []byte(`{"issue_key":"ENG-1"}`))
	if err != nil || hr.Action.Target != cr.Action.Target || hr.Action.Route != cr.Action.Route || hr.Action.Operation != "jira.issue.read" {
		t.Fatalf("read: %v %s %s", err, hr.Canonical, cr.Canonical)
	}
	for name, args := range map[string]string{
		"lowercase key": `{"issue_key":"help-1","body":"x"}`,
		"project only":  `{"issue_key":"HELP","body":"x"}`,
		"no body":       `{"issue_key":"HELP-1"}`,
		"too long":      `{"issue_key":"HELP-1","body":"` + strings.Repeat("x", 8193) + `"}`,
		"unknown field": `{"issue_key":"HELP-1","body":"x","visibility":{"type":"role","value":"Administrators"}}`,
	} {
		if _, err := m.MCP(ctx, tc, "jira_add_comment", []byte(args)); err == nil {
			t.Errorf("%s: mapped", name)
		}
	}
}

// TestHR522_JiraWritesAreDisclosedContentAndCustomerProjectsAConsequence:
// a comment is a content param with disclosure limits (HR-079), every write
// waits for the project's customer visibility, a write into a service desk
// predicts external_disclosure, and only a Basic credential shape is sent
// (HR-301, HR-522).
//
// Covers: F756
func TestHR522_JiraWritesAreDisclosedContentAndCustomerProjectsAConsequence(t *testing.T) {
	p := decode(t)
	var writes int
	for _, d := range p.Definitions {
		if d.Dispatch != nil && d.Dispatch.CredentialPattern != `^[A-Za-z0-9+/]{20,1000}={0,2}$` {
			t.Fatalf("%s credential pattern %q", d.Operation, d.Dispatch.CredentialPattern)
		}
		if d.Access != domain.AccessWrite || len(d.Mappings) == 0 {
			continue
		}
		writes++
		if len(d.Prerequisites) != 1 || d.Prerequisites[0].Fact != "jira.project.external" || d.Prerequisites[0].MaxAgeSeconds != 300 {
			t.Fatalf("%s prerequisites: %+v", d.Operation, d.Prerequisites)
		}
		var required bool
		for _, c := range d.Constraints {
			required = required || (c.Kind == domain.ConstraintDestinationSet && c.Required)
		}
		if !required {
			t.Fatalf("%s: no required destination set", d.Operation)
		}
		var disclosed bool
		for _, ps := range d.Params {
			disclosed = disclosed || (ps.Type == domain.TypeContent && ps.Disclosure)
		}
		if !disclosed {
			t.Fatalf("%s: no disclosure param", d.Operation)
		}
		var found bool
		for _, c := range p.Consequences {
			found = found || (c.Operation == d.Operation && c.Consequence.Effect == "external_disclosure" &&
				len(c.RequiresFacts) == 1 && c.RequiresFacts[0] == "jira.project.external")
		}
		if !found {
			t.Fatalf("%s: no external_disclosure consequence", d.Operation)
		}
	}
	if writes == 0 {
		t.Fatal("no writes")
	}
	secret := base64.StdEncoding.EncodeToString([]byte("agent@example.com:simulated-api-token"))
	if !regexp.MustCompile(`^[A-Za-z0-9+/]{20,1000}={0,2}$`).MatchString(secret) {
		t.Fatal("a Basic credential does not match")
	}
	for _, other := range []string{"xoxb-simulated-token-0000000000", "glpat-0123456789abcdefghij", "Basic " + secret} {
		if regexp.MustCompile(`^[A-Za-z0-9+/]{20,1000}={0,2}$`).MatchString(other) {
			t.Fatalf("%q matches", other)
		}
	}
	if test, ok := p.TestRead(); !ok || test.Operation != "jira.project.read" {
		t.Fatalf("connection test: %+v", test)
	}
}

// TestT226_ACustomerVisibleProjectPredictsExternalDisclosure: the
// consequence rule evaluates: an issue in a service desk predicts
// jira.issue.disclose on the issue, an internal project does not, and an
// unread fact makes the consequence unknown, never "internal" (HR-160,
// HR-522).
//
// Covers: F756
func TestT226_ACustomerVisibleProjectPredictsExternalDisclosure(t *testing.T) {
	p := decode(t)
	on, _ := p.Definition("jira.issue.comment")
	var rules []consequences.Rule
	for _, r := range p.Consequences {
		if r.Operation == on.Operation {
			d, _ := p.Definition(r.Consequence.Operation)
			rules = append(rules, consequences.Rule{ConsequenceRule: r, Definition: d})
		}
	}
	now := time.Now()
	fact := func(members map[string]any) map[string]fdomain.Fact {
		return map[string]fdomain.Fact{"jira.project.external": {
			Name: "jira.project.external", SubjectType: "jira_issue", SubjectID: "HELP-1",
			Value: fdomain.Value{Type: fdomain.TypeObject, Object: members}, ObservedAt: now.Add(-time.Second),
		}}
	}
	ev := consequences.NewEvaluator(celenv.DefaultLimits)
	for name, c := range map[string]struct {
		members map[string]any
		want    consequences.State
	}{
		"service desk": {map[string]any{"external": true, "project": "HELP", "project_type": "service_desk"}, consequences.Predicted},
		"software":     {map[string]any{"external": false, "project": "ENG", "project_type": "software"}, consequences.NotTriggered},
		"unread":       {map[string]any{"unread": "Jira refused the read"}, consequences.Unknown},
	} {
		out := ev.Evaluate(context.Background(), rules, consequences.Input{On: on, TargetID: "HELP-1", Facts: fact(c.members), Now: now})
		if len(out) != 1 || out[0].Err != nil || out[0].State != c.want {
			t.Fatalf("%s: %+v", name, out)
		}
		if c.want == consequences.Predicted && (out[0].Operation != "jira.issue.disclose" || out[0].Target.ID != "HELP-1") {
			t.Fatalf("%s: %+v", name, out[0])
		}
	}
}

// TestHR522_TheJiraCredentialGoesOnlyToItsBoundSite: the sealed Basic
// credential is placed only on a request to a host the connection binds,
// cloud or self-managed, and a request to any other host is refused before
// anything is sent (HR-060, HR-522).
//
// Covers: F756
func TestHR522_TheJiraCredentialGoesOnlyToItsBoundSite(t *testing.T) {
	bound := []string{"acme.atlassian.net"}
	for url, ok := range map[string]bool{
		"https://acme.atlassian.net/rest/api/2/issue/HELP-1/comment":   true,
		"https://ACME.atlassian.net./rest/api/2/issue/HELP-1/comment":  true,
		"https://other.atlassian.net/rest/api/2/issue/HELP-1/comment":  false,
		"https://acme.atlassian.net.evil.test/rest/api/2/issue/HELP-1": false,
		"https://jira.acme.internal/rest/api/2/issue/HELP-1":           false,
	} {
		r, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		err = broker.Place(r, bound, "Authorization", "Basic", []byte("c2VjcmV0c2VjcmV0c2VjcmV0"))
		if ok != (err == nil) || (!ok && (!errors.Is(err, broker.ErrNotBound) || r.Header.Get("Authorization") != "")) {
			t.Errorf("%s: %v %q", url, err, r.Header.Get("Authorization"))
		}
	}
	selfManaged := []string{"jira.acme.internal:8443"}
	r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://jira.acme.internal:8443/rest/api/2/issue/ENG-1", nil)
	if err := broker.Place(r, selfManaged, "Authorization", "Basic", []byte("c2VjcmV0c2VjcmV0c2VjcmV0")); err != nil {
		t.Fatalf("self-managed: %v", err)
	}
	r, _ = http.NewRequestWithContext(context.Background(), http.MethodGet, "https://jira.acme.internal/rest/api/2/issue/ENG-1", nil)
	if err := broker.Place(r, selfManaged, "Authorization", "Basic", []byte("c2VjcmV0c2VjcmV0c2VjcmV0")); !errors.Is(err, broker.ErrNotBound) {
		t.Fatalf("self-managed other port: %v", err)
	}
}

// TestHR523_PCJiraDeclaresItsCoverage: pc.jira declares no environment,
// records scoped by issue, recipients classified by the project's customer
// visibility, and its two channels (F756).
//
// Covers: F756
func TestHR523_PCJiraDeclaresItsCoverage(t *testing.T) {
	c := decode(t).Coverage
	if c == nil || c.Environment.Source != domain.EnvironmentNone || c.RecipientFact != "jira.project.external" ||
		len(c.RecordScope) != 1 || c.RecordScope[0] != "jira_issue" || len(c.Channels) != 2 {
		t.Fatalf("coverage: %+v", c)
	}
}
