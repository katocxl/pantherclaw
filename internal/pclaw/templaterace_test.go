// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// racingPolicies is a policy service that, the first time a version is
// created, has another admin publish a version first; like the server, it
// refuses a create or publish whose expected_current_version is not the
// published one.
type racingPolicies struct {
	pantherclawv1connect.UnimplementedPolicyServiceHandler
	mu        sync.Mutex
	published string
	bundles   map[string][]byte
	race      func(rules []any) []any // the other admin's edit
	raced     bool
	creates   int
}

func (p *racingPolicies) GetPublishedPolicy(context.Context, *pantherclawv1.GetPublishedPolicyRequest) (*pantherclawv1.GetPublishedPolicyResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.published == "" {
		return nil, connect.NewError(connect.CodeNotFound, "POLICY_NOT_PUBLISHED: none")
	}
	return &pantherclawv1.GetPublishedPolicyResponse{Version: &pantherclawv1.PolicyVersion{Id: p.published, Bundle: p.bundles[p.published]}}, nil
}

func (p *racingPolicies) expect(e *string) error {
	if e != nil && *e != p.published {
		return connect.NewError(connect.CodeFailedPrecondition, "POLICY_PUBLISHED_CHANGED: another policy version was published")
	}
	return nil
}

func (p *racingPolicies) CreatePolicyVersion(_ context.Context, req *pantherclawv1.CreatePolicyVersionRequest) (*pantherclawv1.CreatePolicyVersionResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.creates++
	if !p.raced {
		p.raced = true
		var b map[string]any
		_ = json.Unmarshal(p.bundles[p.published], &b)
		rules, _ := b["rules"].([]any)
		b["rules"] = p.race(rules)
		raw, _ := json.Marshal(b)
		id := fmt.Sprintf("0192aaaa-bbbb-7ccc-8ddd-%012d", len(p.bundles))
		p.bundles[id], p.published = raw, id
	}
	if err := p.expect(req.ExpectedCurrentVersion); err != nil {
		return nil, err
	}
	id := fmt.Sprintf("0192aaaa-bbbb-7ccc-8ddd-%012d", len(p.bundles))
	p.bundles[id] = req.GetBundle()
	return &pantherclawv1.CreatePolicyVersionResponse{Version: &pantherclawv1.PolicyVersion{Id: id, Version: int32(len(p.bundles))}}, nil
}

func (p *racingPolicies) PublishPolicyVersion(_ context.Context, req *pantherclawv1.PublishPolicyVersionRequest) (*pantherclawv1.PublishPolicyVersionResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.expect(req.ExpectedCurrentVersion); err != nil {
		return nil, err
	}
	p.published = req.GetId()
	return &pantherclawv1.PublishPolicyVersionResponse{Version: &pantherclawv1.PolicyVersion{Id: req.GetId()}}, nil
}

func (p *racingPolicies) publishedRules(t *testing.T) map[string]map[string]any {
	t.Helper()
	var b struct {
		Rules []map[string]any `json:"rules"`
	}
	if err := json.Unmarshal(p.bundles[p.published], &b); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, r := range b.Rules {
		out[r["id"].(string)] = r
	}
	return out
}

func racingClients(t *testing.T, p *racingPolicies) clients {
	t.Helper()
	cs := connect.NewServer()
	pantherclawv1connect.RegisterPolicyServiceHandler(cs, p)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	a := &app{stdout: io.Discard, stderr: io.Discard, http: ts.Client(), env: envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})}
	c, err := a.clients()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestTemplatePolicyRetriesAfterAConcurrentPublish (G0 M8 C4): another
// admin publishes between the template's plan and its publish. The server
// refuses the stale version; the template plans again from the new one and
// publishes its rules with the other admin's change kept. When the other
// admin changed one of the template's own rules, nothing is published
// without --update.
func TestTemplatePolicyRetriesAfterAConcurrentPublish(t *testing.T) {
	o, err := templateOpts(t, "--repos", "acme/web")
	if err != nil {
		t.Fatal(err)
	}
	d, err := renderTemplate(o)
	if err != nil {
		t.Fatal(err)
	}
	const v1 = "0192aaaa-bbbb-7ccc-8ddd-000000000000"
	start := func(race func([]any) []any) *racingPolicies {
		return &racingPolicies{published: v1, bundles: map[string][]byte{v1: []byte(`{"id":"org-policy","rules":[]}`)}, race: race}
	}

	// The other admin adds a rule of their own: kept, and the template's added.
	p := start(func(rules []any) []any {
		return append(rules, map[string]any{"id": "their-rule", "kind": "FORBID", "reason": "THEIRS"})
	})
	c := racingClients(t, p)
	s, err := planPolicy(context.Background(), c, o, d, "")
	if err != nil || s.state != stepCreate {
		t.Fatalf("plan: %s %v", s.state, err)
	}
	if _, err := s.apply(context.Background()); err != nil {
		t.Fatalf("apply after a concurrent publish: %v", err)
	}
	got := p.publishedRules(t)
	if _, ok := got["their-rule"]; !ok || len(got) != 1+len(d.Rules) || p.creates != 2 {
		t.Fatalf("published %v after %d creates", got, p.creates)
	}

	// The other admin publishes the template's rule with another condition:
	// it differs, so nothing is published without --update.
	merge := d.Rules[0]["id"].(string)
	p = start(func(rules []any) []any {
		return append(rules, map[string]any{"id": merge, "kind": "FORBID", "when": "false", "reason": "THEIRS"})
	})
	c = racingClients(t, p)
	if s, err = planPolicy(context.Background(), c, o, d, ""); err != nil {
		t.Fatal(err)
	}
	before := p.published
	if _, err := s.apply(context.Background()); err == nil || !strings.Contains(err.Error(), "changes the template's rules") {
		t.Fatalf("apply after a conflicting publish: %v", err)
	}
	if p.published == before || p.publishedRules(t)[merge]["when"] != "false" {
		t.Fatal("the template replaced the other admin's rule")
	}

	// A version published again on every attempt: the template gives up.
	p = start(nil)
	p.race = func(rules []any) []any { p.raced = false; return rules }
	c = racingClients(t, p)
	if s, err = planPolicy(context.Background(), c, o, d, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.apply(context.Background()); !errors.Is(err, errPublishedChanged) || p.creates != policyRetries+1 {
		t.Fatalf("apply against a policy that keeps changing: %v after %d creates", err, p.creates)
	}
}
