// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"encoding/json/jsontext"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
)

const prPattern = `^(?P<owner>[a-z0-9][a-z0-9-]{0,38})/(?P<repo>[a-z0-9._-]{1,100})#(?P<number>[1-9][0-9]{0,9})$`

// TestTargetParts: a template may send the named groups of the target id
// pattern on their own (G0 M8), so a pull request acme/payments#7 reaches
// /repos/acme/payments/pulls/7 while its identity stays one canonical id.
func TestTargetParts(t *testing.T) {
	spec := domain.TargetSpec{Type: "github.pull_request", IDPattern: prPattern, Account: domain.PresenceNone}
	for group, want := range map[string]string{"owner": "acme", "repo": "pay.ments", "number": "7"} {
		if got, ok := spec.Part("acme/pay.ments#7", group); !ok || got != want {
			t.Errorf("%s: got %q, %v", group, got, ok)
		}
	}
	for _, c := range []struct{ id, group string }{
		{"acme/payments#7", "branch"},  // no such group
		{"Acme/payments#7", "owner"},   // does not match the pattern
		{"acme/payments#07", "number"}, // does not match the pattern
	} {
		if got, ok := spec.Part(c.id, c.group); ok {
			t.Errorf("%s %s: got %q", c.id, c.group, got)
		}
	}

	d := minimal(map[string]domain.ParamSpec{})
	d.Target = spec
	d.Dispatch = &domain.Dispatch{HTTP: &domain.HTTPDispatch{Method: "GET", Path: "/repos/{target.id.owner}/{target.id.repo}/pulls/{target.id.number}"}}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*domain.Definition){
		"unknown group": func(d *domain.Definition) { d.Dispatch.HTTP.Path = "/repos/{target.id.branch}" },
		"group named twice": func(d *domain.Definition) {
			d.Target.IDPattern = `^(?P<owner>[a-z]+)/(?P<owner>[a-z]+)$`
			d.Dispatch.HTTP.Path = "/repos/{target.id.owner}"
		},
		"uppercase group": func(d *domain.Definition) {
			d.Target.IDPattern = `^(?P<Owner>[a-z]+)$`
			d.Dispatch.HTTP.Path = "/repos/{target.id}"
		},
		"expectation on a part": func(d *domain.Definition) {
			d.Access = domain.AccessWrite
			d.Approval = &domain.ApprovalTemplate{Title: "t", Fields: []string{"target.id"}}
			d.Verifier = &domain.VerifierSpec{
				Operation: "x.y.get", Establishes: "x.done", WithinSeconds: 60, Level: domain.LevelFollowUp,
				Expect: []domain.Expectation{{Field: "/number", Equals: "target.id.number"}},
			}
		},
	} {
		c := *d
		h := *d.Dispatch.HTTP
		c.Dispatch = &domain.Dispatch{HTTP: &h}
		mutate(&c)
		if err := c.Validate(); !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), "target") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestContentParams: content is text the target stores as written; it is
// sent from a template, so it must be material, and it is refused with
// control, format or bidi characters like a command (HR-102).
func TestContentParams(t *testing.T) {
	if err := minimal(map[string]domain.ParamSpec{"title": {Type: domain.TypeContent}}).Validate(); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("content that is not material: %v", err)
	}
	d := minimal(map[string]domain.ParamSpec{"title": {Type: domain.TypeContent, Material: true, MaxLength: 16}})
	d.Dispatch = &domain.Dispatch{HTTP: &domain.HTTPDispatch{Method: "POST", Path: "/pulls", Body: map[string]string{"title": "params.title"}}}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	vals, err := d.DecodeParams(jsontext.Value(`{"title":"Fix: é\tbug\n"}`))
	if err != nil || vals["title"].Str != "Fix: é\tbug\n" {
		t.Fatalf("content is kept exactly: %v %q", err, vals["title"].Str)
	}
	for name, in := range map[string]string{
		"escape":   `{"title":"a\u001b[2J"}`,
		"bidi":     `{"title":"a ` + string(rune(0x202e)) + `"}`,
		"too long": `{"title":"12345678901234567"}`,
		"number":   `{"title":7}`,
	} {
		if _, err := d.DecodeParams(jsontext.Value(in)); !errors.Is(err, actionir.ErrAmbiguous) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestCredentialScope: an operation's dispatch declares the least
// privileges its credential needs, as name to level, which the credential
// kind interprets (G0 M8).
func TestCredentialScope(t *testing.T) {
	d := minimal(map[string]domain.ParamSpec{})
	d.Dispatch = &domain.Dispatch{
		HTTP:            &domain.HTTPDispatch{Method: "GET", Path: "/x"},
		CredentialScope: map[string]string{"contents": "write", "pull_requests": "read"},
	}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := d.Scopes(); !maps.Equal(got, map[string]string{"contents": "write", "pull_requests": "read"}) {
		t.Fatalf("scopes: %v", got)
	}
	if (&domain.Definition{}).Scopes() != nil {
		t.Fatal("a definition without dispatch has scopes")
	}
	many := map[string]string{}
	for _, c := range "abcdefghijklmnopq" {
		many[string(c)] = "read"
	}
	for name, scope := range map[string]map[string]string{
		"uppercase name":  {"Contents": "read"},
		"uppercase level": {"contents": "Read"},
		"empty level":     {"contents": ""},
		"too many":        many,
	} {
		c := *d
		c.Dispatch = &domain.Dispatch{HTTP: d.Dispatch.HTTP, CredentialScope: scope}
		if err := c.Validate(); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestConnectionTestReads: test marks one harmless read per package, an
// HTTP GET that needs no input; nothing else can be marked.
func TestConnectionTestReads(t *testing.T) {
	d := minimal(map[string]domain.ParamSpec{"page": {Type: domain.TypeInteger, Unit: "count"}})
	d.Test, d.Mappings = true, nil
	d.Dispatch = &domain.Dispatch{HTTP: &domain.HTTPDispatch{Method: "GET", Path: "/installation/repositories"}}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	p := &domain.Package{Format: 1, Name: "pc.test", Version: "1.0.0", Publisher: "pantherclaw", Summary: "s", Definitions: []domain.Definition{*d}}
	if err := p.Validate(); err != nil {
		t.Fatalf("an internal test read: %v", err)
	}
	second := *d
	second.Operation = "x.z.read"
	p.Definitions = append(p.Definitions, second)
	if err := p.Validate(); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("two tests: %v", err)
	}
	for name, mutate := range map[string]func(*domain.Definition){
		"a write":     func(d *domain.Definition) { d.Access = domain.AccessWrite },
		"a POST":      func(d *domain.Definition) { d.Dispatch.HTTP.Method = "POST" },
		"no dispatch": func(d *domain.Definition) { d.Dispatch = nil },
		"a required param": func(d *domain.Definition) {
			d.Params = map[string]domain.ParamSpec{"q": {Type: domain.TypeIdentifier, Required: true}}
		},
	} {
		c := *d
		h := *d.Dispatch.HTTP
		c.Dispatch = &domain.Dispatch{HTTP: &h}
		mutate(&c)
		if err := c.Validate(); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestInvalidateOnAndVirtualConsequences: an approval names the
// prerequisite fact whose change supersedes it; a write without mappings
// or dispatch exists only as a consequence of its package.
func TestInvalidateOnAndVirtualConsequences(t *testing.T) {
	merge := minimal(map[string]domain.ParamSpec{"sha": {Type: domain.TypeIdentifier, Material: true}})
	merge.Operation, merge.Access = "x.pull.merge", domain.AccessWrite
	merge.Prerequisites = []domain.Prerequisite{{
		Fact: "x.pull.head", MaxAgeSeconds: 30, Binds: &domain.FactBinding{Member: "sha", Param: "sha", Reason: "HEAD_MOVED"},
	}}
	merge.Approval = &domain.ApprovalTemplate{Title: "Merge {target.id}", Fields: []string{"target.id"}, InvalidateOn: "x.pull.head"}
	if err := merge.Validate(); err != nil {
		t.Fatal(err)
	}
	unbound := *merge
	unbound.Prerequisites = []domain.Prerequisite{{Fact: "x.pull.head", MaxAgeSeconds: 30}}
	if err := unbound.Validate(); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("invalidate_on a fact that binds no member (HR-030 option B): %v", err)
	}
	bad := *merge
	bad.Approval = &domain.ApprovalTemplate{Title: "Merge", Fields: []string{"target.id"}, InvalidateOn: "x.pull.base"}
	if err := bad.Validate(); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("invalidate_on a fact that is not a prerequisite: %v", err)
	}
	trigger := minimal(map[string]domain.ParamSpec{})
	trigger.Operation, trigger.Access, trigger.Mappings = "x.deployment.trigger", domain.AccessWrite, nil
	trigger.Approval = &domain.ApprovalTemplate{Title: "Deploy {target.id}", Fields: []string{"target.id"}}
	p := &domain.Package{
		Format: 1, Name: "pc.test", Version: "1.0.0", Publisher: "pantherclaw", Summary: "s",
		Definitions: []domain.Definition{*merge, *trigger},
		Consequences: []domain.ConsequenceRule{{
			ID: "merge-deploys", Operation: "x.pull.merge", When: "true", RequiresFacts: []string{"x.deploy"}, ValidUntil: "2027-01-01",
			Consequence: domain.Consequence{Operation: "x.deployment.trigger", Effect: "deployment.trigger", Description: "Deploys"},
		}},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("a virtual consequence operation: %v", err)
	}
	p.Consequences = nil
	if err := p.Validate(); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("a write without mappings that is no consequence: %v", err)
	}
	trigger.Dispatch = &domain.Dispatch{HTTP: &domain.HTTPDispatch{Method: "POST", Path: "/deploy"}}
	if err := trigger.Validate(); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("a dispatchable write without mappings: %v", err)
	}
}

// TestRestPaths: the last segment of a mapping path may take the rest of
// the path, and a dispatch path may send an identifier param as the rest,
// nowhere else and from nothing else (HR-073).
func TestRestPaths(t *testing.T) {
	d := minimal(map[string]domain.ParamSpec{"path": {Type: domain.TypeIdentifier, Material: true, Required: true}})
	d.Mappings = []domain.Mapping{{
		Channel: domain.ChannelHTTP, Method: "GET", Path: "/repos/{owner}/{repo}/contents/{path*}", Route: "contents",
		Extract: domain.Extract{TargetID: "'a'", Params: map[string]string{"path": "path.path"}},
	}}
	d.Dispatch = &domain.Dispatch{HTTP: &domain.HTTPDispatch{Method: "GET", Path: "/contents/{params.path*}"}}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*domain.Definition){
		"mapping rest not last":   func(d *domain.Definition) { d.Mappings[0].Path = "/contents/{path*}/x" },
		"mapping rest twice":      func(d *domain.Definition) { d.Mappings[0].Path = "/{path}/{path*}" },
		"dispatch rest not last":  func(d *domain.Definition) { d.Dispatch.HTTP.Path = "/{params.path*}/x" },
		"dispatch rest of target": func(d *domain.Definition) { d.Dispatch.HTTP.Path = "/x/{target.id*}" },
		"dispatch rest of an enum": func(d *domain.Definition) {
			d.Params["kind"] = domain.ParamSpec{Type: domain.TypeEnum, Values: []string{"a"}}
			d.Dispatch.HTTP.Path = "/x/{params.kind*}"
		},
	} {
		c := *d
		c.Params = maps.Clone(d.Params)
		c.Mappings = slices.Clone(d.Mappings)
		h := *d.Dispatch.HTTP
		c.Dispatch = &domain.Dispatch{HTTP: &h}
		mutate(&c)
		if err := c.Validate(); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
