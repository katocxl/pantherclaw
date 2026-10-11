// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"encoding/json/jsontext"
	"errors"
	"maps"
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
		"bidi":     `{"title":"a ‮"}`,
		"too long": `{"title":"12345678901234567"}`,
		"number":   `{"title":7}`,
	} {
		if _, err := d.DecodeParams(jsontext.Value(in)); !errors.Is(err, actionir.ErrAmbiguous) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestCredentialScopes: an operation declares the least privileges it
// needs, each privilege at one level.
func TestCredentialScopes(t *testing.T) {
	d := minimal(map[string]domain.ParamSpec{})
	d.CredentialScopes = []string{"contents:write", "pull_requests:read"}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := d.Scopes(); !maps.Equal(got, map[string]string{"contents": "write", "pull_requests": "read"}) {
		t.Fatalf("scopes: %v", got)
	}
	for name, scopes := range map[string][]string{
		"two levels of one privilege": {"contents:read", "contents:write"},
		"no level":                    {"contents"},
		"uppercase":                   {"Contents:read"},
		"too many": {
			"a:r", "b:r", "c:r", "d:r", "e:r", "f:r", "g:r", "h:r", "i:r",
			"j:r", "k:r", "l:r", "m:r", "n:r", "o:r", "p:r", "q:r",
		},
	} {
		c := *d
		c.CredentialScopes = scopes
		if err := c.Validate(); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
