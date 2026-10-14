// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"encoding/json/v2"
	"io/fs"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	polapp "github.com/katocxl/pantherclaw/internal/policy/app"
	"github.com/katocxl/pantherclaw/internal/policy/domain"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
	pcgithub "github.com/katocxl/pantherclaw/packages/pc-github"
	pcshell "github.com/katocxl/pantherclaw/packages/pc-shell"
	"github.com/katocxl/pantherclaw/templates"
)

// templateDefinitions are the definitions of every package a template can
// reference (pc.github, pc.shell, mock payments), each with a digest of its
// own, as an org that imported them all holds.
func templateDefinitions(t *testing.T) []*defs.Definition {
	t.Helper()
	var out []*defs.Definition
	for name, raw := range map[string][]byte{"pc-github": pcgithub.Package, "pc-shell": pcshell.Package, "mock-payments": mockpayments.Package} {
		p, err := manifest.Decode(raw)
		if err != nil {
			t.Fatalf("package %s: %v", name, err)
		}
		for i := range p.Definitions {
			d := &p.Definitions[i]
			d.Digest = "sha256:" + name + "/" + d.Operation
			out = append(out, d)
		}
	}
	return out
}

// renderedBundle renders template name for repositories and an agent and
// returns it as the policy bundle the server compiles when it is applied.
func renderedBundle(t *testing.T, name, agent string) *domain.Bundle {
	t.Helper()
	o, err := templateOpts(t, "--repos", "acme/web,acme/api")
	if err != nil {
		t.Fatal(err)
	}
	o.name, o.agent = name, agent
	d, err := renderTemplate(o)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{"id": "template-" + name, "version": 1, "rules": d.Rules})
	if err != nil {
		t.Fatal(err)
	}
	var b domain.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("template %s: %v", name, err)
	}
	return &b
}

const templateAgent = "01890000-0000-7000-8000-00000000000a"

// TestTemplatesCompile: every rule of every template compiles against the
// definitions of every package it can reference, as the server does when
// the template is applied to an org that has them. Applying "coding to
// production" once failed with POLICY_DOES_NOT_COMPILE on an org with pc.shell
// because a rule's regular expression used escapes CEL does not know.
func TestTemplatesCompile(t *testing.T) {
	entries, err := fs.ReadDir(templates.FS, ".")
	if err != nil || len(entries) == 0 {
		t.Fatalf("templates: %v %d", err, len(entries))
	}
	ds := templateDefinitions(t)
	for _, e := range entries {
		t.Run(e.Name(), func(t *testing.T) {
			b := renderedBundle(t, e.Name(), templateAgent)
			if _, err := (&polapp.Engine{Limits: celenv.DefaultLimits}).Compile(b, ds); err != nil {
				t.Fatalf("template %s does not compile: %v", e.Name(), err)
			}
		})
	}
}

// TestTemplateShellRuleDecides: c2p-no-shell-merge, compiled and evaluated
// as the server does, forbids the shell commands that merge or push, with
// leading separators, and passes harmless lines, for its own agent only.
func TestTemplateShellRuleDecides(t *testing.T) {
	var shell *defs.Definition
	ds := templateDefinitions(t)
	for _, d := range ds {
		if d.Operation == "shell.command.run" {
			shell = d
		}
	}
	if shell == nil {
		t.Fatal("no shell.command.run")
	}
	c, err := (&polapp.Engine{Limits: celenv.DefaultLimits}).Compile(renderedBundle(t, "coding-to-production", templateAgent), ds)
	if err != nil {
		t.Fatal(err)
	}
	verdict := func(agent, command string) domain.Verdict {
		t.Helper()
		params, err := json.Marshal(map[string]string{"shell": "bash", "command": command, "cwd": "/work", "call": "toolu_1"})
		if err != nil {
			t.Fatal(err)
		}
		a := actionir.ActionIR{Operation: shell.Operation, Definition: actionir.Definition{Digest: shell.Digest}, Params: params,
			Target: actionir.Target{Type: "shell.workspace", ID: "local"}, Channel: "hook"}
		out, err := c.Evaluate(context.Background(), shell, a, polapp.Input{Budget: polapp.DefaultBudget, Run: &polapp.Run{ID: "r", AgentID: agent}})
		if err != nil {
			t.Fatalf("%q: %v", command, err)
		}
		return out.Verdict
	}
	for _, cmd := range []string{
		"gh pr merge 1", "git push origin HEAD:main", "git push", "true; gh pr merge --squash", "make && git push origin main",
		"echo ok | gh api -X PUT repos/acme/web/pulls/1/merge", "(git push)", "git -C dir push", "/usr/bin/git push", "gh -R acme/web pr merge 1",
	} {
		if v := verdict(templateAgent, cmd); v != domain.VerdictDeny {
			t.Errorf("%q: %s, want DENY", cmd, v)
		}
	}
	for _, cmd := range []string{"git status", "gh pr view 1", "gh api repos/acme/web/pulls", "git pushd", "echo legit-push", "git log --grep push", "ls -la"} {
		if v := verdict(templateAgent, cmd); v != domain.VerdictPass {
			t.Errorf("%q: %s, want PASS", cmd, v)
		}
	}
	// Another agent's run is not the template's agent's.
	if v := verdict("01890000-0000-7000-8000-0000000000bb", "git push"); v != domain.VerdictPass {
		t.Errorf("another agent's git push: %s", v)
	}
}
