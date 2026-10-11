// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package manifest

import (
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	pcgithub "github.com/katocxl/pantherclaw/packages/pc-github"
)

// TestHR124_PcGitHubGolden pins the reviewed meaning of pc.github: its
// canonical form and every definition digest.
func TestHR124_PcGitHubGolden(t *testing.T) {
	p, err := Decode(pcgithub.Package)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := Canonical(pcgithub.Package)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "pc-github.canonical.json", append(canon, '\n'))
	var digests strings.Builder
	for _, d := range p.Definitions {
		fmt.Fprintf(&digests, "%s %s\n", d.Operation, d.Digest)
	}
	golden(t, "pc-github.digests", []byte(digests.String()))
	if p.Name != pcgithub.Name || p.Version != pcgithub.Version {
		t.Fatalf("decoded %s %s", p.Name, p.Version)
	}
}

// TestHR203_EveryGitHubOperationDeclaresItsLeastPermissions: the broker
// mints each installation token with exactly the operation's declared
// GitHub App permissions, so every dispatchable operation declares them,
// and none declares GitHub's workflows permission, without which no token
// can change .github/workflows/.
func TestHR203_EveryGitHubOperationDeclaresItsLeastPermissions(t *testing.T) {
	p, err := Decode(pcgithub.Package)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]string{
		"github.contents.read":             {"contents": "read"},
		"github.pull.read":                 {"pull_requests": "read"},
		"github.branch.create":             {"contents": "write"},
		"github.contents.write":            {"contents": "write"},
		"github.pull.create":               {"pull_requests": "write"},
		"github.pull.merge":                {"contents": "write"},
		"github.repo.settings.update":      {"administration": "write"},
		"github.installation.repositories": {"metadata": "read"},
		"github.deployment.trigger":        nil, // virtual: never dispatched
	}
	if len(p.Definitions) != len(want) {
		t.Fatalf("%d definitions, want %d", len(p.Definitions), len(want))
	}
	for _, d := range p.Definitions {
		w, ok := want[d.Operation]
		if !ok {
			t.Errorf("unexpected operation %s", d.Operation)
			continue
		}
		if got := d.Scopes(); !maps.Equal(got, w) {
			t.Errorf("%s: scope %v, want %v", d.Operation, got, w)
		}
		if _, ok := d.Scopes()["workflows"]; ok {
			t.Errorf("%s declares the workflows permission", d.Operation)
		}
	}
}

// TestHR206_EveryRefMovingOperationHasAConsequenceRule: a merge, a contents
// write and a branch creation each may start a deployment, so each has a
// rule whose facts the gateway reads, and the consequence operation is the
// virtual github.deployment.trigger.
func TestHR206_EveryRefMovingOperationHasAConsequenceRule(t *testing.T) {
	p, err := Decode(pcgithub.Package)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"github.pull.merge":     "github.repo.deploy_triggers",
		"github.contents.write": "github.branch.deploy_triggers",
		"github.branch.create":  "github.branch.deploy_triggers",
	}
	got := map[string]string{}
	for _, c := range p.Consequences {
		if c.Consequence.Operation != "github.deployment.trigger" || c.Consequence.Effect != "deployment.trigger" || len(c.RequiresFacts) != 1 {
			t.Errorf("rule %s: %+v", c.ID, c)
		}
		got[c.Operation] = c.RequiresFacts[0]
	}
	if !maps.Equal(got, want) {
		t.Fatalf("rules %v, want %v", got, want)
	}
	trigger, _ := p.Definition("github.deployment.trigger")
	if len(trigger.Mappings) != 0 || trigger.Dispatch != nil {
		t.Fatal("the deployment trigger is mapped or dispatchable")
	}
}

// TestHR205_TheMergeIsBoundToTheHeadSHA: the merge carries the head SHA as
// a required material parameter in its dedupe key and sends it to GitHub;
// a fresh github.pull.head is a prerequisite, and its change supersedes
// unconsumed approvals.
func TestHR205_TheMergeIsBoundToTheHeadSHA(t *testing.T) {
	p, err := Decode(pcgithub.Package)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := p.Definition("github.pull.merge")
	sha := m.Params["sha"]
	if !sha.Material || !sha.Required || sha.Type != domain.TypeIdentifier || m.Reversibility != domain.Irreversible ||
		!slices.Contains(m.Dedupe, "params.sha") || m.Dispatch.HTTP.Body["sha"] != "params.sha" || m.Dispatch.HTTP.Method != http.MethodPut {
		t.Fatalf("merge %+v", m)
	}
	head := slices.IndexFunc(m.Prerequisites, func(p domain.Prerequisite) bool { return p.Fact == "github.pull.head" })
	if head < 0 || m.Prerequisites[head].MaxAgeSeconds != 30 || m.Approval.InvalidateOn != "github.pull.head" {
		t.Fatalf("head fact %+v, invalidate_on %q", m.Prerequisites, m.Approval.InvalidateOn)
	}
}
