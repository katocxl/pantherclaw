// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package manifest

import (
	"fmt"
	"maps"
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
	if p.Name != pcgithub.Name || p.Version != pcgithub.Version || len(p.Consequences) != 1 {
		t.Fatalf("decoded %s %s with %d consequence rules", p.Name, p.Version, len(p.Consequences))
	}
}

// TestHR203_EveryGitHubOperationDeclaresItsLeastPermissions: the broker
// mints each installation token with exactly the operation's declared
// GitHub App permissions, so every operation declares them, and a write
// never needs more than one permission at write level.
func TestHR203_EveryGitHubOperationDeclaresItsLeastPermissions(t *testing.T) {
	p, err := Decode(pcgithub.Package)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]string{
		"github.repository.get":            {"metadata": "read"},
		"github.contents.get":              {"contents": "read"},
		"github.branch.list":               {"contents": "read"},
		"github.branch.create":             {"contents": "write"},
		"github.pull_request.create":       {"pull_requests": "write"},
		"github.pull_request.reviews.list": {"pull_requests": "read"},
		"github.pull_request.merge":        {"contents": "write"},
		"github.repository.update":         {"administration": "write"},
		"github.pull_request.get":          {"pull_requests": "read"},
	}
	if len(p.Definitions) != len(want) {
		t.Fatalf("%d definitions, want %d", len(p.Definitions), len(want))
	}
	for _, d := range p.Definitions {
		if got := d.Scopes(); !maps.Equal(got, want[d.Operation]) {
			t.Errorf("%s: scopes %v, want %v", d.Operation, got, want[d.Operation])
		}
	}
}

// TestHR205_TheMergeIsBoundToTheHeadSHA: the merge carries the head SHA as
// a required material parameter in its dedupe key and sends it to GitHub,
// and a merge into a branch that deploys on push is a deployment
// consequence that needs a verified fact (HR-206).
func TestHR205_TheMergeIsBoundToTheHeadSHA(t *testing.T) {
	p, err := Decode(pcgithub.Package)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := p.Definition("github.pull_request.merge")
	sha := m.Params["sha"]
	if !sha.Material || !sha.Required || sha.Type != domain.TypeIdentifier || m.Reversibility != domain.Irreversible ||
		!strings.Contains(strings.Join(m.Dedupe, ","), "params.sha") || m.Dispatch.HTTP.Body["sha"] != "params.sha" ||
		m.Dispatch.HTTP.Method != "PUT" {
		t.Fatalf("merge %+v", m)
	}
	c := p.Consequences[0]
	if c.Operation != m.Operation || c.Consequence.Effect != "deployment.start" ||
		len(c.RequiresFacts) != 1 || c.RequiresFacts[0] != "github.pull_request.deploys_on_merge" {
		t.Fatalf("consequence %+v", c)
	}
}
