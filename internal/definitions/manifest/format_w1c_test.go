// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package manifest

import (
	"errors"
	"maps"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	pcgithub "github.com/katocxl/pantherclaw/packages/pc-github"
)

// TestHR206_ADeploymentIsVerifiedByItsCommitAndEnvironment: the deployment
// a merge starts has a verifier of its own (G0 M8 W1c). The merge's
// verifier captures the merge commit; the deployment's verifier finds
// GitHub's deployment of that commit to that environment by a matched
// lookup (no idempotency key: it was never dispatched), reads its statuses
// in the same lease, and sends a failure or an error to a person. Every
// malformed form of the new fields is refused.
func TestHR206_ADeploymentIsVerifiedByItsCommitAndEnvironment(t *testing.T) {
	p, err := Decode(pcgithub.Package)
	if err != nil {
		t.Fatal(err)
	}
	merge, _ := p.Definition("github.pull.merge")
	if !maps.Equal(merge.Verifier.Capture, map[string]string{"sha": "/merge_commit_sha"}) {
		t.Fatalf("the merge captures %v", merge.Verifier.Capture)
	}
	trigger, _ := p.Definition("github.deployment.trigger")
	v := trigger.Verifier
	if v == nil || !v.Extended() || v.Operation != "github.deployment.statuses" || v.WithinSeconds != 3600 || v.Lookup == nil ||
		v.Lookup.Operation != "github.deployment.list" || v.Lookup.IDParam != "deployment_id" || v.Lookup.List.Correlate != "" ||
		len(v.Lookup.Match) != 2 || v.States.Field != "/0/state" {
		t.Fatalf("the deployment's verifier %+v", v)
	}
	if !slices.Equal(v.States.Confirmed, []string{"success", "inactive"}) || !slices.Equal(v.States.Pending, []string{"queued", "pending", "in_progress"}) ||
		!slices.Equal(v.States.Reconcile, []string{"failure", "error"}) || len(v.States.None) != 0 {
		t.Fatalf("states %+v", v.States)
	}

	for name, change := range map[string][2]string{
		"a match and a correlation":          {"          id: /id\n        match:", "          id: /id\n          correlate: /sha\n        match:"},
		"a match without id_param":           {"        id_param: deployment_id\n", ""},
		"an id_param not of the read":        {"id_param: deployment_id", "id_param: sha"},
		"a match on untrusted text":          {"equals: params.environment", "equals: target.id"},
		"a match on an undeclared param":     {"equals: params.environment", "equals: params.ref"},
		"a field matched twice":              {"field: /environment", "field: /sha"},
		"a reconcile status twice":           {"reconcile: [failure, error]", "reconcile: [failure, success]"},
		"a capture that is not a pointer":    {"sha: /merge_commit_sha", "sha: merge_commit_sha"},
		"a capture of no param name":         {"sha: /merge_commit_sha", "Merge SHA: /merge_commit_sha"},
		"a list items that is not a pointer": {"items: ''", "items: deployments"},
	} {
		if _, err := Decode(mutate(t, pcgithub.Package, change[0], change[1])); !errors.Is(err, domain.ErrInvalid) && !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
