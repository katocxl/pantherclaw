// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	pcbedrock "github.com/katocxl/pantherclaw/packages/pc-bedrock"
)

const bedrockModel = "anthropic.claude-sonnet-4-5-20250929-v1:0"

// A Bedrock call through a system inference profile needs the profile in
// the session's region and its foundation model in any region, and nothing
// more; a plain model id needs no profile resources; an id, region or
// partition of any other shape fails closed (HR-727, G0 M31 D961a).
func TestHR727_BedrockProfileResourcesAreTheProfileAndItsModelOnly(t *testing.T) {
	p, err := manifest.Decode(pcbedrock.Package)
	if err != nil {
		t.Fatal(err)
	}
	d, ok := p.Definition("bedrock.converse.create")
	if !ok {
		t.Fatal("no bedrock.converse.create")
	}
	target := func(id string) actionir.Target { return actionir.Target{Type: "model", ID: id} }

	for _, c := range []struct{ id, partition, profile string }{
		{"us." + bedrockModel, "aws", "arn:aws:bedrock:us-east-1:*:inference-profile/us." + bedrockModel},
		{"us-gov." + bedrockModel, "aws-us-gov", "arn:aws-us-gov:bedrock:us-east-1:*:inference-profile/us-gov." + bedrockModel},
	} {
		res, ok, err := d.BedrockProfileResources(target(c.id), "us-east-1", c.partition)
		want := []string{c.profile, "arn:" + c.partition + ":bedrock:*::foundation-model/" + bedrockModel}
		if err != nil || !ok || !slices.Equal(res, want) {
			t.Errorf("%s: %v %v %v", c.id, res, ok, err)
		}
	}
	if res, ok, err := d.BedrockProfileResources(target(bedrockModel), "us-east-1", "aws"); err != nil || ok || res != nil {
		t.Errorf("a plain model id: %v %v %v", res, ok, err)
	}
	for name, c := range map[string]struct{ id, region, partition string }{
		"bad region":    {"us." + bedrockModel, "US_EAST_1", "aws"},
		"bad partition": {"us." + bedrockModel, "us-east-1", "gcp"},
		"bad model":     {"us.anthropic", "us-east-1", "aws"},
	} {
		if res, ok, err := d.BedrockProfileResources(target(c.id), c.region, c.partition); err == nil || !ok || res != nil {
			t.Errorf("%s: %v %v %v", name, res, ok, err)
		}
	}
}
