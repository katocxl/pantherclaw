// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package broker

import (
	"encoding/json/v2"
	"errors"
	"slices"
	"testing"
)

// The session policy of a Bedrock call through a system inference profile
// allows the one action on the profile and its foundation model, with no
// other wildcard; any other shape is refused and nothing is signed
// (HR-727, G0 M31 D961a).
func TestHR727_ABedrockProfilePolicyNamesOnlyTheProfileAndItsModel(t *testing.T) {
	const model = "anthropic.claude-sonnet-4-5-20250929-v1:0"
	profile := "arn:aws:bedrock:us-east-1:*:inference-profile/us." + model
	fm := "arn:aws:bedrock:*::foundation-model/" + model
	p, err := BedrockProfilePolicy("bedrock", "InvokeModel", []string{profile, fm})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Statement []struct {
			Effect, Action string
			Resource       []string
		}
	}
	if err := json.Unmarshal([]byte(p), &doc); err != nil || len(doc.Statement) != 1 || doc.Statement[0].Effect != "Allow" ||
		doc.Statement[0].Action != "bedrock:InvokeModel" || !slices.Equal(doc.Statement[0].Resource, []string{profile, fm}) {
		t.Fatalf("policy %s: %v", p, err)
	}
	for name, c := range map[string]struct {
		service   string
		resources []string
	}{
		"another service":      {"s3", []string{profile, fm}},
		"one resource":         {"bedrock", []string{profile}},
		"a third resource":     {"bedrock", []string{profile, fm, fm}},
		"a wildcard profile":   {"bedrock", []string{"arn:aws:bedrock:*:*:inference-profile/us." + model, fm}},
		"a wildcard model":     {"bedrock", []string{profile, "arn:aws:bedrock:*::foundation-model/*"}},
		"not a profile":        {"bedrock", []string{"arn:aws:bedrock:us-east-1::foundation-model/" + model, fm}},
		"an unknown geography": {"bedrock", []string{"arn:aws:bedrock:us-east-1:*:inference-profile/xx." + model, fm}},
	} {
		if _, err := BedrockProfilePolicy(c.service, "InvokeModel", c.resources); !errors.Is(err, ErrAWSAction) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
