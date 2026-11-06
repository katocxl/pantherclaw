// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"regexp"
	"strings"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// BedrockProfilePrefixes are the geographies of Bedrock's system
// inference profiles (G0 M31 D961a): a model id such as
// us.anthropic.claude-… names the profile, which routes to the foundation
// model the rest of the id names, in any of the geography's regions.
// us-gov. comes before us. so the longer prefix wins.
var BedrockProfilePrefixes = []string{"us-gov.", "us.", "eu.", "apac.", "global.", "jp.", "au."}

var (
	// bedrockModelRe is a foundation model id: provider.model[:version].
	bedrockModelRe  = regexp.MustCompile(`^[a-z0-9-]{1,32}\.[A-Za-z0-9._:-]{1,200}$`)
	bedrockRegionRe = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	bedrockPartRe   = regexp.MustCompile(`^aws(-[a-z-]{1,16})?$`)
)

// BedrockProfile splits a system inference profile id into its prefix and
// the foundation model id after it; ok is false for a plain model id.
func BedrockProfile(id string) (prefix, model string, ok bool) {
	for _, p := range BedrockProfilePrefixes {
		if rest, found := strings.CutPrefix(id, p); found {
			return p, rest, true
		}
	}
	return "", "", false
}

// BedrockProfileResources are the resources a Bedrock call through a
// system inference profile needs, and nothing more (G0 M31 D961a): the
// profile in the session's region, any account, and its foundation model
// in any region (the profile routes the call to one of its geography's).
// ok is false when the def is no Bedrock model call or the target is no
// profile id; an id or region of any other shape is an error (fail closed).
func (d *Definition) BedrockProfileResources(target actionir.Target, region, partition string) (resources []string, ok bool, err error) {
	if !d.IsModel() || !bedrockAPI(d.Dispatch.Model.API) {
		return nil, false, nil
	}
	_, model, isProfile := BedrockProfile(target.ID)
	if !isProfile {
		return nil, false, nil
	}
	if !bedrockModelRe.MatchString(target.ID) || !bedrockModelRe.MatchString(model) || !bedrockRegionRe.MatchString(region) ||
		!bedrockPartRe.MatchString(partition) {
		return nil, true, invalid("%s: %q is not a Bedrock inference profile id", d.Operation, target.ID)
	}
	return []string{
		"arn:" + partition + ":bedrock:" + region + ":*:inference-profile/" + target.ID,
		"arn:" + partition + ":bedrock:*::foundation-model/" + model,
	}, true, nil
}
