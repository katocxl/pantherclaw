// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// PayloadFindingInput is a credential-shaped value the gateway found in an
// action's payload (HR-225).
type PayloadFindingInput struct{ Kind, Location string }

// PayloadFindingLine is a payload finding on the approval page: the format
// and where it was found, never the value. The location can carry names the
// agent chose, so it is cleaned like any untrusted text.
type PayloadFindingLine struct {
	Kind     string `json:"kind"`
	Location string `json:"location"`
}

func payloadFindingLines(in []PayloadFindingInput) []PayloadFindingLine {
	var out []PayloadFindingLine
	for _, f := range in[:min(len(in), maxShown)] {
		out = append(out, PayloadFindingLine{Kind: Clean("", f.Kind, 32).Text, Location: Clean("", f.Location, 256).Text})
	}
	return out
}
