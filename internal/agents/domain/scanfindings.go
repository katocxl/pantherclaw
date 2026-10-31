// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import "slices"

// Kinds of a local scan's findings that carry only named attributes (G0 M24
// D233, D238).
const (
	ScanKindHook      = "hook"
	ScanKindSkill     = "skill"
	ScanKindEnvSecret = "env_secret"
)

// ScanSecretKinds are the credential kinds a scan reports as present: those
// the recommendations catalogue reads (D238). A finding holds the kind and
// nothing of the value; other kinds stay on the machine.
var ScanSecretKinds = []string{
	"anthropic_api_key", "aws_access_key_id", "aws_secret_access_key", "google_api_key", "openai_api_key",
}

// scanAttributes are the only attributes of the closed finding kinds (HR-588).
var scanAttributes = map[string][]string{
	ScanKindHook:      {"event", "executable"},
	ScanKindSkill:     {"name", "path"},
	ScanKindEnvSecret: {"secret_kind"},
}

// ScanAttributesOK reports whether a finding's attributes are allowed: a
// finding of a closed kind carries only its named attributes, and an
// env_secret finding one of ScanSecretKinds. Other kinds are not limited here.
func ScanAttributesOK(kind string, attrs map[string]string) bool {
	allowed, closed := scanAttributes[kind]
	if !closed {
		return true
	}
	for k := range attrs {
		if !slices.Contains(allowed, k) {
			return false
		}
	}
	return kind != ScanKindEnvSecret || slices.Contains(ScanSecretKinds, attrs["secret_kind"])
}

// ScanAttributes returns the attributes a finding of a closed kind may carry,
// ok false for any other kind.
func ScanAttributes(kind string) ([]string, bool) {
	a, ok := scanAttributes[kind]
	return a, ok
}
