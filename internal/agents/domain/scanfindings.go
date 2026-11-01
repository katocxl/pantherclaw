// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Kinds of a local scan's findings that carry only named attributes (G0 M24
// D233, D238).
const (
	ScanKindHook      = "hook"
	ScanKindSkill     = "skill"
	ScanKindEnvSecret = "env_secret"
)

// ScanSecretKinds are the credential kinds a scan reports as present: those
// the recommendations catalog reads (D238). A finding holds the kind and
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

// scanNamedAttributes are the attributes the server keeps of the other local
// kinds. Any other attribute of theirs is dropped and counted (D252).
var scanNamedAttributes = map[string][]string{
	"mcp_server":    {"client", "config", "name", "transport", "command", "package_ref", "url_host", "env_names", "header_names", "managed_settings"},
	"agent_project": {"path", "manifest", "frameworks", "managed_settings"},
}

// maxScanValue is the longest attribute value, in bytes (the API's limit).
const maxScanValue = 256

// scanValueOK reports whether v is plain text an operator can be shown: valid
// UTF-8 of at most maxScanValue bytes with no control or format (bidi)
// characters.
func scanValueOK(v string) bool {
	if len(v) > maxScanValue || !utf8.ValidString(v) {
		return false
	}
	return !strings.ContainsFunc(v, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029
	})
}

// CleanScanAttributes is what the server keeps of a finding's attributes:
// those a kind names, with plain values. It returns how many it dropped
// (D252). A kind with no list keeps nothing.
func CleanScanAttributes(kind string, attrs map[string]string) (map[string]string, int) {
	names, ok := scanAttributes[kind]
	if !ok {
		names = scanNamedAttributes[kind]
	}
	kept, dropped := make(map[string]string, len(attrs)), 0
	for k, v := range attrs {
		if slices.Contains(names, k) && scanValueOK(v) {
			kept[k] = v
		} else {
			dropped++
		}
	}
	return kept, dropped
}

// deviceScopeHexLen is the length of a device scope's hex id (G0 M24 D234).
const deviceScopeHexLen = 16

// DeviceScope reports whether scope is a laptop's own scan scope: `device:`
// and 16 lower-case hex digits (G0 M24 D234).
func DeviceScope(scope string) bool {
	id, ok := strings.CutPrefix(scope, "device:")
	if !ok || len(id) != deviceScopeHexLen {
		return false
	}
	for _, r := range id {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
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
