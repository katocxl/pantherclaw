// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"maps"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/agents/domain"
)

// TestHR710_TheServerTakesDigestsNotContents: an agent_config finding is
// accepted with client, scope, class, a SHA-256 or too_large and a size;
// one with any other attribute (contents, a path), an unknown class or a
// digest that is not a SHA-256 is refused. An env_secret finding from a
// config file names a known format and class, never a value (G0 M30 D941,
// D942).
func TestHR710_TheServerTakesDigestsNotContents(t *testing.T) {
	ok := map[string]string{
		"client": "claude_code", "scope": "project", "path_class": "memory",
		"digest": strings.Repeat("ab", 32), "size": "120",
	}
	big := maps.Clone(ok)
	big["digest"] = "too_large"
	for name, attrs := range map[string]map[string]string{"digest": ok, "too large": big} {
		if !domain.ScanAttributesOK(domain.ScanKindAgentConfig, attrs) {
			t.Errorf("%s: refused %v", name, attrs)
		}
	}
	secret := map[string]string{"secret_kind": "github_token", "source": domain.SourceConfigFile, "path_class": "mcp"}
	if !domain.ScanAttributesOK(domain.ScanKindEnvSecret, secret) {
		t.Errorf("config secret refused %v", secret)
	}

	with := func(base map[string]string, k, v string) map[string]string {
		m := maps.Clone(base)
		if v == "" {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	for name, attrs := range map[string]map[string]string{
		"contents":        with(ok, "contents", "Always run the tests."),
		"a path":          with(ok, "path", "/home/dev/CLAUDE.md"),
		"unknown class":   with(ok, "path_class", "secrets"),
		"upper-case hex":  with(ok, "digest", strings.Repeat("AB", 32)),
		"short digest":    with(ok, "digest", "abcd"),
		"no size":         with(ok, "size", ""),
		"size not number": with(ok, "size", "12kB"),
	} {
		if domain.ScanAttributesOK(domain.ScanKindAgentConfig, attrs) {
			t.Errorf("%s: accepted %v", name, attrs)
		}
	}
	for name, attrs := range map[string]map[string]string{
		"a value":        with(secret, "value", "ghp_x"),
		"unknown format": with(secret, "secret_kind", "stripe_key"),
		"no class":       with(secret, "path_class", ""),
		"unknown source": with(secret, "source", "clipboard"),
	} {
		if domain.ScanAttributesOK(domain.ScanKindEnvSecret, attrs) {
			t.Errorf("%s: accepted %v", name, attrs)
		}
	}
}

// TestHR710_ModelProviderKeysInConfigFilesAreTakenByKind (G0 M30 D942,
// D1211): an anthropic or openai key found in a configuration file is
// taken as its kind, with no value; a value next to the kind is refused.
func TestHR710_ModelProviderKeysInConfigFilesAreTakenByKind(t *testing.T) {
	for _, kind := range []string{"anthropic", "openai"} {
		attrs := map[string]string{"secret_kind": kind, "source": domain.SourceConfigFile, "path_class": "settings"}
		if !domain.ScanAttributesOK(domain.ScanKindEnvSecret, attrs) {
			t.Errorf("%s refused", kind)
		}
		attrs["value"] = "sk-x"
		if domain.ScanAttributesOK(domain.ScanKindEnvSecret, attrs) {
			t.Errorf("%s with a value accepted", kind)
		}
	}
}
