// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package edge

import "strings"

// openAIKeyPrefixes are OpenAI's project, service account and admin key
// prefixes (G0 M29 D816).
var openAIKeyPrefixes = []string{"sk-proj-", "sk-svcacct-", "sk-admin-"}

// minOpenAILegacyKey is how many key characters must follow a bare "sk-"
// for it to read as an OpenAI key (D816).
const minOpenAILegacyKey = 32

// modelKeyKind names an Anthropic or OpenAI key (G0 M29 D816): "anthropic"
// for the prefix sk-ant-; "openai" for sk-proj-, sk-svcacct-, sk-admin-, or
// sk- followed by at least 32 characters of [A-Za-z0-9_-]; "" otherwise.
func modelKeyKind(token string) string {
	switch {
	case strings.HasPrefix(token, "sk-ant-"):
		return "anthropic"
	case !strings.HasPrefix(token, "sk-"):
		return ""
	}
	for _, p := range openAIKeyPrefixes {
		if strings.HasPrefix(token, p) {
			return "openai"
		}
	}
	rest := token[len("sk-"):]
	n := 0
	for n < len(rest) && keyChar(rest[n]) {
		n++
	}
	if n >= minOpenAILegacyKey {
		return "openai"
	}
	return ""
}

func keyChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}
