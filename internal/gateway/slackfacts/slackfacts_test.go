// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package slackfacts_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/gateway/slackfacts"
)

// TestHR316_SlackChannelFactNeverGuesses: a shared channel is external, an
// internal one is not, and anything Slack does not clearly answer is
// unread, never internal (HR-160).
func TestHR316_SlackChannelFactNeverGuesses(t *testing.T) {
	for name, c := range map[string]struct {
		status   int
		body     string
		external any
		unread   bool
	}{
		"internal":      {200, `{"ok":true,"channel":{"id":"C0APPROVAL1","is_ext_shared":false,"is_shared":false}}`, false, false},
		"ext shared":    {200, `{"ok":true,"channel":{"id":"C0APPROVAL1","is_ext_shared":true,"is_shared":true}}`, true, false},
		"shared":        {200, `{"ok":true,"channel":{"id":"C0APPROVAL1","is_ext_shared":false,"is_shared":true}}`, true, false},
		"no flags":      {200, `{"ok":true,"channel":{"id":"C0APPROVAL1"}}`, nil, true},
		"other channel": {200, `{"ok":true,"channel":{"id":"C0OTHER0001","is_ext_shared":false,"is_shared":false}}`, nil, true},
		"refused":       {200, `{"ok":false,"error":"channel_not_found"}`, nil, true},
		"rate limited":  {429, `{"ok":false,"error":"ratelimited"}`, nil, true},
		"garbage":       {200, `not json`, nil, true},
	} {
		v := slackfacts.Channel(c.status, []byte(c.body), "C0APPROVAL1")
		_, unread := v["unread"]
		if unread != c.unread || (!c.unread && v["external"] != c.external) {
			t.Errorf("%s: %v", name, v)
		}
	}
}
