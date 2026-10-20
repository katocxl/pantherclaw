// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package slackfacts reads the Slack facts pc.slack names (G0 M14 D25):
// whether Slack shares a channel outside the workspace. It parses
// conversations.info answers and never guesses: a channel it cannot read
// is unread, so the decision sees the fact missing (HR-160), never an
// internal channel.
package slackfacts

import (
	"encoding/json/v2"
	"regexp"
	"strconv"
)

// ChannelExternal is the fact a post's prerequisite and its consequence
// rule name.
const ChannelExternal = "slack.channel.external"

var codeRe = regexp.MustCompile(`^[a-z0-9_]{1,48}$`)

// Channel parses a conversations.info answer for channel into the fact's
// value: {external, ext_shared, shared}. An answer that is not ok, names
// another channel or cannot be parsed gives an unread value with why.
func Channel(status int, body []byte, channel string) map[string]any {
	if status < 200 || status >= 300 {
		return Unread("Slack answered " + httpStatus(status))
	}
	var a struct {
		OK      bool   `json:"ok"`
		Error   string `json:"error"`
		Channel *struct {
			ID        string `json:"id"`
			ExtShared *bool  `json:"is_ext_shared"`
			Shared    *bool  `json:"is_shared"`
		} `json:"channel"`
	}
	if json.Unmarshal(body, &a) != nil {
		return Unread("Slack's answer could not be read")
	}
	switch {
	case !a.OK && codeRe.MatchString(a.Error):
		return Unread("Slack refused the read: " + a.Error)
	case !a.OK:
		return Unread("Slack refused the read")
	case a.Channel == nil || a.Channel.ID != channel || a.Channel.ExtShared == nil || a.Channel.Shared == nil:
		return Unread("Slack's answer does not describe the channel")
	}
	ext, shared := *a.Channel.ExtShared, *a.Channel.Shared
	return map[string]any{"external": ext || shared, "ext_shared": ext, "shared": shared}
}

// Unread is the value of a fact that was not read, with why.
func Unread(why string) map[string]any { return map[string]any{"unread": why} }

func httpStatus(s int) string {
	if s == 0 {
		return "nothing"
	}
	return "HTTP " + strconv.Itoa(s)
}
