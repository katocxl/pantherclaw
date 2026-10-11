// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Template renders one notification type (HR-158). Title and Body hold
// {name} placeholders for declared parameters only; there are no free-text
// parameters and no agent text, and a message never offers an action: it
// links to the authenticated page.
type Template struct {
	Type     string
	Severity Severity
	Title    string
	Body     string
	Params   []string
	// Link is the PantherClaw page the message points to ("" for none).
	Link string
}

// Rendered is a notification ready to store.
type Rendered struct {
	Type, Title, Body, Link string
	Severity                Severity
}

// Limits on rendered text (the notifications table checks them too).
const (
	MaxTitle      = 200
	MaxBody       = 2000
	MaxParamValue = 200
)

// Errors from rendering.
var (
	ErrUnknownType = errors.New("notifications: unknown notification type")
	ErrBadParams   = errors.New("notifications: parameters do not match the template")
)

// templates are the part-1 notification types. Part 2 adds the approval
// types. Every type and parameter is listed here; nothing else renders.
var templates = []Template{
	{
		Type: "channel.test", Severity: Info, Params: []string{"channel"},
		Title: "Test notification from PantherClaw",
		Body:  "This is a test of the notification channel {channel}. No action is needed.",
	},
	{
		Type: "security.credential_registered", Severity: Warning, Params: []string{"user", "key_name"},
		Title: "A security key was added to a PantherClaw account",
		Body: "The security key \"{key_name}\" was added to the account of {user}. " +
			"If this was not you, remove it on your account page and tell your administrator.",
		Link: "/account",
	},
	{
		Type: "security.credential_removed", Severity: Warning, Params: []string{"user", "key_name"},
		Title: "A security key was removed from a PantherClaw account",
		Body: "The security key \"{key_name}\" was removed from the account of {user}. " +
			"If this was not you, tell your administrator.",
		Link: "/account",
	},
	{
		Type: "security.credential_suspended", Severity: Critical, Params: []string{"user", "key_name"},
		Title: "A security key was suspended (possible copy)",
		Body: "The security key \"{key_name}\" of {user} reported a signature counter that did not move forward, " +
			"which can mean the key was copied. It was suspended; remove it and add a new one on the account page.",
		Link: "/account",
	},
	{
		Type: "security.sessions_revoked", Severity: Warning, Params: []string{"user", "count"},
		Title: "Your PantherClaw sessions were signed out",
		Body:  "An administrator signed out {count} sessions of {user}. Sign in again to continue.",
		Link:  "/account",
	},
	{
		Type: "notification.channel_paused", Severity: Warning, Params: []string{"channel", "reason"},
		Title: "A notification channel was paused",
		Body:  "The notification channel {channel} was paused: {reason}. Fix the destination and resume the channel.",
	},
}

// Types lists the registered notification types.
func Types() []string {
	out := make([]string, len(templates))
	for i, t := range templates {
		out[i] = t.Type
	}
	return out
}

// Lookup returns the template of a type.
func Lookup(typ string) (Template, bool) {
	i := slices.IndexFunc(templates, func(t Template) bool { return t.Type == typ })
	if i < 0 {
		return Template{}, false
	}
	return templates[i], true
}

var placeholder = regexp.MustCompile(`\{([a-z_]+)\}`)

// Render fills a template with params, which must be exactly the declared
// ones. Values are single-line plain text: control, format (bidi) and line
// separator characters are refused, and values are at most 200 characters.
func Render(typ string, params map[string]string) (Rendered, error) {
	t, ok := Lookup(typ)
	if !ok {
		return Rendered{}, ErrUnknownType
	}
	if len(params) != len(t.Params) {
		return Rendered{}, ErrBadParams
	}
	for _, p := range t.Params {
		v, ok := params[p]
		if !ok || !PlainValue(v) {
			return Rendered{}, fmt.Errorf("%w: %s", ErrBadParams, p)
		}
	}
	fill := func(s string) string {
		return placeholder.ReplaceAllStringFunc(s, func(m string) string { return params[m[1:len(m)-1]] })
	}
	r := Rendered{Type: t.Type, Severity: t.Severity, Title: fill(t.Title), Body: fill(t.Body), Link: t.Link}
	if utf8.RuneCountInString(r.Title) > MaxTitle || utf8.RuneCountInString(r.Body) > MaxBody {
		return Rendered{}, ErrBadParams
	}
	// A link holds at most an id placeholder (the request's, G0 M5 part 2;
	// the reconciliation's, G0 M7), and only a canonical id fills it, so a
	// link always opens a PantherClaw page.
	for _, m := range placeholder.FindAllStringSubmatch(t.Link, -1) {
		if !slices.Contains(linkParams, m[1]) || !idValue.MatchString(params[m[1]]) {
			return Rendered{}, fmt.Errorf("%w: link %s", ErrBadParams, m[1])
		}
	}
	r.Link = fill(t.Link)
	return r, nil
}

// linkParams are the placeholders a link may hold.
var linkParams = []string{"request", "reconciliation"}

var idValue = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// PlainValue reports whether v is acceptable as a template parameter.
func PlainValue(v string) bool {
	if v == "" || !utf8.ValidString(v) || utf8.RuneCountInString(v) > MaxParamValue || strings.TrimSpace(v) != v {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029 {
			return false
		}
	}
	return true
}
