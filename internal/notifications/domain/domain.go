// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the notification rules of G0 M5 part 1 (HR-157..159):
// channel kinds and subscriptions, severities, the fixed templates every
// message is rendered from, destination checks for webhook and Slack URLs,
// and Standard Webhooks signatures. It is pure: no I/O.
package domain

import (
	"errors"
	"regexp"
	"slices"
	"strings"
)

// Kind is a channel kind.
type Kind string

// Channel kinds.
const (
	KindLog     Kind = "log"
	KindEmail   Kind = "email"
	KindSlack   Kind = "slack"
	KindWebhook Kind = "webhook"
)

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool {
	return slices.Contains([]Kind{KindLog, KindEmail, KindSlack, KindWebhook, KindSlackApp, KindTeamsApp}, k)
}

// HasSecret reports whether channels of kind k hold an encrypted secret
// (the Slack webhook URL, the webhook signing secret, the Slack bot
// token).
func (k Kind) HasSecret() bool {
	return k == KindSlack || k == KindWebhook || k == KindSlackApp || k == KindTeamsApp
}

// Severity orders notifications.
type Severity string

// Severities.
const (
	Info     Severity = "INFO"
	Warning  Severity = "WARNING"
	Critical Severity = "CRITICAL"
)

var severityRank = map[Severity]int{Info: 0, Warning: 1, Critical: 2}

// Valid reports whether s is a known severity.
func (s Severity) Valid() bool { _, ok := severityRank[s]; return ok }

// AtLeast reports whether s is at least min.
func (s Severity) AtLeast(minimum Severity) bool { return severityRank[s] >= severityRank[minimum] }

// Subscription limits.
const (
	MaxEventTypes = 32
	maxPattern    = 64
)

var (
	typePattern    = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,3}$`)
	prefixPattern  = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){0,2}\.\*$`)
	channelPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// ErrInvalid reports invalid channel settings.
var ErrInvalid = errors.New("notifications: invalid channel settings")

// ValidChannelName reports whether n is a valid channel name.
func ValidChannelName(n string) bool { return channelPattern.MatchString(n) }

// ValidEventTypes checks a subscription: 1-32 exact types or prefixes
// ending in ".*" (a bare "*" is not allowed: a channel says what it wants).
func ValidEventTypes(ps []string) error {
	if len(ps) == 0 || len(ps) > MaxEventTypes {
		return ErrInvalid
	}
	for _, p := range ps {
		if len(p) > maxPattern || (!typePattern.MatchString(p) && !prefixPattern.MatchString(p)) {
			return ErrInvalid
		}
	}
	return nil
}

// Matches reports whether event type t matches one of the patterns.
func Matches(patterns []string, t string) bool {
	for _, p := range patterns {
		if p == t || (strings.HasSuffix(p, ".*") && strings.HasPrefix(t, strings.TrimSuffix(p, "*"))) {
			return true
		}
	}
	return false
}
