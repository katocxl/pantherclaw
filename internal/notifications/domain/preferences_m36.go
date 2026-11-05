// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"regexp"
	"slices"
	"strconv"
	"time"
	_ "time/tzdata" // quiet hours name IANA zones; they must not depend on the host's zone files
)

// Per-person notification preferences, digests and Web Push (G0 M36 D1065,
// D1066; HR-792, HR-793). A digest and quiet hours delay only the person's
// own emails, direct messages and pushes; channels, routing and escalation
// to other people never wait.

// KindWebPush is a delivery to one person's browsers through their push
// subscriptions (Team edition). It is not a channel kind.
const KindWebPush Kind = "web_push"

// How approval notices reach a person.
const (
	DeliveryImmediate = "IMMEDIATE"
	DeliveryDigest    = "DIGEST"
)

// DigestType is the notice a digest sends.
const DigestType = "approval.digest"

// DigestWindows are the digest windows in minutes; the first is the
// default.
var DigestWindows = []int{15, 30, 60}

// ErrPreferences refuses preferences outside their bounds.
var ErrPreferences = errors.New("notifications: invalid preferences")

var clock = regexp.MustCompile(`^([01][0-9]|2[0-3]):([0-5][0-9])$`)

// Preferences are one person's preferences; QuietStart and QuietEnd are
// HH:MM, both set or both empty, in TimeZone (UTC when empty).
type Preferences struct {
	Delivery             string
	DigestMinutes        int
	QuietStart, QuietEnd string
	TimeZone             string
	UpdatedAt            time.Time
}

// DefaultPreferences are a person's preferences until they set some.
func DefaultPreferences() Preferences {
	return Preferences{Delivery: DeliveryImmediate, DigestMinutes: DigestWindows[0]}
}

// Validate checks the preferences.
func (p Preferences) Validate() error {
	switch {
	case p.Delivery != DeliveryImmediate && p.Delivery != DeliveryDigest:
		return ErrPreferences
	case !slices.Contains(DigestWindows, p.DigestMinutes):
		return ErrPreferences
	case (p.QuietStart == "") != (p.QuietEnd == ""):
		return ErrPreferences
	case p.QuietStart != "" && (!clock.MatchString(p.QuietStart) || !clock.MatchString(p.QuietEnd) || p.QuietStart == p.QuietEnd):
		return ErrPreferences
	case len(p.TimeZone) > 64:
		return ErrPreferences
	}
	if _, err := p.location(); err != nil {
		return ErrPreferences
	}
	return nil
}

func (p Preferences) location() (*time.Location, error) {
	if p.TimeZone == "" {
		return time.UTC, nil
	}
	if p.TimeZone == "Local" {
		return nil, ErrPreferences
	}
	return time.LoadLocation(p.TimeZone)
}

func minutes(hhmm string) int {
	m := clock.FindStringSubmatch(hhmm)
	h, _ := strconv.Atoi(m[1])
	mm, _ := strconv.Atoi(m[2])
	return h*60 + mm
}

// QuietUntil returns when the quiet hours that hold now end, or the zero
// time when now is outside them (or none are set). The end may be before
// the start: quiet hours then run overnight.
func (p Preferences) QuietUntil(now time.Time) time.Time {
	if p.QuietStart == "" || !clock.MatchString(p.QuietStart) || !clock.MatchString(p.QuietEnd) {
		return time.Time{}
	}
	loc, err := p.location()
	if err != nil {
		return time.Time{}
	}
	local := now.In(loc)
	m := local.Hour()*60 + local.Minute()
	start, end := minutes(p.QuietStart), minutes(p.QuietEnd)
	day := 0
	switch {
	case start < end && m >= start && m < end:
	case start > end && m >= start:
		day = 1
	case start > end && m < end:
	default:
		return time.Time{}
	}
	y, mo, d := local.Date()
	return time.Date(y, mo, d+day, end/60, end%60, 0, 0, loc)
}

// DigestReplaces reports whether a digest replaces a person's notice of
// this type: a new, escalated or reminded approval request.
func DigestReplaces(notificationType string) bool {
	switch notificationType {
	case "approval.requested", "approval.escalated", "approval.reminder":
		return true
	}
	return false
}

// QuietDelays reports whether a person's quiet hours delay a notice of
// this type: the approval notices and the digest. Security notices are
// never delayed.
func QuietDelays(notificationType string) bool {
	return DigestReplaces(notificationType) || notificationType == DigestType
}

// PushEvent reports whether a notice of this type is also pushed to the
// person's browsers.
func PushEvent(notificationType string) bool { return QuietDelays(notificationType) }

// PushPayloadFor is the link-only payload of a push (HR-793): "Approval
// waiting" with the request's page, or for a digest "N approvals waiting"
// with the approvals page. publicURL has no trailing slash; request is a
// canonical id or "".
func PushPayloadFor(publicURL, notificationType, request string, count int) PushPayload {
	if notificationType == DigestType {
		return PushPayload{Title: strconv.Itoa(count) + " approvals waiting", URL: publicURL + "/approvals"}
	}
	if idValue.MatchString(request) {
		return PushPayload{Title: "Approval waiting", URL: publicURL + "/approvals/" + request}
	}
	return PushPayload{Title: "Approval waiting", URL: publicURL + "/approvals"}
}

// m36Templates are the digest notice: a count and a link, nothing about
// any one request (HR-158, HR-313).
var m36Templates = []Template{
	{
		Type: DigestType, Severity: Warning, Params: []string{"count"},
		Title: "{count} approvals are waiting for you",
		Body: "{count} approval requests routed to you are waiting for a decision. Open the approvals page to see " +
			"each one and decide there.",
		Link: "/approvals",
	},
}

func init() { templates = append(templates, m36Templates...) }
