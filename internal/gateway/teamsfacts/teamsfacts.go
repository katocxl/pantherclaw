// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package teamsfacts reads the Microsoft Teams facts pc.teams names (G0 M20
// D254, HR-524): whether a channel admits people from outside the tenant
// the bot posts for. It parses the Bot Connector's paged channel members
// and never guesses: a channel it cannot read whole is unread, so the
// decision sees the fact missing (HR-160), never an internal channel.
//
// Microsoft advises against relying on a channel's type to tell shared
// channels apart, so the fact is read from the members themselves: a
// channel is external when any member belongs to another tenant than the
// target's, is a guest or anonymous, or when its members span more than
// one tenant.
package teamsfacts

import (
	"encoding/json/v2"
	"regexp"
	"strconv"
)

// ChannelExternal is the fact a post's prerequisite and its consequence
// rule name.
const ChannelExternal = "teams.channel.external"

// Limits of one read: members per page (the Bot Connector's maximum) and
// pages, so a read is bounded.
const (
	PageSize = 500
	MaxPages = 20
)

var (
	tenantRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	tokenRe  = regexp.MustCompile(`^[\x21-\x7e]{1,512}$`)
)

// Tally accumulates a channel's members across pages.
type Tally struct {
	tenants map[string]bool
	foreign bool
	guests  bool
	members int
}

// Page parses one pagedmembers answer into t against the host tenant, and
// returns the next page's continuation token ("" for the last page). A
// page that is not a 200, cannot be parsed, or lists a member without a
// tenant or a role gives why it is unread.
func (t *Tally) Page(status int, body []byte, tenant string) (next, unread string) {
	if status < 200 || status >= 300 {
		return "", "Teams answered " + httpStatus(status)
	}
	var a struct {
		Members *[]struct {
			TenantID string `json:"tenantId"`
			UserRole string `json:"userRole"`
		} `json:"members"`
		ContinuationToken string `json:"continuationToken"`
	}
	if json.Unmarshal(body, &a) != nil || a.Members == nil {
		return "", "Teams' answer could not be read"
	}
	if t.tenants == nil {
		t.tenants = map[string]bool{}
	}
	for _, m := range *a.Members {
		if !tenantRe.MatchString(m.TenantID) {
			return "", "a member has no tenant"
		}
		switch m.UserRole {
		case "user":
		case "guest", "anonymous":
			t.guests = true
		default:
			return "", "a member has no role"
		}
		t.tenants[m.TenantID] = true
		t.foreign = t.foreign || m.TenantID != tenant
		t.members++
	}
	if a.ContinuationToken != "" && !tokenRe.MatchString(a.ContinuationToken) {
		return "", "Teams' continuation could not be read"
	}
	return a.ContinuationToken, ""
}

// Value is the fact's value once every page was read: {external,
// other_tenant, guests, members}. A channel with no members at all is
// unread: the bot itself would be one.
func (t *Tally) Value() map[string]any {
	if t.members == 0 {
		return Unread("Teams listed no members")
	}
	foreign := t.foreign || len(t.tenants) > 1
	return map[string]any{"external": foreign || t.guests, "other_tenant": foreign, "guests": t.guests, "members": t.members}
}

// Unread is the value of a fact that was not read, with why.
func Unread(why string) map[string]any { return map[string]any{"unread": why} }

func httpStatus(s int) string {
	if s == 0 {
		return "nothing"
	}
	return "HTTP " + strconv.Itoa(s)
}
