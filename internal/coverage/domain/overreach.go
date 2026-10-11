// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/json/v2"
	"slices"
	"strings"
)

// Permissions maps a target permission to its level, e.g. "contents" →
// "write" (GitHub App permissions; G0 M9 decision 9).
type Permissions map[string]string

// levels orders permission levels.
var levels = map[string]int{"read": 1, "write": 2, "admin": 3}

// ParsePermissions reads permissions written as a JSON object
// ({"contents":"write"}) or a comma list (contents:write,metadata:read).
// Malformed entries are left out. An unknown level is kept: Merge drops
// it, so it declares nothing, and Overreach ranks it held as admin.
func ParsePermissions(s string) Permissions {
	out := Permissions{}
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "{") {
		var m map[string]string
		if json.Unmarshal([]byte(s), &m) != nil {
			return out
		}
		for k, v := range m {
			if k != "" && v != "" {
				out[k] = v
			}
		}
		return out
	}
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), ":")
		if ok && k != "" && v != "" {
			out[k] = v
		}
	}
	return out
}

// Merge returns the higher level of each permission of p and q.
func (p Permissions) Merge(q Permissions) Permissions {
	out := Permissions{}
	for _, m := range []Permissions{p, q} {
		for k, v := range m {
			if levels[v] > levels[out[k]] {
				out[k] = v
			}
		}
	}
	return out
}

// List renders p as sorted "name:level" entries.
func (p Permissions) List() []string {
	out := make([]string, 0, len(p))
	for k, v := range p {
		out = append(out, k+":"+v)
	}
	slices.Sort(out)
	return out
}

// sensitive permissions make write access a high-severity excess: they
// change code, CI, secrets, hooks, runners, roles or membership.
var sensitive = []string{
	"actions", "administration", "codespaces_secrets", "contents", "dependabot_secrets", "environments", "members",
	"organization_administration", "organization_custom_org_roles", "organization_custom_roles", "organization_hooks",
	"organization_personal_access_token_requests", "organization_personal_access_tokens", "organization_secrets",
	"organization_self_hosted_runners", "repository_hooks", "secrets", "workflows",
}

// implicit is what every GitHub App holds whatever it asks for, so it
// counts as declared.
var implicit = Permissions{"metadata": "read"}

// heldLevel ranks a held level; one it does not know ranks as admin.
func heldLevel(v string) int {
	if l, ok := levels[v]; ok {
		return l
	}
	return levels["admin"]
}

// Overreach is the reach a credential holds beyond what the connection's
// operations declare they need (F048): exposure, never extra permission.
// Its severity is critical for any admin excess, high for write access to
// a sensitive permission, medium for other write access, low for reads.
// A held level it does not know counts as admin; metadata:read counts as
// declared.
func Overreach(declared, held Permissions) (excess []string, severity string) {
	declared = declared.Merge(implicit)
	rank := 0
	for k, v := range held {
		l := heldLevel(v)
		if l <= levels[declared[k]] {
			continue
		}
		excess = append(excess, k+":"+v)
		r := l
		if v == "write" && slices.Contains(sensitive, k) {
			r = 3
		}
		if l == levels["admin"] {
			r = 4
		}
		rank = max(rank, r)
	}
	slices.Sort(excess)
	return excess, [...]string{"", "low", "medium", "high", "critical"}[rank]
}
