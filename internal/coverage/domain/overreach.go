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
// Unknown levels and malformed entries are left out.
func ParsePermissions(s string) Permissions {
	out := Permissions{}
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "{") {
		var m map[string]string
		if json.Unmarshal([]byte(s), &m) != nil {
			return out
		}
		for k, v := range m {
			if levels[v] > 0 && k != "" {
				out[k] = v
			}
		}
		return out
	}
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), ":")
		if ok && k != "" && levels[v] > 0 {
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

// sensitive permissions make write access a high-severity excess.
var sensitive = []string{"administration", "members", "organization_administration", "secrets", "workflows", "environments"}

// Overreach is the reach a credential holds beyond what the connection's
// operations declare they need (F048): exposure, never extra permission.
// Its severity is critical for any admin excess, high for write access to
// a sensitive permission, medium for other write access, low for reads.
func Overreach(declared, held Permissions) (excess []string, severity string) {
	rank := 0
	for k, v := range held {
		if levels[v] <= levels[declared[k]] {
			continue
		}
		excess = append(excess, k+":"+v)
		r := levels[v]
		if v == "write" && slices.Contains(sensitive, k) {
			r = 3
		}
		if v == "admin" {
			r = 4
		}
		rank = max(rank, r)
	}
	slices.Sort(excess)
	return excess, [...]string{"", "low", "medium", "high", "critical"}[rank]
}
