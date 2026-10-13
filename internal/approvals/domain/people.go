// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import "slices"

// GitHubPeople are the GitHub user ids a pull request's people fact lists
// (G0 M8, HR-207): its author and every commit author, committer and
// pusher. ok is false unless the fact says it is complete and names its
// author and its pushers, every id a positive integer: anything else
// leaves the authorship unknown, so nobody counts as independent
// (AUTHORSHIP_UNKNOWN), never someone whose id did not decode.
func GitHubPeople(people map[string]any) (out []int64, ok bool) {
	if people["complete"] != true {
		return nil, false
	}
	add := func(v any) bool {
		id, isInt := v.(int64)
		if !isInt || id <= 0 {
			return false
		}
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
		return true
	}
	if !add(people["author"]) {
		return nil, false
	}
	for _, member := range []string{"authors", "committers", "pushers"} {
		v, present := people[member]
		if !present {
			if member == "pushers" {
				return nil, false
			}
			continue
		}
		list, isList := v.([]any)
		if !isList {
			return nil, false
		}
		for _, id := range list {
			if !add(id) {
				return nil, false
			}
		}
	}
	return out, true
}
