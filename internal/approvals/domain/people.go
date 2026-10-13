// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"slices"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// People facts (G0 M8, HR-207, F158). A fact such as github.pull.people
// lists GitHub user ids: its author, and its lists of commit authors,
// committers and pushers. An independent approval excludes the users
// linked to them in github_identities; the approval page lists every one
// of them with its linked user, or "not linked".

// MaxPeopleShown caps the people the approval page lists for one fact.
const MaxPeopleShown = 200

// Why a people list may not name everyone, as the approval page says it.
const (
	PeopleNotKnown   = "the fact is not known about the target now"
	PeopleUnreadable = "the fact's value cannot be read"
	PeopleNotAll     = "the fact says it does not list everyone (for example a fork, more than 250 commits or an unreadable activity feed)"
	PeopleMalformed  = "the fact holds something that is not a GitHub user id"
)

// peopleMembers are the members of a people fact that list GitHub user
// ids, in the order the page lists them, with how each lists a person.
var peopleMembers = []struct{ member, as string }{
	{"author", "author"}, {"authors", "commit author"}, {"committers", "committer"}, {"pushers", "pusher"},
}

// Listed is one GitHub user a people fact lists.
type Listed struct {
	GitHubID int64
	// As says how the fact lists them: author, commit author, committer or
	// pusher.
	As []string
	// User is the user linked to the GitHub user id; nil when none is.
	User *ids.UUID
}

// PeopleList is what a people fact lists now about a held action's target,
// each GitHub user once, in the order the fact lists them.
type PeopleList struct {
	// Fact is the fact's name, such as github.pull.people.
	Fact   string
	People []Listed
	// Complete is set when the fact is known, can be read and says it lists
	// everyone: only then can anyone count as independent of it (design
	// decision 18).
	Complete bool
	// Gaps say why the list may not name everyone; empty when it does.
	Gaps []string
}

// ListPeople reads the people a people fact's value lists. A member that
// is not a GitHub user id (author) or a list of them (authors, committers,
// pushers) is a gap, never skipped in silence.
func ListPeople(fact string, value map[string]any) PeopleList {
	l := PeopleList{Fact: fact, Complete: value["complete"] == true}
	if !l.Complete {
		l.Gaps = append(l.Gaps, PeopleNotAll)
	}
	malformed := false
	add := func(v any, as string) {
		id, ok := v.(int64)
		if !ok || id <= 0 {
			malformed = true
			return
		}
		i := slices.IndexFunc(l.People, func(p Listed) bool { return p.GitHubID == id })
		if i < 0 {
			l.People = append(l.People, Listed{GitHubID: id})
			i = len(l.People) - 1
		}
		if !slices.Contains(l.People[i].As, as) {
			l.People[i].As = append(l.People[i].As, as)
		}
	}
	for _, m := range peopleMembers {
		v, ok := value[m.member]
		switch {
		case !ok:
		case m.member == "author":
			add(v, m.as)
		default:
			list, ok := v.([]any)
			if !ok {
				malformed = true
			}
			for _, x := range list {
				add(x, m.as)
			}
		}
	}
	if malformed {
		l.Gaps = append(l.Gaps, PeopleMalformed)
	}
	return l
}

// GitHubIDs are the GitHub user ids the list names.
func (l PeopleList) GitHubIDs() []int64 {
	out := make([]int64, 0, len(l.People))
	for _, p := range l.People {
		out = append(out, p.GitHubID)
	}
	return out
}

// Link records that user is linked to the GitHub user id github.
func (l *PeopleList) Link(github int64, user ids.UUID) {
	for i := range l.People {
		if l.People[i].GitHubID == github {
			l.People[i].User = &user
		}
	}
}

// Authorship is the list as independence reads it: the users linked to the
// people it names, when it lists everyone.
func (l PeopleList) Authorship() Authorship {
	if !l.Complete {
		return Authorship{}
	}
	var users []ids.UUID
	for _, p := range l.People {
		if p.User != nil && !slices.Contains(users, *p.User) {
			users = append(users, *p.User)
		}
	}
	return Authorship{Users: users, Complete: true}
}

// Shown is the list as the page shows it: at most n people, with a gap
// saying so when it names more.
func (l PeopleList) Shown(n int) PeopleList {
	if len(l.People) <= n {
		return l
	}
	l.Gaps = append(slices.Clip(l.Gaps), fmt.Sprintf("only the first %d of the %d people it lists are shown", n, len(l.People)))
	l.People = l.People[:n]
	return l
}
