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
	PeopleUnnamed    = "the fact does not name both its author and its pushers"
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
	// Bot: the fact names the account as not a person (a GitHub App's bot).
	// Exempt: an admin registered it as not a person (a bot or a machine
	// user). Either way, being linked to nobody does not stop approvals
	// (founder decision 2026-10-13). ExemptedBy is the admin, who is
	// excluded like the people the fact lists.
	Bot, Exempt bool
	ExemptedBy  *ids.UUID
	// Formerly are the other users who ever proved a link to the GitHub user
	// id (github_identity_history): they stay excluded too, so unlinking or
	// moving the link to someone else lets nobody approve their own change.
	Formerly []ids.UUID
}

// PeopleList is what a people fact lists now about a held action's target,
// each GitHub user once, in the order the fact lists them.
type PeopleList struct {
	// Fact is the fact's name, such as github.pull.people.
	Fact   string
	People []Listed
	// Complete is set only when the fact is known, can be read, says it
	// lists everyone, names its author and a list of pushers, and every id
	// it holds is a positive integer: only then can anyone count as
	// independent of it (design decision 18), by the rule the decision
	// applies to the same fact (HR-207).
	Complete bool
	// Gaps say why the list may not name everyone; empty when it does.
	Gaps []string
}

// ListPeople reads the people a people fact's value lists. A member that
// is not a GitHub user id (author) or a list of them (authors, committers,
// pushers) is a gap, never skipped in silence, and so is a missing author
// or pushers list.
func ListPeople(fact string, value map[string]any) PeopleList {
	l := PeopleList{Fact: fact}
	if value["complete"] != true {
		l.Gaps = append(l.Gaps, PeopleNotAll)
	}
	_, author := value["author"]
	_, pushers := value["pushers"]
	if !author || !pushers {
		l.Gaps = append(l.Gaps, PeopleUnnamed)
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
	if bots, ok := value["bots"]; ok {
		list, ok := bots.([]any)
		if !ok {
			malformed = true
		}
		for _, x := range list {
			id, ok := x.(int64)
			if !ok || id <= 0 {
				malformed = true
				continue
			}
			for i := range l.People {
				if l.People[i].GitHubID == id {
					l.People[i].Bot = true
				}
			}
		}
	}
	if malformed {
		l.Gaps = append(l.Gaps, PeopleMalformed)
	}
	l.Complete = len(l.Gaps) == 0
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

// Exempted records that the user by (zero when not a user) registered the
// GitHub user id as not a person.
func (l *PeopleList) Exempted(github int64, by ids.UUID) {
	for i := range l.People {
		if l.People[i].GitHubID == github {
			l.People[i].Exempt = true
			if !by.IsZero() {
				l.People[i].ExemptedBy = &by
			}
		}
	}
}

// Formerly records that user once proved a link to the GitHub user id.
func (l *PeopleList) Formerly(github int64, user ids.UUID) {
	for i := range l.People {
		p := &l.People[i]
		if p.GitHubID == github && (p.User == nil || *p.User != user) && !slices.Contains(p.Formerly, user) {
			p.Formerly = append(p.Formerly, user)
		}
	}
}

// Authorship is the list as independence reads it: the users linked to the
// people it names, now or ever, only when it is complete and has
// no gap.
func (l PeopleList) Authorship() Authorship {
	if !l.Complete || len(l.Gaps) > 0 {
		return Authorship{}
	}
	var users []ids.UUID
	var unlinked []int64
	for _, p := range l.People {
		if p.User == nil && !p.Bot && !p.Exempt {
			unlinked = append(unlinked, p.GitHubID)
		}
		if p.User != nil && !slices.Contains(users, *p.User) {
			users = append(users, *p.User)
		}
		for _, u := range p.Formerly {
			if !slices.Contains(users, u) {
				users = append(users, u)
			}
		}
		if p.ExemptedBy != nil && !slices.Contains(users, *p.ExemptedBy) {
			users = append(users, *p.ExemptedBy)
		}
	}
	return Authorship{Users: users, Complete: true, Unlinked: unlinked}
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
