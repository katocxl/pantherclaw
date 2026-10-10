// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"fmt"
	"time"
)

// Escalation scopes: the widest bindings whose eligible deciders a step
// reaches.
const (
	// ScopeNearest is the environment and team bindings, or the next wider
	// scope when there are none.
	ScopeNearest      = "NEAREST"
	ScopeBusinessUnit = "BUSINESS_UNIT"
	ScopeOrg          = "ORG"
)

// MaxSteps bounds a chain (the schema allows 5).
const MaxSteps = 5

// Step is one step of an escalation chain (decision 8), taken at a
// percentage of the time between an entry's creation and its deadline.
// Each step recomputes eligibility; no step makes anyone eligible.
type Step struct {
	AtPercent int    `json:"at_percent"`
	Scope     string `json:"scope"`
	// Remind tells the deciders already notified again.
	Remind bool `json:"remind,omitzero"`
	// NotifyOwners tells the agent's owner and backup owner, who get no
	// vote unless they are eligible.
	NotifyOwners bool `json:"notify_owners,omitzero"`
	// NotifyChannels tells the channels subscribed to the entry's notice.
	NotifyChannels bool `json:"notify_channels,omitzero"`
}

// DefaultChain is decision 8's chain: the nearest deciders and subscribed
// channels at once, a reminder and business-unit deciders at half the
// time, org-scope deciders and a notice to the agent's owners at three
// quarters.
var DefaultChain = []Step{
	{AtPercent: 0, Scope: ScopeNearest, NotifyChannels: true},
	{AtPercent: 50, Scope: ScopeBusinessUnit, Remind: true},
	{AtPercent: 75, Scope: ScopeOrg, NotifyOwners: true},
}

// ErrChainInvalid is returned for a chain that is not 1 to 5 steps
// starting at 0%, with increasing times below 100% and scopes that never
// narrow.
var ErrChainInvalid = errors.New("waitlist: invalid escalation chain")

var scopeRanks = map[string]int{ScopeNearest: RankNear, ScopeBusinessUnit: RankBusinessUnit, ScopeOrg: RankOrg}

// ValidateChain checks a chain an org or team sets.
func ValidateChain(steps []Step) error {
	if len(steps) == 0 || len(steps) > MaxSteps {
		return fmt.Errorf("%w: %d steps", ErrChainInvalid, len(steps))
	}
	if steps[0].AtPercent != 0 {
		return fmt.Errorf("%w: the first step is at 0%%", ErrChainInvalid)
	}
	for i, s := range steps {
		rank, ok := scopeRanks[s.Scope]
		switch {
		case !ok:
			return fmt.Errorf("%w: step %d scope %q", ErrChainInvalid, i, s.Scope)
		case s.AtPercent < 0 || s.AtPercent > 99:
			return fmt.Errorf("%w: step %d at %d%%", ErrChainInvalid, i, s.AtPercent)
		case i > 0 && s.AtPercent <= steps[i-1].AtPercent:
			return fmt.Errorf("%w: step %d is not later than the one before", ErrChainInvalid, i)
		case i > 0 && rank < scopeRanks[steps[i-1].Scope]:
			return fmt.Errorf("%w: step %d narrows the scope", ErrChainInvalid, i)
		}
	}
	return nil
}

// StepAt is when step i of chain is due for an entry, or zero when the
// chain has no step i.
func StepAt(chain []Step, i int, created, deadline time.Time) time.Time {
	if i < 0 || i >= len(chain) {
		return time.Time{}
	}
	return created.Add(deadline.Sub(created) * time.Duration(chain[i].AtPercent) / 100)
}

// Reach returns the deciders a step reaches: the nearest ones for
// ScopeNearest, else every decider bound at that scope or nearer, at most
// MaxRecipients.
func Reach(s Step, cs []Candidate) []Candidate {
	if s.Scope == ScopeNearest {
		return Nearest(cs)
	}
	var out []Candidate
	for _, c := range cs {
		if c.Rank <= scopeRanks[s.Scope] && len(out) < MaxRecipients {
			out = append(out, c)
		}
	}
	return out
}
