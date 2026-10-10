// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"slices"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Routing (HR-173, decision 8) reaches only eligible deciders and never
// changes who is eligible; no response means the entry ends as its kind
// says.

// Ranks of a decider's nearest binding to the entry's agent.
const (
	RankNear         = 0 // environment or team
	RankBusinessUnit = 1
	RankOrg          = 2
)

// MaxRecipients caps the people one routing step notifies personally.
const MaxRecipients = 50

// Routing health of an entry.
const (
	HealthOK              = "OK"
	HealthNoDecider       = "NO_ELIGIBLE_DECIDER"
	HealthDeliveryFailing = "DELIVERY_FAILING"
)

// Candidate is an eligible decider and the rank of their nearest binding.
type Candidate struct {
	User ids.UUID
	Rank int
}

// Nearest returns the deciders at the nearest rank any of them has: the
// environment and team bindings, or the next wider scope when there are
// none (decision 8). At most MaxRecipients, in the order given.
func Nearest(cs []Candidate) []Candidate {
	if len(cs) == 0 {
		return nil
	}
	best := slices.MinFunc(cs, func(a, b Candidate) int { return a.Rank - b.Rank }).Rank
	var out []Candidate
	for _, c := range cs {
		if c.Rank == best && len(out) < MaxRecipients {
			out = append(out, c)
		}
	}
	return out
}
