// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"maps"
	"slices"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// Decline reasons, safer alternatives and evidence questions (design
// decision 11, G0 M5 part 2 slice 203).
var (
	DeclineReasons = []string{"NOT_NEEDED", "TOO_RISKY", "WRONG_TARGET", "NEEDS_DIFFERENT_APPROACH", "OTHER"}
	Alternatives   = []string{"NARROWER_ACTION", "PERSON_PERFORMS", "RETRY_LATER", "ASK_OWNER"}
	Questions      = []string{"WHY_NEEDED", "CONTEXT", "PARAMETER_BASIS", "OTHER"}
)

// Bounds of what people and workloads add to a request.
const (
	// MaxNote is a decider's note (shown to people only).
	MaxNote = 500
	// MaxEvidence is one evidence note, in bytes; MaxEvidenceNotes the notes
	// per request.
	MaxEvidence      = 4096
	MaxEvidenceNotes = 20
)

// ErrNotNarrower refuses a proposal that is not the same action with
// narrower material parameters (HR-172).
var ErrNotNarrower = pcerr.New(pcerr.InvalidArgument, "NOT_NARROWER",
	"a proposal keeps the operation, target, account and destinations and only narrows material parameters")

// MayRespond reports whether p may decline, ask for evidence or propose a
// narrower action on a request with requirement r: an enabled person who
// is the step-up's subject, or who holds the requirement's role on the
// agent's scope path and is not excluded (the run's launcher and principal
// and their ancestors; owners and grant issuers when independent). These
// responses grant nothing, so neither a security key nor the cooldowns are
// needed (decision 1, HR-172). It relaxes a copy: p, and the bindings it
// shares with the caller, stay as they were, so a later Check of the same
// person still reports the cooldown that holds.
func MayRespond(r Requirement, p Person, c Context) (bool, string) {
	if !p.Enabled {
		return false, IneligibleDisabled
	}
	if r.Kind == KindStepUp {
		u, err := StepUpUser(r, c.Run)
		if err != nil || u != p.UserID {
			return false, IneligibleNotStepUpSubject
		}
		return true, ""
	}
	relaxed := c
	relaxed.Cooldowns = Cooldowns{}
	q := p
	q.Credentials = []Credential{{CreatedAt: c.Now.Add(-minCooldowns.CredentialAge)}}
	q.JoinedAt = c.Now.Add(-minCooldowns.AccountAge)
	q.Bindings = slices.Clone(p.Bindings)
	for i := range q.Bindings {
		q.Bindings[i].SelfGranted = false
		q.Bindings[i].CreatedAt = c.Now.Add(-minCooldowns.RoleAge)
	}
	r.Count = 1
	return Check(r, q, relaxed, q.Credentials[0].ID)
}

// CheckNarrower checks a proposal against the held action's parameters
// (HR-172, F147): the same parameters, at least one changed, and every
// change to a material parameter toward a narrower value: money in the
// same currency and no larger, decimals and integers no larger in
// magnitude, identifier lists as subsets. Any other change is refused.
func CheckNarrower(d *defs.Definition, held, proposed defs.Values) error {
	if !slices.Equal(slices.Sorted(maps.Keys(held)), slices.Sorted(maps.Keys(proposed))) {
		return ErrNotNarrower
	}
	changed := false
	for name, was := range held {
		now := proposed[name]
		if sameValue(was, now) {
			continue
		}
		changed = true
		spec, ok := d.Params[name]
		if !ok || !spec.Material || was.Type != now.Type || !narrower(was, now) {
			return ErrNotNarrower
		}
	}
	if !changed {
		return ErrNotNarrower
	}
	return nil
}

func narrower(was, now defs.Value) bool {
	switch was.Type { //nolint:exhaustive // only these types can be narrowed; any other change is refused
	case defs.TypeMoney:
		return was.Money.Currency == now.Money.Currency && now.Money.Amount.Cmp(was.Money.Amount) <= 0 &&
			now.Money.Amount.Sign() >= 0
	case defs.TypeDecimal:
		return absDecimal(now.Decimal).Cmp(absDecimal(was.Decimal)) <= 0
	case defs.TypeInteger:
		return abs(now.Int) <= abs(was.Int)
	case defs.TypeIdentifierList:
		if len(now.List) == 0 {
			return false
		}
		for _, x := range now.List {
			if !slices.Contains(was.List, x) {
				return false
			}
		}
		return true
	}
	return false
}

func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

func absDecimal(d money.Decimal) money.Decimal {
	if d.Sign() < 0 {
		return d.Neg()
	}
	return d
}
