// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"slices"
	"time"

	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Why a person may not count toward a requirement (stable codes, shown to
// the person themselves and to approval readers).
const (
	IneligibleDisabled          = "USER_DISABLED"
	IneligibleLauncher          = "LAUNCHER_EXCLUDED"
	IneligiblePrincipal         = "PRINCIPAL_EXCLUDED"
	IneligibleAncestor          = "ANCESTOR_RUN_EXCLUDED"
	IneligibleOwner             = "OWNER_EXCLUDED"
	IneligibleGrantIssuer       = "GRANT_ISSUER_EXCLUDED"
	IneligibleNoRole            = "NO_ROLE"
	IneligibleSelfGrant         = "SELF_GRANT_COOLDOWN"
	IneligibleRoleCooldown      = "ROLE_COOLDOWN"
	IneligibleAccountTooNew     = "ACCOUNT_TOO_NEW"
	IneligibleNoCredential      = "NO_ACTIVE_CREDENTIAL"  //nolint:gosec // G101: a reason code, not a credential
	IneligibleCredentialTooNew  = "CREDENTIAL_TOO_NEW"    //nolint:gosec // G101: a reason code, not a credential
	IneligibleCredentialRevoked = "CREDENTIAL_NOT_ACTIVE" //nolint:gosec // G101: a reason code, not a credential
	IneligibleNotStepUpSubject  = "NOT_STEP_UP_SUBJECT"
	IneligibleRequester         = "REQUESTER_EXCLUDED"
)

// ErrStepUpSubjectNotAPerson is returned when a step-up names a launcher or
// principal that is not a person: a service account, or the parent
// instance of a child run (decision 4). The decision is CANNOT_AUTHORIZE.
var ErrStepUpSubjectNotAPerson = pcerr.New(pcerr.CannotAuthorize, ReasonStepUpSubjectNotAPerson,
	"the step-up names a launcher or principal that is not a person")

// Cooldowns guard against a fresh account, role or credential being used to
// approve (decision 5). Orgs may lengthen them, never shorten them.
type Cooldowns struct {
	// For requirements of two or more people.
	AccountAge    time.Duration
	RoleAge       time.Duration
	CredentialAge time.Duration
	// For every approval: a role a person granted themselves.
	SelfGrantDelay time.Duration
}

// Minimum cooldowns (decision 5).
var minCooldowns = Cooldowns{
	AccountAge: 7 * 24 * time.Hour, RoleAge: 24 * time.Hour, CredentialAge: 24 * time.Hour, SelfGrantDelay: 24 * time.Hour,
}

// DefaultCooldowns returns the minimum cooldowns.
func DefaultCooldowns() Cooldowns { return minCooldowns }

// AtLeastMinimum raises each period to its minimum: an org setting can only
// lengthen them.
func (c Cooldowns) AtLeastMinimum() Cooldowns {
	return Cooldowns{
		AccountAge: max(c.AccountAge, minCooldowns.AccountAge), RoleAge: max(c.RoleAge, minCooldowns.RoleAge),
		CredentialAge:  max(c.CredentialAge, minCooldowns.CredentialAge),
		SelfGrantDelay: max(c.SelfGrantDelay, minCooldowns.SelfGrantDelay),
	}
}

// RoleBinding is one binding of an approval role on the agent's scope path.
type RoleBinding struct {
	Role      string
	CreatedAt time.Time
	// SelfGranted is true when the person created the binding themselves
	// (allowed and audited since ADR-0016).
	SelfGranted bool
}

// Credential is one active WebAuthn credential of a person.
type Credential struct {
	ID        ids.UUID
	CreatedAt time.Time
}

// Person is a possible decider as the store sees them now.
type Person struct {
	UserID   ids.UUID
	Enabled  bool
	JoinedAt time.Time
	// Bindings of roles holding approval.respond on the agent's scope path
	// (its business unit, team and environment, and the org).
	Bindings []RoleBinding
	// Active credentials only.
	Credentials []Credential
}

// RunPeople are the people around a run: its launcher and represented
// principal, and those of every ancestor run.
type RunPeople struct {
	Launcher  gdomain.Principal
	Principal gdomain.Principal
	// Ancestors' launchers and principals, nearest first.
	Ancestors []gdomain.Principal
}

// Context is what eligibility depends on besides the person.
type Context struct {
	Run RunPeople
	// The agent's owner and backup owner.
	Owners []ids.UUID
	// The people who issued or revised a grant of the run's chain.
	GrantIssuers []ids.UUID
	// Requester is a restoration's requester, who never decides it
	// (decision 11).
	Requester ids.UUID
	Cooldowns Cooldowns
	Now       time.Time
}

func isUser(p gdomain.Principal, u ids.UUID) bool {
	return p.Kind == gdomain.PrincipalUser && p.ID == u
}

// StepUpUser returns the person a step-up requirement names, or
// ErrStepUpSubjectNotAPerson.
func StepUpUser(r Requirement, run RunPeople) (ids.UUID, error) {
	p := run.Launcher
	if r.Subject == SubjectPrincipal {
		p = run.Principal
	}
	if p.Kind != gdomain.PrincipalUser || p.ID.IsZero() {
		return ids.UUID{}, ErrStepUpSubjectNotAPerson
	}
	return p.ID, nil
}

// Check reports whether p may count toward r now (HR-035, HR-036, HR-170).
// cred is the credential of their assertion; when it is zero, Check asks
// whether any of their active credentials would do (for showing
// eligibility before a ceremony). The code says why not.
func Check(r Requirement, p Person, c Context, cred ids.UUID) (bool, string) {
	if !p.Enabled {
		return false, IneligibleDisabled
	}
	if r.Kind == KindStepUp {
		u, err := StepUpUser(r, c.Run)
		if err != nil || u != p.UserID {
			return false, IneligibleNotStepUpSubject
		}
		return credentialOK(p, cred, 0, c.Now)
	}
	if r.Kind == KindRestore {
		return checkRestore(p, c, cred)
	}
	switch {
	case isUser(c.Run.Launcher, p.UserID):
		return false, IneligibleLauncher
	case isUser(c.Run.Principal, p.UserID):
		return false, IneligiblePrincipal
	case slices.ContainsFunc(c.Run.Ancestors, func(a gdomain.Principal) bool { return isUser(a, p.UserID) }):
		return false, IneligibleAncestor
	}
	if r.Independent {
		if slices.Contains(c.Owners, p.UserID) {
			return false, IneligibleOwner
		}
		if slices.Contains(c.GrantIssuers, p.UserID) {
			return false, IneligibleGrantIssuer
		}
	}
	cd := c.Cooldowns.AtLeastMinimum()
	multi := r.Count >= 2
	why := IneligibleNoRole
	held := slices.ContainsFunc(p.Bindings, func(b RoleBinding) bool {
		if b.Role != r.Role || !ApprovalRole(b.Role) {
			return false
		}
		age := c.Now.Sub(b.CreatedAt)
		switch {
		case b.SelfGranted && age < cd.SelfGrantDelay:
			why = IneligibleSelfGrant
			return false
		case multi && age < cd.RoleAge:
			if why == IneligibleNoRole {
				why = IneligibleRoleCooldown
			}
			return false
		}
		return true
	})
	if !held {
		return false, why
	}
	if multi && c.Now.Sub(p.JoinedAt) < cd.AccountAge {
		return false, IneligibleAccountTooNew
	}
	var minAge time.Duration
	if multi {
		minAge = cd.CredentialAge
	}
	return credentialOK(p, cred, minAge, c.Now)
}

// checkRestore checks a restoration's decider (decision 11): not the
// requester, holding a role with agent.restore where the agent lives (a
// self-granted one only after the self-grant delay), with an active key.
func checkRestore(p Person, c Context, cred ids.UUID) (bool, string) {
	if p.UserID == c.Requester {
		return false, IneligibleRequester
	}
	cd := c.Cooldowns.AtLeastMinimum()
	why := IneligibleNoRole
	held := slices.ContainsFunc(p.Bindings, func(b RoleBinding) bool {
		if !RestoreRole(b.Role) {
			return false
		}
		if b.SelfGranted && c.Now.Sub(b.CreatedAt) < cd.SelfGrantDelay {
			why = IneligibleSelfGrant
			return false
		}
		return true
	})
	if !held {
		return false, why
	}
	return credentialOK(p, cred, 0, c.Now)
}

func credentialOK(p Person, cred ids.UUID, minAge time.Duration, now time.Time) (bool, string) {
	if !cred.IsZero() {
		i := slices.IndexFunc(p.Credentials, func(k Credential) bool { return k.ID == cred })
		if i < 0 {
			return false, IneligibleCredentialRevoked
		}
		if now.Sub(p.Credentials[i].CreatedAt) < minAge {
			return false, IneligibleCredentialTooNew
		}
		return true, ""
	}
	if len(p.Credentials) == 0 {
		return false, IneligibleNoCredential
	}
	if !slices.ContainsFunc(p.Credentials, func(k Credential) bool { return now.Sub(k.CreatedAt) >= minAge }) {
		return false, IneligibleCredentialTooNew
	}
	return true, ""
}

// Response is a recorded approval or step-up as tallies see it.
type Response struct {
	UserID       ids.UUID
	CredentialID ids.UUID
	// Requirement is the index of the requirement it counts toward.
	Requirement int
	Voided      bool
}

// Tally counts the responses toward each requirement: a response counts
// toward the one requirement it was recorded for, and each person and each
// credential counts once per request (HR-035). Voided responses and
// responses for an unknown requirement count for nothing.
func Tally(reqs []Requirement, rs []Response) []int {
	out := make([]int, len(reqs))
	var users, creds []ids.UUID
	for _, r := range rs {
		if r.Voided || r.Requirement < 0 || r.Requirement >= len(reqs) ||
			slices.Contains(users, r.UserID) || slices.Contains(creds, r.CredentialID) {
			continue
		}
		users, creds = append(users, r.UserID), append(creds, r.CredentialID)
		out[r.Requirement]++
	}
	return out
}

// Met reports whether every requirement has its responses.
func Met(reqs []Requirement, rs []Response) bool {
	t := Tally(reqs, rs)
	for i, r := range reqs {
		if t[i] < r.Needed() {
			return false
		}
	}
	return len(reqs) > 0
}

// Next picks the requirement a new response counts toward: the first one,
// in order, that still needs responses and that eligible accepts.
func Next(reqs []Requirement, rs []Response, eligible func(i int) bool) (int, bool) {
	t := Tally(reqs, rs)
	for i, r := range reqs {
		if t[i] < r.Needed() && eligible(i) {
			return i, true
		}
	}
	return -1, false
}
