// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"regexp"
	"time"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// ScopeKind is what an envelope applies to (F047, F054).
type ScopeKind string

// Envelope scopes. A principal envelope bounds what any grant may give an
// agent acting for that user or service account ("principal bounds").
const (
	ScopeOrg          ScopeKind = "org"
	ScopeBusinessUnit ScopeKind = "business_unit"
	ScopeTeam         ScopeKind = "team"
	ScopeEnvironment  ScopeKind = "environment"
	ScopePrincipal    ScopeKind = "principal"
)

var scopeOrder = []ScopeKind{ScopeOrg, ScopeBusinessUnit, ScopeTeam, ScopeEnvironment, ScopePrincipal}

// Scope names what one envelope applies to. ID is zero for the org scope;
// for a principal scope Principal is set instead.
type Scope struct {
	Kind      ScopeKind
	ID        ids.UUID
	Principal Principal
}

func (s Scope) String() string {
	switch s.Kind {
	case ScopeOrg:
		return "org"
	case ScopePrincipal:
		return "principal " + s.Principal.String()
	case ScopeBusinessUnit, ScopeTeam, ScopeEnvironment:
	}
	return string(s.Kind) + " " + s.ID.String()
}

// Delegation and lifetime caps (G0 M4 part 2, decision 5). An org can lower
// each default in its guardrails, or raise it up to the hard cap; the other
// scopes can only lower.
const (
	DefaultMaxDepth        = 2
	HardMaxDepth           = 4
	DefaultMaxChildren     = 10
	HardMaxChildren        = 50
	MaxChildrenTotal       = 100 // over a grant's life; stops a looping agent
	MaxDelegatedLifetime   = 24 * time.Hour
	DefaultMaxRootLifetime = 7 * 24 * time.Hour
	HardMaxRootLifetime    = 90 * 24 * time.Hour
	// IssueSkew backdates the start of a grant that takes effect when it is
	// issued. Issuance reads the server's clock, while runs and decisions
	// check validity against the database clock (BUILD_GUIDE §3.1). Without
	// it, a database clock slightly behind the server's would find a grant
	// just issued "not yet valid". Lifetimes are measured from the issue
	// time, so this widens nothing that matters: the grant did not exist
	// before it was issued.
	IssueSkew = time.Minute
)

// Repeat-protection window for irreversible actions (decision 6, HR-007).
const (
	DefaultRepeatWindow = 24 * time.Hour
	MinRepeatWindow     = time.Hour
	MaxRepeatWindow     = 30 * 24 * time.Hour
)

// Caps are the delegation and lifetime caps in effect for a grant.
type Caps struct {
	MaxDepth        int
	MaxChildren     int
	MaxRootLifetime time.Duration
	RepeatWindow    time.Duration
}

// Settings are the caps an envelope sets; nil leaves a cap as it is.
type Settings struct {
	MaxDepth        *int
	MaxChildren     *int
	MaxRootLifetime *time.Duration
	// RepeatWindow is an org-wide setting: only the org envelope sets it.
	RepeatWindow *time.Duration
}

// Envelope is one revision of an org guardrail (F047, F054).
type Envelope struct {
	ID           EnvelopeID
	Org          ids.OrgID
	Revision     int
	Scope        Scope
	Name         string
	Bounds       Bounds
	Requirements []Requirement
	Limits       Limits
	Settings     Settings
	// MinAttestation is the lowest attestation level any grant under this
	// envelope may be used at.
	MinAttestation int
	// ChangedBy and RevisedAt record who stored the current revision, and
	// when (empty before it is stored).
	ChangedBy string
	RevisedAt time.Time
}

var reasonPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)

// Validate checks the envelope on its own.
func (e Envelope) Validate() error {
	if e.ID.IsZero() || e.Org.IsZero() || e.Revision < 1 {
		return invalid("envelope: id, org and a revision from 1 are required")
	}
	switch e.Scope.Kind {
	case ScopeOrg:
		if !e.Scope.ID.IsZero() || !e.Scope.Principal.ID.IsZero() {
			return invalid("envelope: the org scope takes no id")
		}
	case ScopePrincipal:
		if k := e.Scope.Principal.Kind; (k != PrincipalUser && k != PrincipalServiceAccount) || e.Scope.Principal.ID.IsZero() {
			return invalid("envelope: a principal scope names a user or a service account")
		}
	case ScopeBusinessUnit, ScopeTeam, ScopeEnvironment:
		if e.Scope.ID.IsZero() {
			return invalid("envelope: the %s scope needs an id", e.Scope.Kind)
		}
	default:
		return invalid("envelope: unknown scope %q", e.Scope.Kind)
	}
	if err := checkLabel("name", e.Name, 100); err != nil {
		return err
	}
	if e.MinAttestation < 0 || e.MinAttestation > 2 {
		return invalid("envelope: min_attestation is 0, 1 or 2")
	}
	if len(e.Requirements) > maxRequirements {
		return invalid("envelope: at most %d requirements", maxRequirements)
	}
	for i, r := range e.Requirements {
		if err := r.validate(fmt.Sprintf("requirements[%d]", i)); err != nil {
			return err
		}
	}
	s := e.Settings
	if s.MaxDepth != nil && (*s.MaxDepth < 0 || *s.MaxDepth > HardMaxDepth) {
		return invalid("envelope: max_depth is 0..%d", HardMaxDepth)
	}
	if s.MaxChildren != nil && (*s.MaxChildren < 0 || *s.MaxChildren > HardMaxChildren) {
		return invalid("envelope: max_children is 0..%d", HardMaxChildren)
	}
	if s.MaxRootLifetime != nil && (*s.MaxRootLifetime < time.Minute || *s.MaxRootLifetime > HardMaxRootLifetime) {
		return invalid("envelope: max_root_lifetime is 1m..%s", HardMaxRootLifetime)
	}
	if s.RepeatWindow != nil {
		if e.Scope.Kind != ScopeOrg {
			return invalid("envelope: the repeat window is an org-wide setting")
		}
		if *s.RepeatWindow < MinRepeatWindow || *s.RepeatWindow > MaxRepeatWindow {
			return invalid("envelope: the repeat window is %s..%s", MinRepeatWindow, MaxRepeatWindow)
		}
	}
	if err := e.Limits.validate(false); err != nil {
		return err
	}
	return e.Bounds.Validate()
}

// CheckDispatched refuses a guardrail budget or counter that names an
// operation which is only ever a consequence, as a grant's are (G0 M8, HR-206): it would never count
// anything, so an admin would believe a cap that is not there. lookup is
// the service's preloaded active definitions.
func (e Envelope) CheckDispatched(lookup func(op string) *defs.Definition) error {
	return e.Limits.checkDispatched(lookup)
}

// EffectiveCaps combines the caps of the applicable envelopes: the org
// envelope replaces each default (up to the hard cap), and every other
// scope can only lower the result.
func EffectiveCaps(envs []Envelope) Caps {
	c := Caps{MaxDepth: DefaultMaxDepth, MaxChildren: DefaultMaxChildren, MaxRootLifetime: DefaultMaxRootLifetime, RepeatWindow: DefaultRepeatWindow}
	for _, e := range envs {
		if e.Scope.Kind != ScopeOrg {
			continue
		}
		s := e.Settings
		if s.MaxDepth != nil {
			c.MaxDepth = min(*s.MaxDepth, HardMaxDepth)
		}
		if s.MaxChildren != nil {
			c.MaxChildren = min(*s.MaxChildren, HardMaxChildren)
		}
		if s.MaxRootLifetime != nil {
			c.MaxRootLifetime = min(*s.MaxRootLifetime, HardMaxRootLifetime)
		}
		if s.RepeatWindow != nil {
			c.RepeatWindow = min(max(*s.RepeatWindow, MinRepeatWindow), MaxRepeatWindow)
		}
	}
	for _, e := range envs {
		if e.Scope.Kind == ScopeOrg {
			continue
		}
		s := e.Settings
		if s.MaxDepth != nil {
			c.MaxDepth = min(c.MaxDepth, *s.MaxDepth)
		}
		if s.MaxChildren != nil {
			c.MaxChildren = min(c.MaxChildren, *s.MaxChildren)
		}
		if s.MaxRootLifetime != nil {
			c.MaxRootLifetime = min(c.MaxRootLifetime, *s.MaxRootLifetime)
		}
	}
	return c
}

// Change describes how a new envelope revision differs from the current
// one, for the audit record and the confirmation shown to the admin.
type Change struct {
	// Widens is set when the new revision allows something the current one
	// does not (a bound, a removed requirement, a raised cap or a lower
	// attestation minimum). Narrowings take effect at once (HR-046).
	Widens bool
	Detail string
}

// Compare reports whether next widens cur.
func Compare(cur, next Envelope) Change {
	if v := next.Bounds.Inherit(Bounds{}).Within(cur.Bounds); v != nil {
		return Change{Widens: true, Detail: "bounds: " + v.Error()}
	}
	for _, r := range cur.Requirements {
		if !containsRequirement(next.Requirements, r) {
			return Change{Widens: true, Detail: "requirement " + r.Reason + " is removed or changed"}
		}
	}
	if next.MinAttestation < cur.MinAttestation {
		return Change{Widens: true, Detail: "the minimum attestation level is lowered"}
	}
	if !limitsKept(cur.Limits, next.Limits) {
		return Change{Widens: true, Detail: "a budget or counter is removed or changed"}
	}
	c1, c2 := cur.Settings.effective(cur.Scope.Kind), next.Settings.effective(next.Scope.Kind)
	if c2.MaxDepth > c1.MaxDepth || c2.MaxChildren > c1.MaxChildren {
		return Change{Widens: true, Detail: "a delegation cap is raised or removed"}
	}
	if c2.MaxRootLifetime > c1.MaxRootLifetime {
		return Change{Widens: true, Detail: "the grant lifetime cap is raised or removed"}
	}
	if c2.RepeatWindow < c1.RepeatWindow {
		return Change{Widens: true, Detail: "the repeat-protection window is shortened"}
	}
	return Change{Detail: "narrows or keeps every limit"}
}

func containsRequirement(rs []Requirement, r Requirement) bool {
	for _, x := range rs {
		if requirementEqual(x, r) {
			return true
		}
	}
	return false
}

// effective returns the caps these settings impose on their own: at the org
// scope an unset cap is the default; elsewhere it is no cap at all.
func (s Settings) effective(k ScopeKind) Caps {
	c := Caps{MaxDepth: HardMaxDepth + 1, MaxChildren: HardMaxChildren + 1, MaxRootLifetime: HardMaxRootLifetime + 1, RepeatWindow: 0}
	if k == ScopeOrg {
		c = Caps{MaxDepth: DefaultMaxDepth, MaxChildren: DefaultMaxChildren, MaxRootLifetime: DefaultMaxRootLifetime, RepeatWindow: DefaultRepeatWindow}
	}
	if s.MaxDepth != nil {
		c.MaxDepth = *s.MaxDepth
	}
	if s.MaxChildren != nil {
		c.MaxChildren = *s.MaxChildren
	}
	if s.MaxRootLifetime != nil {
		c.MaxRootLifetime = *s.MaxRootLifetime
	}
	if s.RepeatWindow != nil {
		c.RepeatWindow = *s.RepeatWindow
	}
	return c
}

func requirementEqual(a, b Requirement) bool {
	x, err1 := json.Marshal(a, json.Deterministic(true))
	y, err2 := json.Marshal(b, json.Deterministic(true))
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}
