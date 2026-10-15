// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the pure licensing rules (BUILD_GUIDE §8 M1 billing
// part 1, ADR-0007): editions, limits and how a licence's validity and dates
// translate into the entitlements the server enforces.
//
// Founder decision (2026-10-08): an expired paid licence keeps its limits
// for a 14-day grace period with warnings, then the server falls back to
// Community. A licence that fails verification falls back to Community at
// once. Licensing never stops the server or switches enforcement off.
package domain

import (
	"errors"
	"fmt"
	"time"
)

// Edition is a product edition.
type Edition string

// Editions.
const (
	Community  Edition = "community"
	Team       Edition = "team"
	Business   Edition = "business"
	Enterprise Edition = "enterprise"
)

// Paid reports whether e requires a licence.
func (e Edition) Paid() bool { return e == Team || e == Business || e == Enterprise }

// Limits are the quantities an edition allows. Zero means "none allowed";
// Unlimited means no cap.
type Limits struct {
	MaxAgents int
	MaxOrgs   int
}

// Unlimited marks a limit without a cap.
const Unlimited = -1

// CommunityLimits are the BSL Additional Use Grant limits: 5 governed agents
// in 1 organization (LICENSE, ADR-0007).
var CommunityLimits = Limits{MaxAgents: 5, MaxOrgs: 1}

// GracePeriod is how long an expired paid licence keeps its limits.
const GracePeriod = 14 * 24 * time.Hour

// Claims is the signed content of a licence document (v1).
type Claims struct {
	Version    int       `json:"v"`
	LicenceID  string    `json:"lid"`
	Licensee   string    `json:"sub"`
	CustomerID string    `json:"cid"`
	Edition    Edition   `json:"edition"`
	MaxAgents  int       `json:"max_agents"`
	MaxOrgs    int       `json:"max_orgs"`
	IssuedAt   time.Time `json:"iat"`
	NotBefore  time.Time `json:"nbf"`
	ExpiresAt  time.Time `json:"exp"`
}

// ErrInvalidClaims reports claims that no valid licence may contain.
var ErrInvalidClaims = errors.New("licence: invalid claims")

// Validate checks the claims' internal consistency (not dates against now).
func (c Claims) Validate() error {
	switch {
	case c.Version != 1:
		return fmt.Errorf("%w: unsupported version %d", ErrInvalidClaims, c.Version)
	case c.LicenceID == "" || len(c.LicenceID) > 64:
		return fmt.Errorf("%w: lid must be 1..64 characters", ErrInvalidClaims)
	case c.Licensee == "" || len(c.Licensee) > 200:
		return fmt.Errorf("%w: sub must be 1..200 characters", ErrInvalidClaims)
	case c.CustomerID == "" || len(c.CustomerID) > 64:
		return fmt.Errorf("%w: cid must be 1..64 characters", ErrInvalidClaims)
	case !c.Edition.Paid():
		return fmt.Errorf("%w: edition %q cannot be licensed", ErrInvalidClaims, c.Edition)
	case !validLimit(c.MaxAgents) || !validLimit(c.MaxOrgs) || c.MaxOrgs == 0:
		return fmt.Errorf("%w: limits must be positive or %d (unlimited)", ErrInvalidClaims, Unlimited)
	case c.IssuedAt.IsZero() || c.NotBefore.IsZero() || c.ExpiresAt.IsZero():
		return fmt.Errorf("%w: iat, nbf and exp are required", ErrInvalidClaims)
	case !c.ExpiresAt.After(c.NotBefore):
		return fmt.Errorf("%w: exp must be after nbf", ErrInvalidClaims)
	}
	return nil
}

func validLimit(n int) bool { return n == Unlimited || (n > 0 && n <= 1_000_000) }

// Status is the licensing state the server runs in.
type Status string

// Statuses.
const (
	StatusCommunity   Status = "COMMUNITY"     // no licence installed
	StatusValid       Status = "VALID"         // paid licence in force
	StatusGrace       Status = "GRACE"         // expired, within the grace period: paid limits kept, warnings
	StatusExpired     Status = "EXPIRED"       // grace over: Community limits
	StatusNotYetValid Status = "NOT_YET_VALID" // nbf in the future: Community limits
	StatusInvalid     Status = "INVALID"       // failed verification: Community limits
)

// Entitlements are what the server enforces right now.
type Entitlements struct {
	Edition     Edition
	Status      Status
	Limits      Limits
	LicenceID   string
	ExpiresAt   time.Time // zero for Community
	GraceEndsAt time.Time // set in GRACE and EXPIRED
	Warning     string    // operator-facing warning, empty when none
}

// CommunityEntitlements is the state without a licence.
func CommunityEntitlements() Entitlements {
	return Entitlements{Edition: Community, Status: StatusCommunity, Limits: CommunityLimits}
}

// Invalid returns Community entitlements recording that a licence failed
// verification (tampered, unknown signer, malformed).
func Invalid(reason string) Entitlements {
	e := CommunityEntitlements()
	e.Status = StatusInvalid
	e.Warning = "licence rejected (" + reason + "); running with Community limits"
	return e
}

// Evaluate turns verified claims into entitlements at time now.
func Evaluate(c Claims, now time.Time) Entitlements {
	if err := c.Validate(); err != nil {
		return Invalid("invalid claims")
	}
	paid := Entitlements{
		Edition: c.Edition, Status: StatusValid, LicenceID: c.LicenceID,
		Limits: Limits{MaxAgents: c.MaxAgents, MaxOrgs: c.MaxOrgs}, ExpiresAt: c.ExpiresAt,
	}
	graceEnds := c.ExpiresAt.Add(GracePeriod)
	switch {
	case now.Before(c.NotBefore):
		e := CommunityEntitlements()
		e.Status, e.LicenceID, e.ExpiresAt = StatusNotYetValid, c.LicenceID, c.ExpiresAt
		e.Warning = "licence is not valid before " + c.NotBefore.UTC().Format(time.RFC3339) + "; running with Community limits"
		return e
	case now.Before(c.ExpiresAt):
		if remaining := c.ExpiresAt.Sub(now); remaining < 30*24*time.Hour {
			paid.Warning = fmt.Sprintf("licence expires in %d days", int(remaining.Hours()/24)+1)
		}
		return paid
	case now.Before(graceEnds):
		paid.Status, paid.GraceEndsAt = StatusGrace, graceEnds
		paid.Warning = "licence expired on " + c.ExpiresAt.UTC().Format(time.RFC3339) +
			"; paid limits remain until " + graceEnds.UTC().Format(time.RFC3339) + ", then Community limits apply"
		return paid
	default:
		e := CommunityEntitlements()
		e.Status, e.LicenceID, e.ExpiresAt, e.GraceEndsAt = StatusExpired, c.LicenceID, c.ExpiresAt, graceEnds
		e.Warning = "licence expired and the grace period ended; running with Community limits"
		return e
	}
}

// ErrLimitReached reports an action that would exceed an edition limit.
var ErrLimitReached = errors.New("licence: edition limit reached")

// CheckOrgs reports whether creating one more organization is allowed when
// current tenant organizations exist (the platform org is not counted).
func (e Entitlements) CheckOrgs(current int) error {
	if e.Limits.MaxOrgs != Unlimited && current+1 > e.Limits.MaxOrgs {
		return fmt.Errorf("%w: %d organization(s) allowed by %s (%s)", ErrLimitReached, e.Limits.MaxOrgs, e.Edition, e.Status)
	}
	return nil
}

// CheckAgents reports whether governing one more agent is allowed.
func (e Entitlements) CheckAgents(current int) error {
	if e.Limits.MaxAgents != Unlimited && current+1 > e.Limits.MaxAgents {
		return fmt.Errorf("%w: %d agent(s) allowed by %s (%s)", ErrLimitReached, e.Limits.MaxAgents, e.Edition, e.Status)
	}
	return nil
}

// BusinessUnits reports whether the edition includes business units
// (F573: Business and Enterprise; smaller tenants use only org, teams and
// environments).
func (e Entitlements) BusinessUnits() bool { return e.Edition == Business || e.Edition == Enterprise }

// OrgPackageKeys reports whether the edition lets an org register its own
// package-signing keys and import packages signed with them (F361, HR-162:
// Team and above). Packages already active keep deciding without it.
func (e Entitlements) OrgPackageKeys() bool { return e.Edition.Paid() }

// TeamWaitlist reports whether the edition offers batch review and the
// waitlist's SLA metrics (G0 M5 part 2: F171, F169, F170; Team and above).
func (e Entitlements) TeamWaitlist() bool { return e.Edition.Paid() }

// PolicyRollout reports whether the edition offers policy shadow
// evaluation, pilots and pilot cohorts (G0 M11.1, D12: Team and above). A
// publish records a completed rollout in every edition.
func (e Entitlements) PolicyRollout() bool { return e.Edition.Paid() }

// GitHubOrgScan reports whether the edition scans GitHub organizations
// (G0 M8, PN-001.2: Team and above).
func (e Entitlements) GitHubOrgScan() bool { return e.Edition.Paid() }

// PolicySimulation reports whether the edition simulates policy versions
// over recorded decisions (G0 M11.1 D15, F187: Team and above).
func (e Entitlements) PolicySimulation() bool { return e.Edition.Paid() }

// MLDSACosign reports whether the edition includes ML-DSA-65 co-signatures
// on checkpoints and pack manifests (G0 M7 decision 6, PN-007.5:
// Enterprise).
func (e Entitlements) MLDSACosign() bool { return e.Edition == Enterprise }

// Reflex editions (G0 M10 D5). Community keeps the core detections,
// graduated containment, the kill switch, search, the run's "what actually
// happened" view and the HR-037 variant-shopping rule: a hardening rule is
// never edition-gated.

// ReflexTeam reports whether the edition offers alert grouping (F603),
// suppression (F616), alert notifications and digests (F620), staged
// restoration (F568), residual follow-up (F571), the task-phase timeline
// (F232) and operating metrics (F301): Team and above.
func (e Entitlements) ReflexTeam() bool { return e.Edition.Paid() }

// Cases reports whether the edition offers investigation cases (F237, F241,
// F244, F248, F249, F251, F299): Team and above.
func (e Entitlements) Cases() bool { return e.Edition.Paid() }

// BreachRadius reports whether the edition offers breach radius and graphs
// (F253–F260, F272, F274, F289, F293, F430): Team and above.
func (e Entitlements) BreachRadius() bool { return e.Edition.Paid() }

// AdvancedDetections reports whether the edition runs the sequence,
// probing, delegation and behavior-drift detections and typical-run
// comparison (PN-006.4, PN-006.5, F399, F234): Business and above.
func (e Entitlements) AdvancedDetections() bool { return e.businessPlus() }

// CustomDetections reports whether the edition publishes custom detection
// rules (PN-006.1, founder decision F4): Business and above.
func (e Entitlements) CustomDetections() bool { return e.businessPlus() }

// PostureRemediation reports whether the edition offers the posture
// remediation queue and finding lifecycle (F265, F268): Business and above.
func (e Entitlements) PostureRemediation() bool { return e.businessPlus() }

// SIEMExport reports whether the edition exports OCSF events (PN-018):
// Business and above.
func (e Entitlements) SIEMExport() bool { return e.businessPlus() }

// SOAR reports whether the edition accepts SOAR response requests (F541):
// Business and above.
func (e Entitlements) SOAR() bool { return e.businessPlus() }

// SharedSignals reports whether the edition receives Shared Signals events
// (PN-024): Business and above.
func (e Entitlements) SharedSignals() bool { return e.businessPlus() }

func (e Entitlements) businessPlus() bool { return e.Edition == Business || e.Edition == Enterprise }
