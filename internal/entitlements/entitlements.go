// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package entitlements is the per-org plan (G0 UI D9, D12, D37, D43;
// PN-012.2, PN-026; HR-354..361).
//
// Every gate and limit reads an org's entitlements through For (or
// Current, which finds the org in the context). Where they come from
// depends on the server's billing mode:
//
//   - licence (the default, self-hosted): the installed licence, as before;
//     an operator's comp plan overrides it for one org.
//   - off (development only; production refuses it): every org is DEV,
//     with every feature and no limit.
//   - external (hosted): the org's plan row, written only by the billing
//     extension through ApplyPlan, by the operator's comp command, never by
//     an API or browser call (HR-354); an org without a row has no plan.
//
// A lapsed, paused, canceled or missing plan never weakens enforcement
// (HR-357): the entitlements keep the org's last edition and limits, and
// only the plan gate (Gate) refuses changes.
package entitlements

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/tenantctx"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// Mode is the server's billing mode (config billing.mode).
type Mode string

// Billing modes.
const (
	ModeLicence  Mode = "licence"
	ModeOff      Mode = "off"
	ModeExternal Mode = "external"
)

// Valid reports whether m is a known mode.
func (m Mode) Valid() bool { return m == ModeLicence || m == ModeOff || m == ModeExternal }

// Status is where an org's plan stands.
type Status string

// Plan statuses.
const (
	StatusNone     Status = "NONE"
	StatusTrialing Status = "TRIALING"
	StatusActive   Status = "ACTIVE"
	StatusPastDue  Status = "PAST_DUE"
	StatusPaused   Status = "PAUSED"
	StatusCanceled Status = "CANCELED"
	StatusLapsed   Status = "LAPSED"
	StatusComp     Status = "COMP"
	StatusDev      Status = "DEV"
)

// Billing reports whether s may come from the billing extension (HR-361:
// COMP and DEV never do).
func (s Status) Billing() bool {
	switch s {
	case StatusNone, StatusTrialing, StatusActive, StatusPastDue, StatusPaused, StatusCanceled, StatusLapsed:
		return true
	case StatusComp, StatusDev:
		return false
	}
	return false
}

// Source says where a plan came from.
type Source string

// Plan sources.
const (
	SourceLicence Source = "LICENCE"
	SourceBilling Source = "BILLING"
	SourceComp    Source = "COMP"
	SourceDev     Source = "DEV"
)

// Editions a plan may name: the licence editions and development.
const EditionDevelopment = "development"

// ValidEdition reports whether e names an edition.
func ValidEdition(e string) bool {
	switch billing.Edition(e) {
	case billing.Community, billing.Team, billing.Business, billing.Enterprise:
		return true
	}
	return e == EditionDevelopment
}

// Limits are a plan's limits; 0 means unlimited.
type Limits struct {
	MaxAgents         int `json:"max_agents,omitzero"`
	MaxEnvironments   int `json:"max_environments,omitzero"`
	RetentionDays     int `json:"retention_days,omitzero"`
	InstanceAllowance int `json:"instance_allowance,omitzero"`
	MaxMembers        int `json:"max_members,omitzero"`
}

// maxLimit bounds a limit (the database CHECK allows up to 10^9).
const maxLimit = 1_000_000_000

func (l Limits) valid() bool {
	for _, n := range []int{l.MaxAgents, l.MaxEnvironments, l.RetentionDays, l.InstanceAllowance, l.MaxMembers} {
		if n < 0 || n > maxLimit {
			return false
		}
	}
	return true
}

// Plan is an org's effective plan.
type Plan struct {
	Org         ids.OrgID
	PlanID      string
	Edition     string
	Status      Status
	Source      Source
	Limits      Limits
	Features    []string
	PeriodEnd   *time.Time
	CompUntil   *time.Time
	CompReason  string
	Version     int64
	LastEventAt *time.Time
	LapsedAt    *time.Time
}

// Licence is the installed licence (billing.Service.Licence, adapted with
// LicenceFunc).
type Licence interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// LicenceFunc adapts a function to Licence.
type LicenceFunc func(ctx context.Context) (billing.Entitlements, error)

// Current implements Licence.
func (f LicenceFunc) Current(ctx context.Context) (billing.Entitlements, error) { return f(ctx) }

// Service resolves and writes per-org plans.
type Service struct {
	pool    *db.Pool
	licence Licence
	mode    Mode
	clock   clock.Clock
	log     *slog.Logger
}

// New returns the service. mode "" is ModeLicence.
func New(pool *db.Pool, licence Licence, mode Mode, clk clock.Clock, log *slog.Logger) (*Service, error) {
	if mode == "" {
		mode = ModeLicence
	}
	if !mode.Valid() {
		return nil, fmt.Errorf("entitlements: unknown billing mode %q", mode)
	}
	if pool == nil || licence == nil {
		return nil, errors.New("entitlements: pool and licence are required")
	}
	if clk == nil {
		clk = clock.System{}
	}
	if log == nil {
		log = pclog.Discard()
	}
	return &Service{pool: pool, licence: licence, mode: mode, clock: clk, log: log}, nil
}

// Mode returns the billing mode.
func (s *Service) Mode() Mode { return s.mode }

// Current returns the entitlements of the org the context is for: the
// authenticated caller's org, or the org a job named with tenantctx.WithOrg.
// Without either it returns the licence's (as self-hosted servers always did).
func (s *Service) Current(ctx context.Context) (billing.Entitlements, error) {
	if org, ok := orgOfContext(ctx); ok {
		return s.For(ctx, org)
	}
	return s.licence.Current(ctx)
}

// OrgEntitlements implements billing.OrgSource: the entitlements of the org
// ctx is for (caller or tenantctx), ok false when it names none.
func (s *Service) OrgEntitlements(ctx context.Context) (billing.Entitlements, bool, error) {
	org, ok := orgOfContext(ctx)
	if !ok {
		return billing.Entitlements{}, false, nil
	}
	e, err := s.For(ctx, org)
	return e, true, err
}

func orgOfContext(ctx context.Context) (ids.OrgID, bool) {
	if c, err := tapp.CallerFrom(ctx); err == nil {
		return c.Org, true
	}
	return tenantctx.Org(ctx)
}

// For returns org's entitlements, which every gate and limit reads.
func (s *Service) For(ctx context.Context, org ids.OrgID) (billing.Entitlements, error) {
	p, err := s.Plan(ctx, org)
	if err != nil {
		return billing.Entitlements{}, err
	}
	if p.Source == SourceLicence {
		return s.licence.Current(ctx)
	}
	return p.entitlements(), nil
}

// Plan returns org's effective plan: development mode's, the licence's
// (self-hosted: plan rows never override a licence, D85), or the hosted
// org's — its comp plan while in force, else its billing state, a
// canceled plan past its period end reading as LAPSED (D87).
func (s *Service) Plan(ctx context.Context, org ids.OrgID) (Plan, error) {
	switch s.mode {
	case ModeOff:
		return Plan{Org: org, Edition: EditionDevelopment, Status: StatusDev, Source: SourceDev}, nil
	case ModeLicence:
		lic, err := s.licence.Current(ctx)
		if err != nil {
			return Plan{}, err
		}
		return Plan{Org: org, Edition: string(lic.Edition), Status: StatusActive, Source: SourceLicence, Limits: Limits{
			MaxAgents: fromLicence(lic.Limits.MaxAgents),
		}}, nil
	case ModeExternal:
	}
	var row dbq.PcOrgEntitlement
	found := true
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		row, err = dbq.New(tx).GetOrgEntitlements(ctx, org)
		if db.IsNoRows(err) {
			found = false
			return nil
		}
		return err
	}, db.ReadOnly())
	if err != nil {
		return Plan{}, fmt.Errorf("entitlements: read plan: %w", err)
	}
	if !found {
		return Plan{Org: org, Edition: string(billing.Community), Status: StatusNone, Source: SourceBilling}, nil
	}
	p, err := effectivePlan(row, s.clock.Now())
	p.LapsedAt = row.LapsedAt
	if p.LapsedAt == nil && (p.Status == StatusLapsed || p.Status == StatusPaused) {
		p.LapsedAt = row.PeriodEnd
		if row.CompUntil != nil && row.Source != string(SourceBilling) {
			p.LapsedAt = row.CompUntil
		}
	}
	return p, err
}

func fromLicence(n int) int {
	if n == billing.Unlimited {
		return 0
	}
	return n
}

// effectivePlan is a hosted org's plan at now (D87): the comp plan while it
// is in force; otherwise the billing state (a canceled plan past its period
// end reads as LAPSED); with no billing state, an ended comp plan reads as
// LAPSED with its edition (enforcement never weakens, HR-357).
func effectivePlan(r dbq.PcOrgEntitlement, now time.Time) (Plan, error) {
	var l Limits
	if len(r.Limits) > 0 {
		if err := json.Unmarshal(r.Limits, &l); err != nil {
			return Plan{}, fmt.Errorf("entitlements: limits of %s: %w", r.OrgID, err)
		}
	}
	comp := r.CompUntil != nil && r.CompAt != nil && r.CompPlanID != nil && r.CompEdition != nil
	inForce := comp && now.Before(*r.CompUntil)
	reason := ""
	if r.CompReason != nil {
		reason = *r.CompReason
	}
	switch {
	case inForce:
		return Plan{
			Org: r.OrgID, PlanID: *r.CompPlanID, Edition: *r.CompEdition, Status: StatusComp, Source: SourceComp,
			CompUntil: r.CompUntil, CompReason: reason, Version: r.Version, LastEventAt: r.LastEventAt,
		}, nil
	case r.Source == string(SourceBilling):
		p := Plan{
			Org: r.OrgID, PlanID: r.PlanID, Edition: r.Edition, Status: Status(r.Status), Source: SourceBilling, Limits: l,
			Features: r.Features, PeriodEnd: r.PeriodEnd, Version: r.Version, LastEventAt: r.LastEventAt,
		}
		if p.Status == StatusCanceled && (p.PeriodEnd == nil || !now.Before(*p.PeriodEnd)) {
			p.Status = StatusLapsed
		}
		return p, nil
	case comp:
		return Plan{
			Org: r.OrgID, PlanID: *r.CompPlanID, Edition: *r.CompEdition, Status: StatusLapsed, Source: SourceComp,
			CompUntil: r.CompUntil, CompReason: reason, Version: r.Version,
		}, nil
	}
	return Plan{Org: r.OrgID, Edition: string(billing.Community), Status: StatusNone, Source: SourceBilling, Version: r.Version}, nil
}

// entitlements turns a plan into what the gates read. The edition and
// limits stay whatever the plan's status (HR-357); development is every
// feature (Enterprise) without a limit.
func (p Plan) entitlements() billing.Entitlements {
	if p.Status == StatusNone {
		e := billing.CommunityEntitlements()
		e.Limits.MaxOrgs = billing.Unlimited
		return e
	}
	ed, l := billing.Edition(p.Edition), p.Limits
	if p.Edition == EditionDevelopment {
		ed, l = billing.Enterprise, Limits{}
	}
	return billing.Entitlements{
		Edition: ed, Status: billing.StatusValid,
		Limits: billing.Limits{
			MaxAgents: toLimit(l.MaxAgents), MaxOrgs: billing.Unlimited,
			MaxEnvironments: toLimit(l.MaxEnvironments), MaxMembers: toLimit(l.MaxMembers),
		},
	}
}

func toLimit(n int) int {
	if n <= 0 {
		return billing.Unlimited
	}
	return n
}
