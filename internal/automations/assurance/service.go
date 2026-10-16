// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package assurance

import (
	"context"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Entitlements reports the current edition (billing.Service).
type Entitlements interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// API errors.
var (
	ErrEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED",
		"automation assurance needs the Team edition or above")
	ErrBusiness = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED",
		"automation exposure previews need the Business edition or above")
	ErrNotFound     = pcerr.New(pcerr.NotFound, "AUTOMATION_NOT_FOUND", "automation, version or run not found")
	ErrVersionState = pcerr.New(pcerr.FailedPrecondition, "VERSION_STATE",
		"the version's tests change only while it is DRAFT or VALIDATED, and run only once it is VALIDATED")
	ErrDefinition = pcerr.New(pcerr.FailedPrecondition, "DEFINITION_UNREADABLE", "the version's definition cannot be read")
	ErrCases      = pcerr.New(pcerr.InvalidArgument, "TEST_CASES_INVALID", "the test cases do not fit the version")
)

// Service serves AssuranceService. Every call needs a person or service
// account holding the permission at the org (automations are org objects);
// previews of reach also apply exposure.read where each agent lives.
type Service struct {
	Pool  *db.Pool
	Ents  Entitlements
	Clock clock.Clock
}

func (s *Service) now() clock.Clock {
	if s.Clock == nil {
		return clock.System{}
	}
	return s.Clock
}

// edition checks Team (business false) or Business; a missing licence
// service offers nothing (fail closed).
func (s *Service) edition(ctx context.Context, business bool) error {
	if s.Ents == nil {
		return ErrEdition
	}
	e, err := s.Ents.Current(ctx)
	if err != nil {
		return err
	}
	switch {
	case business && !e.AutomationLatentExposure():
		return ErrBusiness
	case !e.Automations():
		return ErrEdition
	}
	return nil
}

// caller is the authenticated caller holding perm at the org.
func caller(ctx context.Context, perm td.Permission) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return tenancy.Caller{}, err
	}
	if err := c.Require(perm, td.OrgPath(c.Org)); err != nil {
		return tenancy.Caller{}, err
	}
	return c, nil
}

// version reads a version with its automation and parses its definition.
func version(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID) (dbq.AssuranceVersionRow, *autodomain.Definition, error) {
	v, err := q.AssuranceVersion(ctx, org, id)
	if db.IsNoRows(err) {
		return v, nil, ErrNotFound
	} else if err != nil {
		return v, nil, err
	}
	def, err := autodomain.Parse(v.Definition)
	if err != nil {
		return v, nil, ErrDefinition
	}
	return v, def, nil
}
