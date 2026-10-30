// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"time"

	"github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Recorded is a stored fact with its value as the provider sent it.
type Recorded struct {
	Name, SubjectType, SubjectID string
	Value                        []byte // typed JSON (domain.DecodeValue)
	ObservedAt, RecordedAt       time.Time
	ProviderID                   ids.UUID
	// Source and Method are its provenance (G0 M16 D80), when sent.
	Source, Method string
}

// Reads lists providers and facts for the API. It is separate from Store
// because the decision pipeline reads facts through its own port.
type Reads interface {
	ListProviders(ctx context.Context, org ids.OrgID, includeDisabled bool) ([]domain.Provider, error)
	// About returns the facts of active providers about one subject; every
	// name when names is empty.
	About(ctx context.Context, org ids.OrgID, subjectType, subjectID string, names []string) ([]Recorded, error)
}

// ListProviders lists the org's fact providers (fact.read at the org).
func (s *Service) ListProviders(ctx context.Context, includeDisabled bool) ([]domain.Provider, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.Authz.Require(c, PermFactRead, tdomain.OrgPath(c.Org)); err != nil {
		return nil, err
	}
	return s.Reads.ListProviders(ctx, c.Org, includeDisabled)
}

// ListFacts returns the current facts about one subject (fact.read at the
// org). Only facts of active providers are current.
func (s *Service) ListFacts(ctx context.Context, subjectType, subjectID string, names []string) ([]Recorded, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.Authz.Require(c, PermFactRead, tdomain.OrgPath(c.Org)); err != nil {
		return nil, err
	}
	return s.Reads.About(ctx, c.Org, subjectType, subjectID, names)
}
