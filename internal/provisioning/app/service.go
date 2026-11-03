// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app is the core's side of provisioning (G0 M26 D405, D406, D409):
// the SCIM directory and the SAML sign-in that the private enterprise
// package drives through internal/provisioning/ports, and the people's
// side, ProvisioningService, where tokens, connections and group role
// mappings are filed as protected changes.
package app

import (
	"context"
	"log/slog"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/idps"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/protect"
	"github.com/katocxl/pantherclaw/internal/provisioning/ports"
)

// Editions reports the licence's entitlements.
type Editions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// Service is every provisioning use case. Pool, IdPs and Gate are
// required; the rest may be nil in tests.
type Service struct {
	Pool *db.Pool
	// IdPs is the organization identity provider store: the deployment's
	// issuers and the lock-out guard (HR-484).
	IdPs *idps.Store
	Gate *protect.Gate
	// Editions nil refuses everything that adds (ErrEdition).
	Editions Editions
	// Notify tells every org admin of a filed and an applied change.
	Notify idps.Notifier
	// Browser opens sessions for a verified SAML assertion.
	Browser *authnapp.Browser
	// CheckURL is the core's check of a public HTTPS URL (SAML sign-in).
	CheckURL func(string) error
	Clock    clock.Clock
	Log      *slog.Logger
}

var _ ports.Directory = (*Service)(nil)

// Errors of ProvisioningService.
var (
	ErrEdition = pcerr.New(pcerr.PermissionDenied, "EDITION_REQUIRED", "SCIM and SAML need the Enterprise edition")
	ErrHuman   = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person can change provisioning")
	ErrState   = pcerr.New(pcerr.FailedPrecondition, "PROVISIONING_STATE", "it is not in a state that allows this")
	ErrIssuer  = pcerr.New(pcerr.InvalidArgument, "SCIM_ISSUER_UNKNOWN",
		"a SCIM token provisions the users of one of the organization's or the deployment's identity providers")
	ErrInvalid = pcerr.New(pcerr.InvalidArgument, "SCIM_TOKEN_INVALID",
		"a SCIM token needs a name of lowercase letters, digits and hyphens, a subject attribute of userName or externalId, and a life of 1-366 days")
	ErrNotFound    = pcerr.New(pcerr.NotFound, "PROVISIONING_NOT_FOUND", "not found")
	ErrNameTaken   = pcerr.New(pcerr.AlreadyExists, "PROVISIONING_NAME_TAKEN", "the name or entity id is taken")
	ErrTooMany     = pcerr.New(pcerr.ResourceExhausted, "SAML_CONNECTION_LIMIT", "the organization has as many SAML connections as it may")
	ErrMappingSame = pcerr.New(pcerr.AlreadyExists, "GROUP_ROLE_MAPPING_EXISTS", "the group already carries this role at this scope")
)

func (s *Service) entitled(ctx context.Context, need func(billing.Entitlements) bool) error {
	if s.Editions == nil {
		return ErrEdition
	}
	e, err := s.Editions.Current(ctx)
	if err != nil {
		return err
	}
	if !need(e) {
		return ErrEdition
	}
	return nil
}

func (s *Service) log() *slog.Logger {
	if s.Log == nil {
		return slog.Default()
	}
	return s.Log
}

func (s *Service) now() clock.Clock {
	if s.Clock == nil {
		return clock.System{}
	}
	return s.Clock
}

func scim(e billing.Entitlements) bool { return e.SCIM() }
func saml(e billing.Entitlements) bool { return e.SAML() }
