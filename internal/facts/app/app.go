// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app holds the fact use cases (HR-160; G0 M4 part 2, design
// decision 11): people register and disable fact providers; a provider's
// own service account pushes observations, which become facts only for the
// names it is registered for. Nothing a workload sends is ever a fact: a
// workload is not a tenancy caller, so it reaches none of these use cases.
package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/facts/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Permissions of the fact use cases (the tenancy catalog's).
const (
	PermFactRead           = tdomain.PermFactRead
	PermFactProviderManage = tdomain.PermFactProviderManage // human only
	PermFactWrite          = tdomain.PermFactWrite
)

// MaxObservations caps one PutFacts call.
const MaxObservations = 100

// Errors.
var (
	ErrNotFound              = errors.New("facts: not found")
	ErrHumanOnly             = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person can do this")
	ErrNotProvider           = pcerr.New(pcerr.PermissionDenied, "NOT_A_FACT_PROVIDER", "the caller is not the service account of an active fact provider")
	ErrServiceAccountUnknown = pcerr.New(pcerr.FailedPrecondition, "SERVICE_ACCOUNT_UNKNOWN", "the service account does not exist in the org")
	ErrProviderExists        = pcerr.New(pcerr.AlreadyExists, "FACT_PROVIDER_EXISTS", "a fact provider with that name, or one already providing these facts, exists")
)

// Store persists providers and facts.
type Store interface {
	// Taken reports whether an active declaration already uses a fact
	// name (compared with dots as underscores).
	Taken(ctx context.Context, org ids.OrgID) (func(name string) bool, error)
	CreateProvider(ctx context.Context, org ids.OrgID, p domain.Provider, createdBy string, ev audit.Event) error
	DisableProvider(ctx context.Context, org ids.OrgID, id ids.UUID, ev audit.Event) error
	// ProviderFor returns the active provider bound to a service account.
	ProviderFor(ctx context.Context, org ids.OrgID, serviceAccount ids.UUID) (domain.Provider, error)
	// ProviderForConnection returns the active gateway provider of a
	// connection (G0 M8).
	ProviderForConnection(ctx context.Context, org ids.OrgID, connection ids.UUID) (domain.Provider, error)
	// Now returns the database time.
	Now(ctx context.Context, org ids.OrgID) (time.Time, error)
	// Latest returns the recorded fact for (name, subject), or nil.
	Latest(ctx context.Context, org ids.OrgID, name, subjectType, subjectID string) (*domain.Fact, error)
	// Put records a fact unless a newer observation is recorded meanwhile;
	// it reports whether it wrote.
	Put(ctx context.Context, org ids.OrgID, f domain.Fact) (bool, error)
}

// Authorizer checks a caller's permission at a path.
type Authorizer interface {
	Require(c tapp.Caller, p tdomain.Permission, path tdomain.Path) error
}

// Service runs the fact use cases.
type Service struct {
	Store Store
	Authz Authorizer
	// Reads serves the API's listings (optional elsewhere).
	Reads Reads
	// Packages names the facts a connection's package uses, for gateway
	// providers (optional elsewhere).
	Packages PackageFacts
}

// RegisterProvider registers a provider bound to a service account. Only a
// person holding fact.provider.manage may.
func (s *Service) RegisterProvider(ctx context.Context, name string, serviceAccount ids.UUID, decls []domain.Declaration) (domain.Provider, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return domain.Provider{}, err
	}
	if !c.Human() {
		return domain.Provider{}, ErrHumanOnly
	}
	if err := s.Authz.Require(c, PermFactProviderManage, tdomain.OrgPath(c.Org)); err != nil {
		return domain.Provider{}, err
	}
	taken, err := s.Store.Taken(ctx, c.Org)
	if err != nil {
		return domain.Provider{}, err
	}
	p := domain.Provider{ID: ids.NewV7(), Org: c.Org, Name: name, ServiceAccountID: serviceAccount, State: domain.ProviderActive, Facts: decls}
	if err := p.Validate(taken); err != nil {
		return domain.Provider{}, pcerr.Wrap(err, pcerr.InvalidArgument, "PROVIDER_INVALID", err.Error())
	}
	ev := audit.Event{
		Name: "facts.provider_registered", Actor: c.Actor(), Outcome: audit.Success,
		Object:  &audit.Object{Type: "fact_provider", ID: p.ID.String()},
		Details: map[string]string{"service_account": serviceAccount.String(), "facts": fmt.Sprint(len(decls))},
	}
	if err := s.Store.CreateProvider(ctx, c.Org, p, c.Principal.String(), ev); err != nil {
		return domain.Provider{}, err
	}
	return p, nil
}

// DisableProvider stops a provider; its facts stop counting at once.
func (s *Service) DisableProvider(ctx context.Context, id ids.UUID) error {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return err
	}
	if !c.Human() {
		return ErrHumanOnly
	}
	if err := s.Authz.Require(c, PermFactProviderManage, tdomain.OrgPath(c.Org)); err != nil {
		return err
	}
	return s.Store.DisableProvider(ctx, c.Org, id, audit.Event{
		Name: "facts.provider_disabled", Actor: c.Actor(),
		Outcome: audit.Success, Object: &audit.Object{Type: "fact_provider", ID: id.String()},
	})
}

// Result says what happened to one observation.
type Result struct {
	Name, SubjectID string
	Err             error
}

// PutFacts records observations pushed by a provider's own service account
// (HR-160). Each one is accepted only for a name the provider declares,
// with a typed value and an observation time the database clock allows; an
// older observation never replaces a newer one.
func (s *Service) PutFacts(ctx context.Context, obs []domain.Observation) ([]Result, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if c.Principal.Kind != tdomain.KindServiceAccount {
		return nil, ErrNotProvider
	}
	if len(obs) == 0 || len(obs) > MaxObservations {
		return nil, pcerr.New(pcerr.InvalidArgument, "OBSERVATIONS_INVALID", fmt.Sprintf("send 1..%d observations", MaxObservations))
	}
	if err := s.Authz.Require(c, PermFactWrite, tdomain.OrgPath(c.Org)); err != nil {
		return nil, err
	}
	p, err := s.Store.ProviderFor(ctx, c.Org, c.Principal.ID)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNotProvider
	}
	if err != nil {
		return nil, err
	}
	return s.put(ctx, c.Org, p, obs)
}

// put records each observation of provider p that it may make.
func (s *Service) put(ctx context.Context, org ids.OrgID, p domain.Provider, obs []domain.Observation) ([]Result, error) {
	now, err := s.Store.Now(ctx, org)
	if err != nil {
		return nil, err
	}
	out := make([]Result, 0, len(obs))
	for _, o := range obs {
		r := Result{Name: o.Name, SubjectID: o.SubjectID}
		prev, err := s.Store.Latest(ctx, org, o.Name, o.SubjectType, o.SubjectID)
		if err != nil {
			return nil, err
		}
		f, err := domain.Accept(p, o, now, prev)
		if err == nil {
			var wrote bool
			if wrote, err = s.Store.Put(ctx, org, f); err == nil && !wrote {
				err = fmt.Errorf("%w: a newer observation of %s was recorded meanwhile", domain.ErrStale, o.Name)
			}
		}
		r.Err = err
		out = append(out, r)
	}
	return out, nil
}
