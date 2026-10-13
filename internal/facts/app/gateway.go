// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/facts/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors of gateway providers.
var (
	ErrConnectionUnknown = pcerr.New(pcerr.FailedPrecondition, "CONNECTION_UNKNOWN", "the connection does not exist or is not served by that gateway")
	ErrNotDeclared       = pcerr.New(pcerr.InvalidArgument, "FACT_NOT_DECLARED",
		"a gateway provider may provide only the facts its connection's package names, about that package's targets")
)

// PackageFacts are the facts a connection's pinned package names: each
// prerequisite and consequence fact, with the target types it is about.
type PackageFacts func(ctx context.Context, org ids.OrgID, gateway, connection ids.UUID) (map[string][]string, error)

// RegisterGatewayProvider registers the gateway that serves a connection as
// the provider of facts its package names (G0 M8 decision 5, HR-160). Only
// a person holding fact.provider.manage may; each declaration must be a
// fact the package names, about the target type it names it for.
func (s *Service) RegisterGatewayProvider(ctx context.Context, name string, gateway, connection ids.UUID, decls []domain.Declaration) (domain.Provider, error) {
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
	if s.Packages == nil {
		return domain.Provider{}, ErrConnectionUnknown
	}
	named, err := s.Packages(ctx, c.Org, gateway, connection)
	if err != nil {
		return domain.Provider{}, err
	}
	for _, d := range decls {
		if !slices.Contains(named[d.Name], d.SubjectType) {
			return domain.Provider{}, fmt.Errorf("%w: %s about %s", ErrNotDeclared, d.Name, d.SubjectType)
		}
	}
	taken, err := s.Store.Taken(ctx, c.Org)
	if err != nil {
		return domain.Provider{}, err
	}
	p := domain.Provider{ID: ids.NewV7(), Org: c.Org, Name: name, GatewayID: gateway, ConnectionID: connection, State: domain.ProviderActive, Facts: decls}
	if err := p.Validate(taken); err != nil {
		return domain.Provider{}, pcerr.Wrap(err, pcerr.InvalidArgument, "PROVIDER_INVALID", err.Error())
	}
	ev := audit.Event{
		Name: "facts.provider_registered", Actor: c.Actor(), Outcome: audit.Success,
		Object:  &audit.Object{Type: "fact_provider", ID: p.ID.String()},
		Details: map[string]string{"gateway": gateway.String(), "connection": connection.String(), "facts": fmt.Sprint(len(decls))},
	}
	if err := s.Store.CreateProvider(ctx, c.Org, p, c.Principal.String(), ev); err != nil {
		return domain.Provider{}, err
	}
	return p, nil
}

// PutGatewayFacts records observations a gateway read from a connection's
// system of record before a decision (G0 M8 decision 5). The org and the
// gateway come from its mTLS certificate; the provider must be the one
// bound to that gateway and connection, and each observation must be a
// fact it declares, about its declared target type, that the package
// pinned now still names (HR-160): a declaration the pin no longer names
// is refused like an undeclared fact.
func (s *Service) PutGatewayFacts(ctx context.Context, org ids.OrgID, gateway, connection ids.UUID, obs []domain.Observation) ([]Result, error) {
	if len(obs) == 0 || len(obs) > MaxObservations {
		return nil, pcerr.New(pcerr.InvalidArgument, "OBSERVATIONS_INVALID", fmt.Sprintf("send 1..%d observations", MaxObservations))
	}
	p, err := s.Store.ProviderForConnection(ctx, org, connection)
	if errors.Is(err, ErrNotFound) || (err == nil && p.GatewayID != gateway) {
		return nil, ErrNotProvider
	}
	if err != nil {
		return nil, err
	}
	if s.Packages != nil {
		named, err := s.Packages(ctx, org, gateway, connection)
		if errors.Is(err, ErrConnectionUnknown) {
			return nil, ErrNotProvider
		} else if err != nil {
			return nil, err
		}
		p.Facts = slices.DeleteFunc(p.Facts, func(d domain.Declaration) bool { return !slices.Contains(named[d.Name], d.SubjectType) })
	}
	return s.put(ctx, org, p, obs)
}
