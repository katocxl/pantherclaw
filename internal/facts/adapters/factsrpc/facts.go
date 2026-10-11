// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package factsrpc serves FactService over Connect (HR-160; G0 M4 part 2).
// People register and disable providers; a provider's own service account
// pushes observations. Workloads never reach this service, so nothing a
// workload sends becomes a fact.
package factsrpc

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/facts/app"
	"github.com/katocxl/pantherclaw/internal/facts/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Facts serves FactService.
type Facts struct {
	pantherclawv1connect.UnimplementedFactServiceHandler
	svc *app.Service
}

// New returns the FactService handler.
func New(svc *app.Service) *Facts { return &Facts{svc: svc} }

var (
	errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")
	errNotFound  = pcerr.New(pcerr.NotFound, "FACT_PROVIDER_NOT_FOUND", "fact provider not found")

	types = map[pantherclawv1.FactType]domain.Type{
		pantherclawv1.FactType_FACT_TYPE_BOOLEAN:    domain.TypeBoolean,
		pantherclawv1.FactType_FACT_TYPE_INTEGER:    domain.TypeInteger,
		pantherclawv1.FactType_FACT_TYPE_DECIMAL:    domain.TypeDecimal,
		pantherclawv1.FactType_FACT_TYPE_MONEY:      domain.TypeMoney,
		pantherclawv1.FactType_FACT_TYPE_IDENTIFIER: domain.TypeIdentifier,
		pantherclawv1.FactType_FACT_TYPE_TIMESTAMP:  domain.TypeTimestamp,
		pantherclawv1.FactType_FACT_TYPE_OBJECT:     domain.TypeObject,
	}
	typeProtos = func() map[domain.Type]pantherclawv1.FactType {
		out := map[domain.Type]pantherclawv1.FactType{}
		for k, v := range types {
			out[v] = k
		}
		return out
	}()
	states = map[domain.ProviderState]pantherclawv1.ProviderState{
		domain.ProviderActive:   pantherclawv1.ProviderState_PROVIDER_STATE_ACTIVE,
		domain.ProviderDisabled: pantherclawv1.ProviderState_PROVIDER_STATE_DISABLED,
	}
)

func parseID(s string) (ids.UUID, error) {
	u, err := ids.ParseUUID(s)
	if err != nil || u.Version() != 7 {
		return ids.UUID{}, errInvalidID
	}
	return u, nil
}

// ProviderProto renders a provider.
func ProviderProto(p domain.Provider) *pantherclawv1.FactProvider {
	out := &pantherclawv1.FactProvider{
		Id: p.ID.String(), Name: p.Name, ServiceAccountId: p.ServiceAccountID.String(), State: states[p.State],
	}
	for _, d := range p.Facts {
		out.Facts = append(out.Facts, &pantherclawv1.FactDeclaration{
			Name: d.Name, Type: typeProtos[d.Type], SubjectType: d.SubjectType, MaxLag: durationpb.New(d.MaxLag),
		})
	}
	return out
}

// RegisterProvider implements FactServiceHandler.
func (s *Facts) RegisterProvider(ctx context.Context, req *pantherclawv1.RegisterProviderRequest) (*pantherclawv1.RegisterProviderResponse, error) {
	sa, err := parseID(req.GetServiceAccountId())
	if err != nil {
		return nil, err
	}
	decls := make([]domain.Declaration, 0, len(req.GetFacts()))
	for _, d := range req.GetFacts() {
		decls = append(decls, domain.Declaration{
			Name: d.GetName(), Type: types[d.GetType()], SubjectType: d.GetSubjectType(), MaxLag: d.GetMaxLag().AsDuration(),
		})
	}
	p, err := s.svc.RegisterProvider(ctx, req.GetName(), sa, decls)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RegisterProviderResponse{Provider: ProviderProto(p)}, nil
}

// DisableProvider implements FactServiceHandler.
func (s *Facts) DisableProvider(ctx context.Context, req *pantherclawv1.DisableProviderRequest) (*pantherclawv1.DisableProviderResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	if err := s.svc.DisableProvider(ctx, id); err != nil {
		if errors.Is(err, app.ErrNotFound) {
			return nil, errNotFound
		}
		return nil, err
	}
	return &pantherclawv1.DisableProviderResponse{}, nil
}

// ListProviders implements FactServiceHandler.
func (s *Facts) ListProviders(ctx context.Context, req *pantherclawv1.ListProvidersRequest) (*pantherclawv1.ListProvidersResponse, error) {
	ps, err := s.svc.ListProviders(ctx, req.GetIncludeDisabled())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListProvidersResponse{}
	for _, p := range ps {
		out.Providers = append(out.Providers, ProviderProto(p))
	}
	return out, nil
}

// resultCode names why an observation was refused.
func resultCode(err error) (string, string) {
	for _, c := range []struct {
		sentinel error
		code     string
	}{
		{domain.ErrUntrusted, "FACT_UNTRUSTED"},
		{domain.ErrStale, "FACT_STALE"},
		{domain.ErrInvalid, "FACT_INVALID"},
	} {
		if errors.Is(err, c.sentinel) {
			return c.code, strings.TrimPrefix(err.Error(), c.sentinel.Error()+": ")
		}
	}
	return "FACT_REFUSED", "the observation was not recorded"
}

// PutFacts implements FactServiceHandler. Each observation gets its own
// result; one refusal does not stop the others.
func (s *Facts) PutFacts(ctx context.Context, req *pantherclawv1.PutFactsRequest) (*pantherclawv1.PutFactsResponse, error) {
	obs := make([]domain.Observation, 0, len(req.GetObservations()))
	for _, o := range req.GetObservations() {
		obs = append(obs, domain.Observation{
			Name: o.GetName(), SubjectType: o.GetSubjectType(), SubjectID: o.GetSubjectId(),
			Value: jsontext.Value(o.GetValue()), ObservedAt: o.GetObserveTime().AsTime(),
		})
	}
	results, err := s.svc.PutFacts(ctx, obs)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.PutFactsResponse{}
	for i, r := range results {
		fr := &pantherclawv1.FactResult{Index: int32(i), Accepted: r.Err == nil}
		if r.Err != nil {
			fr.Code, fr.Detail = resultCode(r.Err)
		}
		out.Results = append(out.Results, fr)
	}
	return out, nil
}

func ts(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

// ListFacts implements FactServiceHandler.
func (s *Facts) ListFacts(ctx context.Context, req *pantherclawv1.ListFactsRequest) (*pantherclawv1.ListFactsResponse, error) {
	facts, err := s.svc.ListFacts(ctx, req.GetSubjectType(), req.GetSubjectId(), req.GetNames())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListFactsResponse{}
	for _, f := range facts {
		out.Facts = append(out.Facts, &pantherclawv1.Fact{
			Name: f.Name, SubjectType: f.SubjectType, SubjectId: f.SubjectID, Value: f.Value,
			ObserveTime: ts(f.ObservedAt), RecordTime: ts(f.RecordedAt), ProviderId: f.ProviderID.String(),
		})
	}
	return out, nil
}
