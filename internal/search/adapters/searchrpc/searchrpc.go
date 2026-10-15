// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package searchrpc serves SearchService over Connect (G0 M10 D34,
// HR-257): structured and built-in queries and saved queries, every one
// run under the caller's permissions.
package searchrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/search"
)

// Handler serves SearchService.
type Handler struct {
	pantherclawv1connect.UnimplementedSearchServiceHandler
	svc *search.Service
}

// New returns the SearchService handler.
func New(svc *search.Service) *Handler { return &Handler{svc: svc} }

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

func idOf(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil {
		return ids.UUID{}, errInvalidID
	}
	return id, nil
}

func optID(s *string) (*ids.UUID, error) {
	if s == nil {
		return nil, nil //nolint:nilnil // unset
	}
	id, err := idOf(*s)
	return &id, err
}

func optTime(t *timestamppb.Timestamp) *time.Time {
	if t == nil {
		return nil
	}
	v := t.AsTime().UTC()
	return &v
}

func ts(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func filtersOf(f *pantherclawv1.SearchFilters) (search.Filters, error) {
	if f == nil {
		return search.Filters{}, nil
	}
	out := search.Filters{
		Operation: f.GetOperation(), OperationPrefix: f.GetOperationPrefix(), TargetType: f.GetTargetType(),
		EffectPrefix: f.GetEffectPrefix(), KindPrefix: f.GetKindPrefix(), Actor: f.GetActor(),
		Decisions: f.GetDecisions(), Modes: f.GetModes(), States: f.GetStates(), Kinds: f.GetKinds(),
		AccessModes: f.GetAccessModes(), EnvKinds: f.GetEnvironmentKinds(), UnusedSince: optTime(f.GetUnusedSince()),
		WidensOnly: f.GetWidensOnly(), Start: optTime(f.GetStartTime()), End: optTime(f.GetEndTime()),
	}
	for _, p := range []struct {
		dst **ids.UUID
		src *string
	}{
		{&out.ID, f.Id}, {&out.Agent, f.AgentId}, {&out.Run, f.RunId}, {&out.Grant, f.GrantId},
		{&out.Connection, f.ConnectionId}, {&out.Gateway, f.GatewayId}, {&out.Team, f.TeamId},
		{&out.PrincipalUser, f.PrincipalUserId}, {&out.PrincipalSA, f.PrincipalServiceAccountId},
		{&out.UsedConnection, f.UsedConnectionId},
	} {
		id, err := optID(p.src)
		if err != nil {
			return search.Filters{}, err
		}
		*p.dst = id
	}
	return out, nil
}

func queryOf(q *pantherclawv1.Query) (search.Query, error) {
	f, err := filtersOf(q.GetFilters())
	return search.Query{Entity: search.Entity(q.GetEntity()), Filters: f}, err
}

func builtinOf(b *pantherclawv1.BuiltinQuery) (search.BuiltinQuery, error) {
	p := b.GetParams()
	out := search.BuiltinQuery{Name: search.Builtin(b.GetName()), Params: search.Params{
		Effect: p.GetEffect(), TargetType: p.GetTargetType(), Days: int(p.GetDays()),
		Start: optTime(p.GetStartTime()), End: optTime(p.GetEndTime()),
	}}
	for _, x := range []struct {
		dst **ids.UUID
		src *string
	}{
		{&out.Params.Transaction, p.TransactionId}, {&out.Params.Agent, p.AgentId}, {&out.Params.Connection, p.ConnectionId},
		{&out.Params.PrincipalUser, p.PrincipalUserId}, {&out.Params.PrincipalSA, p.PrincipalServiceAccountId},
	} {
		id, err := optID(x.src)
		if err != nil {
			return search.BuiltinQuery{}, err
		}
		*x.dst = id
	}
	return out, nil
}

func idPtr(u *ids.UUID) *string {
	if u == nil {
		return nil
	}
	s := u.String()
	return &s
}

func filtersProto(f search.Filters) *pantherclawv1.SearchFilters {
	return &pantherclawv1.SearchFilters{
		Id: idPtr(f.ID), AgentId: idPtr(f.Agent), RunId: idPtr(f.Run), GrantId: idPtr(f.Grant),
		ConnectionId: idPtr(f.Connection), GatewayId: idPtr(f.Gateway), TeamId: idPtr(f.Team),
		PrincipalUserId: idPtr(f.PrincipalUser), PrincipalServiceAccountId: idPtr(f.PrincipalSA),
		UsedConnectionId: idPtr(f.UsedConnection), Operation: f.Operation, OperationPrefix: f.OperationPrefix,
		TargetType: f.TargetType, EffectPrefix: f.EffectPrefix, KindPrefix: f.KindPrefix, Actor: f.Actor,
		Decisions: f.Decisions, Modes: f.Modes, States: f.States, Kinds: f.Kinds, AccessModes: f.AccessModes,
		EnvironmentKinds: f.EnvKinds, UnusedSince: ts(f.UnusedSince), WidensOnly: f.WidensOnly,
		StartTime: ts(f.Start), EndTime: ts(f.End),
	}
}

func builtinProto(b search.BuiltinQuery) *pantherclawv1.BuiltinQuery {
	p := b.Params
	return &pantherclawv1.BuiltinQuery{Name: string(b.Name), Params: &pantherclawv1.BuiltinParams{
		TransactionId: idPtr(p.Transaction), AgentId: idPtr(p.Agent), ConnectionId: idPtr(p.Connection),
		PrincipalUserId: idPtr(p.PrincipalUser), PrincipalServiceAccountId: idPtr(p.PrincipalSA),
		Effect: p.Effect, TargetType: p.TargetType, Days: int32(p.Days), //nolint:gosec // G115: bounded by validation
		StartTime: ts(p.Start), EndTime: ts(p.End),
	}}
}

func resultProto(r search.Result) *pantherclawv1.SearchResult {
	out := &pantherclawv1.SearchResult{
		NextPageToken: r.Next, Count: int32(r.Count), CountCapped: r.Capped, //nolint:gosec // G115: at most MaxCount
		ScopePermission: string(r.Scope.Permission), ScopeWhole: r.Scope.All,
		RangeStartTime: ts(r.Range.Start), RangeEndTime: ts(r.Range.End), RangeChanging: r.Range.Changing,
		AsOfTime: timestamppb.New(r.AsOf), EmptyReason: string(r.Empty),
	}
	for _, i := range r.Items {
		it := &pantherclawv1.SearchItem{Entity: string(i.Entity), Id: i.ID, Label: i.Label, Fields: i.Fields, Evidence: i.Evidence}
		if !i.Time.IsZero() {
			it.Time = timestamppb.New(i.Time)
		}
		out.Items = append(out.Items, it)
	}
	for _, o := range r.Omissions {
		out.Omissions = append(out.Omissions, &pantherclawv1.Omission{Code: o.Code, Detail: o.Detail})
	}
	return out
}

func savedProto(q search.SavedQuery) *pantherclawv1.SavedQuery {
	out := &pantherclawv1.SavedQuery{
		Id: q.ID.String(), Owner: q.Owner, Name: q.Name, Description: q.Description, Visibility: string(q.Visibility),
		CreateTime: timestamppb.New(q.Created), UpdateTime: timestamppb.New(q.Updated), Mine: q.Mine,
	}
	if q.Team != nil {
		out.TeamId = q.Team.String()
	}
	if q.Spec.Query != nil {
		out.Query = &pantherclawv1.Query{Entity: string(q.Spec.Query.Entity), Filters: filtersProto(q.Spec.Query.Filters)}
	}
	if q.Spec.Builtin != nil {
		out.Builtin = builtinProto(*q.Spec.Builtin)
	}
	return out
}

func inputOf(in *pantherclawv1.SavedQueryInput) (search.SaveInput, error) {
	team, err := optID(in.TeamId)
	if err != nil {
		return search.SaveInput{}, err
	}
	out := search.SaveInput{Name: in.GetName(), Description: in.GetDescription(), Visibility: search.Visibility(in.GetVisibility()), Team: team}
	if in.GetQuery() != nil {
		q, err := queryOf(in.GetQuery())
		if err != nil {
			return search.SaveInput{}, err
		}
		out.Spec.Query = &q
	}
	if in.GetBuiltin() != nil {
		b, err := builtinOf(in.GetBuiltin())
		if err != nil {
			return search.SaveInput{}, err
		}
		out.Spec.Builtin = &b
	}
	return out, nil
}

// Search implements SearchServiceHandler.
func (h *Handler) Search(ctx context.Context, req *pantherclawv1.SearchRequest) (*pantherclawv1.SearchResponse, error) {
	pr, err := page.Parse(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	q, err := queryOf(req.GetQuery())
	if err != nil {
		return nil, err
	}
	r, err := h.svc.Search(ctx, q, pr)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.SearchResponse{Result: resultProto(r)}, nil
}

// ListBuiltinQueries implements SearchServiceHandler.
func (h *Handler) ListBuiltinQueries(ctx context.Context, _ *pantherclawv1.ListBuiltinQueriesRequest) (
	*pantherclawv1.ListBuiltinQueriesResponse, error,
) {
	if err := h.svc.CanSearch(ctx); err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListBuiltinQueriesResponse{}
	for _, b := range search.Builtins() {
		out.Queries = append(out.Queries, &pantherclawv1.BuiltinQueryInfo{
			Name: string(b.Name), Feature: b.Feature, Description: b.Description, Params: b.Params,
		})
	}
	return out, nil
}

// RunBuiltinQuery implements SearchServiceHandler.
func (h *Handler) RunBuiltinQuery(ctx context.Context, req *pantherclawv1.RunBuiltinQueryRequest) (
	*pantherclawv1.RunBuiltinQueryResponse, error,
) {
	pr, err := page.Parse(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	b, err := builtinOf(req.GetQuery())
	if err != nil {
		return nil, err
	}
	r, err := h.svc.RunBuiltin(ctx, b, pr)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RunBuiltinQueryResponse{Result: resultProto(r)}, nil
}

// SaveQuery implements SearchServiceHandler.
func (h *Handler) SaveQuery(ctx context.Context, req *pantherclawv1.SaveQueryRequest) (*pantherclawv1.SaveQueryResponse, error) {
	in, err := inputOf(req.GetInput())
	if err != nil {
		return nil, err
	}
	q, err := h.svc.Save(ctx, in)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.SaveQueryResponse{Query: savedProto(q)}, nil
}

// UpdateSavedQuery implements SearchServiceHandler.
func (h *Handler) UpdateSavedQuery(ctx context.Context, req *pantherclawv1.UpdateSavedQueryRequest) (
	*pantherclawv1.UpdateSavedQueryResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	in, err := inputOf(req.GetInput())
	if err != nil {
		return nil, err
	}
	q, err := h.svc.Update(ctx, id, in)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.UpdateSavedQueryResponse{Query: savedProto(q)}, nil
}

// DeleteSavedQuery implements SearchServiceHandler.
func (h *Handler) DeleteSavedQuery(ctx context.Context, req *pantherclawv1.DeleteSavedQueryRequest) (
	*pantherclawv1.DeleteSavedQueryResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	if err := h.svc.Delete(ctx, id); err != nil {
		return nil, err
	}
	return &pantherclawv1.DeleteSavedQueryResponse{}, nil
}

// GetSavedQuery implements SearchServiceHandler.
func (h *Handler) GetSavedQuery(ctx context.Context, req *pantherclawv1.GetSavedQueryRequest) (
	*pantherclawv1.GetSavedQueryResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	q, err := h.svc.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetSavedQueryResponse{Query: savedProto(q)}, nil
}

// ListSavedQueries implements SearchServiceHandler.
func (h *Handler) ListSavedQueries(ctx context.Context, req *pantherclawv1.ListSavedQueriesRequest) (
	*pantherclawv1.ListSavedQueriesResponse, error,
) {
	pr, err := page.Parse(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	p, err := h.svc.List(ctx, pr)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListSavedQueriesResponse{NextPageToken: p.Next}
	for _, q := range p.Items {
		out.Queries = append(out.Queries, savedProto(q))
	}
	return out, nil
}

// RunSavedQuery implements SearchServiceHandler.
func (h *Handler) RunSavedQuery(ctx context.Context, req *pantherclawv1.RunSavedQueryRequest) (
	*pantherclawv1.RunSavedQueryResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	pr, err := page.Parse(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	r, err := h.svc.RunSaved(ctx, id, pr)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RunSavedQueryResponse{Result: resultProto(r)}, nil
}
