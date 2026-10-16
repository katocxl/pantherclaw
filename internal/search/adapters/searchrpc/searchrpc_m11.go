// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package searchrpc

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/search"
)

// Quick find, plain-language questions, opening a case from results and
// exporting results (G0 M11 part 2 D45, D46, D48; HR-295, HR-296).

func matchProto(m search.Match) *pantherclawv1.FindMatch {
	out := &pantherclawv1.FindMatch{
		Kind: string(m.Kind), Id: m.ID, Label: m.Label, State: m.State, MatchedBy: m.MatchedBy, Evidence: m.Evidence,
	}
	if !m.Time.IsZero() {
		out.Time = timestamppb.New(m.Time)
	}
	return out
}

func omissionsProto(os []search.Omission) []*pantherclawv1.Omission {
	out := make([]*pantherclawv1.Omission, 0, len(os))
	for _, o := range os {
		out = append(out, &pantherclawv1.Omission{Code: o.Code, Detail: o.Detail})
	}
	return out
}

// Find implements SearchServiceHandler.
func (h *Handler) Find(ctx context.Context, req *pantherclawv1.FindRequest) (*pantherclawv1.FindResponse, error) {
	r := search.FindRequest{Text: req.GetText(), Limit: int(req.GetLimit())}
	for _, k := range req.GetKinds() {
		r.Kinds = append(r.Kinds, search.FindKind(k))
	}
	res, err := h.svc.Find(ctx, r)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.FindResponse{Text: res.Text, Omissions: omissionsProto(res.Omissions), AsOfTime: timestamppb.New(res.AsOf)}
	for _, k := range res.Kinds {
		kr := &pantherclawv1.FindKindResult{
			Kind: string(k.Kind), Count: int32(k.Count), CountCapped: k.Capped, //nolint:gosec // G115: at most MaxCount
			ScopePermission: string(k.Scope.Permission), ScopeWhole: k.Scope.All, CountPrefixOnly: k.PrefixOnly,
		}
		for _, m := range k.Matches {
			kr.Matches = append(kr.Matches, matchProto(m))
		}
		out.Kinds = append(out.Kinds, kr)
	}
	return out, nil
}

func interpretationProto(in search.Interpretation) *pantherclawv1.Interpretation {
	out := &pantherclawv1.Interpretation{
		Question: in.Question, Entity: in.Entity, Filters: in.Filters, Environment: in.Environment,
		RangeStartTime: ts(in.Start), RangeEndTime: ts(in.End), Timezone: in.Timezone, EventMeaning: string(in.Meaning),
		Matched: in.Matched, UnknownWords: in.UnknownWords, NeedsClarification: in.NeedsClarification,
		Clarifications: in.Clarifications,
	}
	out.Query, out.Builtin = SpecProto(search.Spec{Query: in.Query, Builtin: in.Builtin})
	for _, a := range in.Ambiguities {
		pa := &pantherclawv1.Ambiguity{Phrase: a.Phrase}
		for _, m := range a.Candidates {
			pa.Candidates = append(pa.Candidates, matchProto(m))
		}
		out.Ambiguities = append(out.Ambiguities, pa)
	}
	return out
}

// Interpret implements SearchServiceHandler.
func (h *Handler) Interpret(ctx context.Context, req *pantherclawv1.InterpretRequest) (*pantherclawv1.InterpretResponse, error) {
	in, err := h.svc.Interpret(ctx, req.GetQuestion(), req.GetTimezone())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.InterpretResponse{Interpretation: interpretationProto(in)}, nil
}

// Ask implements SearchServiceHandler.
func (h *Handler) Ask(ctx context.Context, req *pantherclawv1.AskRequest) (*pantherclawv1.AskResponse, error) {
	pr, err := page.Parse(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	a, err := h.svc.Ask(ctx, req.GetQuestion(), req.GetTimezone(), pr)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.AskResponse{Interpretation: interpretationProto(a.Interpretation)}
	if a.Result != nil {
		out.Result = resultProto(*a.Result)
	}
	return out, nil
}

func sourceOf(s *pantherclawv1.SearchSource) (search.Source, error) {
	var out search.Source
	if s.GetQuery() != nil {
		q, err := queryOf(s.GetQuery())
		if err != nil {
			return search.Source{}, err
		}
		out.Query = &q
	}
	if s.GetBuiltin() != nil {
		b, err := builtinOf(s.GetBuiltin())
		if err != nil {
			return search.Source{}, err
		}
		out.Builtin = &b
	}
	id, err := optID(s.SavedQueryId)
	if err != nil {
		return search.Source{}, err
	}
	out.Saved = id
	return out, nil
}

// OpenCaseFromResults implements SearchServiceHandler.
func (h *Handler) OpenCaseFromResults(ctx context.Context, req *pantherclawv1.OpenCaseFromResultsRequest) (
	*pantherclawv1.OpenCaseFromResultsResponse, error,
) {
	src, err := sourceOf(req.GetSource())
	if err != nil {
		return nil, err
	}
	id, err := h.svc.OpenCaseFromResults(ctx, search.OpenCaseRequest{Source: src, Items: req.GetItemIds(), Title: req.GetTitle()})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.OpenCaseFromResultsResponse{CaseId: id.String()}, nil
}

// ExportResults implements SearchServiceHandler.
func (h *Handler) ExportResults(ctx context.Context, req *pantherclawv1.ExportResultsRequest) (
	*pantherclawv1.ExportResultsResponse, error,
) {
	src, err := sourceOf(req.GetSource())
	if err != nil {
		return nil, err
	}
	e, err := h.svc.ExportResults(ctx, src, req.GetFormat())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ExportResultsResponse{
		Format: e.Format, ContentType: e.ContentType, Data: e.Data, Rows: int32(e.Rows), Truncated: e.Truncated, //nolint:gosec // G115: at most MaxExportRows
		Omissions: omissionsProto(e.Omissions), ScopePermission: string(e.Scope.Permission), ScopeWhole: e.Scope.All,
		AsOfTime: timestamppb.New(e.AsOf), AuditEntryId: e.AuditID.String(),
	}, nil
}
