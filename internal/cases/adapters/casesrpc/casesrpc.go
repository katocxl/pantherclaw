// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package casesrpc serves CaseService over Connect (G0 M10 D19).
package casesrpc

import (
	"context"
	"encoding/hex"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	capp "github.com/katocxl/pantherclaw/internal/cases/app"
	"github.com/katocxl/pantherclaw/internal/cases/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// Handler serves CaseService.
type Handler struct {
	pantherclawv1connect.UnimplementedCaseServiceHandler
	svc *capp.Service
}

// New returns the CaseService handler.
func New(svc *capp.Service) *Handler { return &Handler{svc: svc} }

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

func ts(t *time.Time) *timestamppb.Timestamp {
	if t == nil || t.IsZero() {
		return nil
	}
	return timestamppb.New(*t)
}

func str(id *ids.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

// CaseProto maps a case.
func CaseProto(k domain.Case) *pantherclawv1.Case {
	return &pantherclawv1.Case{
		Id: k.ID.String(), Title: k.Title, Source: k.Source, OpenedBy: k.OpenedBy.Type + ":" + k.OpenedBy.ID,
		AlertId: str(k.Alert), IncidentId: str(k.Incident), State: string(k.State), OwnerId: str(k.Owner),
		FollowUpOwnerId: str(k.FollowUpOwner), Disposition: string(k.Disposition), Impact: string(k.Impact),
		HeadSeq: k.HeadSeq, HeadHash: hex.EncodeToString(k.HeadHash), CreateTime: timestamppb.New(k.Created),
		UpdateTime: timestamppb.New(k.Updated), ContainTime: ts(k.OperationalClosed), CloseTime: ts(k.Closed),
	}
}

func optStr(id *ids.UUID) *string {
	if id == nil {
		return nil
	}
	s := id.String()
	return &s
}

func draftProto(d domain.Draft) *pantherclawv1.CaseEntryDraft {
	out := &pantherclawv1.CaseEntryDraft{
		Kind: string(d.Kind), Text: d.Text, Basis: string(d.Basis), Confidence: string(d.Confidence),
		Alternatives: d.Alternatives, QuestionId: optStr(d.Question), Unresolved: d.Unresolved, OwnerId: optStr(d.Owner),
		OwnerRole: string(d.OwnerRole), Impact: string(d.Impact), State: string(d.State),
		NoContainmentNeeded: d.NoContainmentNeeded, Disposition: string(d.Disposition), CaseImpact: string(d.CaseImpact),
		Reason: d.Reason, Supersedes: optStr(d.Supersedes),
	}
	for _, e := range d.Evidence {
		out.Evidence = append(out.Evidence, &pantherclawv1.CaseEvidenceRef{Kind: e.Kind, Id: e.ID.String()})
	}
	if d.Ref != nil {
		out.Ref = &pantherclawv1.CaseSubject{Type: d.Ref.Kind, Id: d.Ref.ID}
	}
	return out
}

// EntryProto maps an entry.
func EntryProto(e domain.Entry, superseded, unowned bool) *pantherclawv1.CaseEntry {
	return &pantherclawv1.CaseEntry{
		Id: e.ID.String(), Seq: e.Seq, Author: e.Author.Type + ":" + e.Author.ID, Entry: draftProto(e.Draft),
		Superseded: superseded, Unowned: unowned, LedgerEntryId: e.LedgerEntry.String(), PrevHash: hex.EncodeToString(e.PrevHash),
		EntryHash: hex.EncodeToString(e.Hash), Body: e.Body, CreateTime: timestamppb.New(e.Created),
	}
}

func draftOf(p *pantherclawv1.CaseEntryDraft) (domain.Draft, error) {
	d := domain.Draft{
		Kind: domain.Kind(p.GetKind()), Text: p.GetText(), Basis: domain.Basis(p.GetBasis()),
		Confidence: domain.Confidence(p.GetConfidence()), Alternatives: p.GetAlternatives(), Unresolved: p.GetUnresolved(),
		OwnerRole: domain.OwnerRole(p.GetOwnerRole()), Impact: domain.ImpactKind(p.GetImpact()),
		State: domain.State(p.GetState()), NoContainmentNeeded: p.GetNoContainmentNeeded(),
		Disposition: domain.Disposition(p.GetDisposition()), CaseImpact: domain.Impact(p.GetCaseImpact()), Reason: p.GetReason(),
	}
	if len(d.Alternatives) == 0 {
		d.Alternatives = nil
	}
	var err error
	if d.Question, err = optID(p.QuestionId); err != nil {
		return d, err
	}
	if d.Owner, err = optID(p.OwnerId); err != nil {
		return d, err
	}
	if d.Supersedes, err = optID(p.Supersedes); err != nil {
		return d, err
	}
	for _, e := range p.GetEvidence() {
		id, err := idOf(e.GetId())
		if err != nil {
			return d, err
		}
		d.Evidence = append(d.Evidence, domain.EvidenceRef{Kind: e.GetKind(), ID: id})
	}
	if r := p.GetRef(); r != nil {
		d.Ref = &domain.Ref{Kind: r.GetType(), ID: r.GetId()}
	}
	return d, nil
}

func subjectsOf(ps []*pantherclawv1.CaseSubject) []reflexdomain.Subject {
	out := make([]reflexdomain.Subject, 0, len(ps))
	for _, p := range ps {
		out = append(out, reflexdomain.Subject{Type: reflexdomain.SubjectType(p.GetType()), ID: p.GetId()})
	}
	return out
}

// OpenCase implements CaseServiceHandler.
func (h *Handler) OpenCase(ctx context.Context, req *pantherclawv1.OpenCaseRequest) (*pantherclawv1.OpenCaseResponse, error) {
	alert, err := optID(req.AlertId)
	if err != nil {
		return nil, err
	}
	incident, err := optID(req.IncidentId)
	if err != nil {
		return nil, err
	}
	k, err := h.svc.Open(ctx, capp.OpenRequest{
		Title: req.GetTitle(), Subjects: subjectsOf(req.GetSubjects()), Questions: req.GetQuestions(),
		Alert: alert, Incident: incident,
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.OpenCaseResponse{Case: CaseProto(k)}, nil
}

// AppendCaseEntry implements CaseServiceHandler.
func (h *Handler) AppendCaseEntry(ctx context.Context, req *pantherclawv1.AppendCaseEntryRequest) (
	*pantherclawv1.AppendCaseEntryResponse, error,
) {
	c, err := idOf(req.GetCaseId())
	if err != nil {
		return nil, err
	}
	d, err := draftOf(req.GetEntry())
	if err != nil {
		return nil, err
	}
	e, err := h.svc.Append(ctx, c, d)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.Get(ctx, c, e.Seq, 1)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.AppendCaseEntryResponse{Entry: EntryProto(e, false, false), Case: CaseProto(v.Case)}, nil
}

// GetCase implements CaseServiceHandler.
func (h *Handler) GetCase(ctx context.Context, req *pantherclawv1.GetCaseRequest) (*pantherclawv1.GetCaseResponse, error) {
	c, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	v, err := h.svc.Get(ctx, c, req.GetAfterSeq(), int(req.GetPageSize()))
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetCaseResponse{Case: CaseProto(v.Case), More: v.More, OpenQuestions: v.OpenQuestions}
	for _, e := range v.Entries {
		out.Entries = append(out.Entries, EntryProto(e, v.Superseded[e.ID], v.Unowned[e.ID]))
	}
	return out, nil
}

// ListCases implements CaseServiceHandler.
func (h *Handler) ListCases(ctx context.Context, req *pantherclawv1.ListCasesRequest) (*pantherclawv1.ListCasesResponse, error) {
	f := capp.Filter{}
	for _, s := range req.GetStates() {
		f.States = append(f.States, domain.State(s))
	}
	var err error
	if f.Owner, err = optID(req.OwnerId); err != nil {
		return nil, err
	}
	if f.Alert, err = optID(req.AlertId); err != nil {
		return nil, err
	}
	if f.Incident, err = optID(req.IncidentId); err != nil {
		return nil, err
	}
	p, err := h.svc.List(ctx, req.GetPageSize(), req.GetPageToken(), f)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListCasesResponse{NextPageToken: p.Next}
	for _, k := range p.Items {
		out.Cases = append(out.Cases, CaseProto(k))
	}
	return out, nil
}

// GetCaseLens implements CaseServiceHandler.
func (h *Handler) GetCaseLens(ctx context.Context, req *pantherclawv1.GetCaseLensRequest) (*pantherclawv1.GetCaseLensResponse, error) {
	c, err := idOf(req.GetCaseId())
	if err != nil {
		return nil, err
	}
	r := capp.LensRequest{Case: c, Lens: req.GetLens()}
	if s := req.GetSelection(); s != nil {
		r.Selection = &reflexdomain.Subject{Type: reflexdomain.SubjectType(s.GetType()), ID: s.GetId()}
	}
	if req.GetStartTime() != nil {
		r.Start = req.GetStartTime().AsTime()
	}
	if req.GetEndTime() != nil {
		r.End = req.GetEndTime().AsTime()
	}
	l, err := h.svc.GetLens(ctx, r)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetCaseLensResponse{
		Lens: l.Name, StartTime: timestamppb.New(l.Start), EndTime: timestamppb.New(l.End), Available: l.Available,
		Note: l.Note, Truncated: l.Truncated, ScopeLimited: l.ScopeLimited,
	}
	if l.Selection != nil {
		out.Selection = &pantherclawv1.CaseSubject{Type: string(l.Selection.Type), Id: l.Selection.ID}
	}
	for _, it := range l.Items {
		item := &pantherclawv1.CaseLensItem{Time: ts(&it.At), Kind: it.Kind, Title: it.Title, Detail: it.Detail, Basis: string(it.Basis)}
		for _, s := range it.Subjects {
			item.Subjects = append(item.Subjects, &pantherclawv1.CaseSubject{Type: string(s.Type), Id: s.ID})
		}
		out.Items = append(out.Items, item)
	}
	return out, nil
}

// ExportCase implements CaseServiceHandler.
func (h *Handler) ExportCase(ctx context.Context, req *pantherclawv1.ExportCaseRequest) (*pantherclawv1.ExportCaseResponse, error) {
	c, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	x, err := h.svc.Export(ctx, c)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ExportCaseResponse{Document: x.Document, AuditEntryId: x.AuditEntry.String()}, nil
}
