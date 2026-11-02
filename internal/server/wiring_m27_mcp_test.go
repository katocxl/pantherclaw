// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"slices"
	"testing"

	"connectrpc.com/connect/v2"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type fixedEditions billing.Edition

func (e fixedEditions) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Edition(e)}, nil
}

// auditLog collects what a gate records; fail makes every write fail.
type auditLog struct {
	events []audit.Event
	fail   bool
	// sent counts the stream's sends when each record was written.
	sentAt []int
	stream *fakeStream
}

func (l *auditLog) record(_ context.Context, _ ids.OrgID, ev audit.Event) error {
	if l.fail {
		return errors.New("ledger down")
	}
	l.events = append(l.events, ev)
	if l.stream != nil {
		l.sentAt = append(l.sentAt, len(l.stream.sent))
	}
	return nil
}

func testGate(edition billing.Edition, l *auditLog) *selfMCPGate {
	if l == nil {
		l = &auditLog{}
	}
	return &selfMCPGate{editions: fixedEditions(edition), record: l.record}
}

// fakeStream hands the handler one request and keeps what it sends.
type fakeStream struct {
	request any
	sent    []any
}

func (s *fakeStream) Receive(msg any) error {
	switch m := msg.(type) {
	case *pb.GetRunTimelineRequest:
		m.RunId = s.request.(*pb.GetRunTimelineRequest).GetRunId()
	case *pb.SearchRequest:
		m.Query = s.request.(*pb.SearchRequest).GetQuery()
		m.PageSize = s.request.(*pb.SearchRequest).GetPageSize()
	}
	return nil
}
func (s *fakeStream) SendHeaders() error { return nil }
func (s *fakeStream) Send(msg any) error {
	s.sent = append(s.sent, msg)
	return nil
}

// handler reads its request and answers, or fails with fail.
func handler(req any, fail error) connect.ServerFunc {
	return func(_ context.Context, _ connect.Spec, s connect.ServerStream) error {
		if err := s.Receive(req); err != nil {
			return err
		}
		if fail != nil {
			return fail
		}
		return s.Send(&pb.GetRunTimelineResponse{State: "record"})
	}
}

func call(g *selfMCPGate, c tapp.Caller, procedure string, s *fakeStream, req any, fail error) error {
	return g.intercept(handler(req, fail))(tapp.WithCaller(context.Background(), c), connect.Spec{Procedure: procedure}, s)
}

// TestHR657_EveryReadIsRecordedBeforeItsAnswer: the record names the read,
// the run asked for and the key, and is written before the first send.
// Covers: F948
func TestHR657_EveryReadIsRecordedBeforeItsAnswer(t *testing.T) {
	c := investigatorCaller()
	c.CredentialID = ids.NewV7()
	run := ids.NewV7().String()
	s := &fakeStream{request: &pb.GetRunTimelineRequest{RunId: run}}
	l := &auditLog{stream: s}
	if err := call(testGate(billing.Team, l), c, pantherclawv1connect.InvestigationServiceGetRunTimelineProcedure, s, &pb.GetRunTimelineRequest{}, nil); err != nil {
		t.Fatal(err)
	}
	if len(l.events) != 1 || len(s.sent) != 1 || l.sentAt[0] != 0 {
		t.Fatalf("events %v, sent %d, recorded at %v", l.events, len(s.sent), l.sentAt)
	}
	ev := l.events[0]
	if ev.Name != selfMCPAuditName || ev.Outcome != audit.Success || ev.Object == nil || ev.Object.Type != "run" || ev.Object.ID != run ||
		ev.Details["procedure"] != pantherclawv1connect.InvestigationServiceGetRunTimelineProcedure || ev.Details["key_id"] != c.CredentialID.String() {
		t.Errorf("event %+v", ev)
	}
	if ev.Actor.Type != string(td.KindServiceAccount) {
		t.Errorf("actor %+v", ev.Actor)
	}
}

// TestHR657_NoRecordNoAnswer: when the record cannot be written, nothing is
// sent and the call fails AUDIT_UNAVAILABLE; without a recorder at all the
// read does not run.
// Covers: F948
func TestHR657_NoRecordNoAnswer(t *testing.T) {
	c := investigatorCaller()
	s := &fakeStream{request: &pb.GetRunTimelineRequest{RunId: ids.NewV7().String()}}
	err := call(testGate(billing.Team, &auditLog{fail: true}), c, pantherclawv1connect.InvestigationServiceGetRunTimelineProcedure, s, &pb.GetRunTimelineRequest{}, nil)
	if !errors.Is(err, errSelfMCPAudit) || len(s.sent) != 0 {
		t.Errorf("err %v, sent %d", err, len(s.sent))
	}
	g := testGate(billing.Team, nil)
	g.record = nil
	ran, _, err := passesWith(g, c, pantherclawv1connect.SearchServiceSearchProcedure)
	if ran || !errors.Is(err, errSelfMCPAudit) {
		t.Errorf("no recorder: ran=%v err=%v", ran, err)
	}
}

// TestHR657_FailedReadIsRecordedWithItsCode and keeps only the entity of a
// search, never its filters.
// Covers: F948
func TestHR657_FailedReadIsRecordedWithItsCode(t *testing.T) {
	c := investigatorCaller()
	req := &pb.SearchRequest{Query: &pb.Query{Entity: "agents", Filters: &pb.SearchFilters{Operation: "secret.operation"}}, PageSize: 5}
	s := &fakeStream{request: req}
	l := &auditLog{}
	fail := td.ErrPermissionDenied(td.PermAgentRead)
	if err := call(testGate(billing.Team, l), c, pantherclawv1connect.SearchServiceSearchProcedure, s, &pb.SearchRequest{}, fail); !errors.Is(err, fail) {
		t.Fatalf("err %v", err)
	}
	if len(l.events) != 1 {
		t.Fatalf("events %v", l.events)
	}
	ev := l.events[0]
	if ev.Outcome != audit.Denied || ev.ReasonCode != "PERMISSION_DENIED" || ev.Details["entity"] != "agents" || ev.Details["page_size"] != "5" {
		t.Errorf("event %+v", ev)
	}
	for _, v := range ev.Details {
		if v == "secret.operation" {
			t.Error("a filter reached the ledger")
		}
	}
}

// TestF946_EditionGatesTheRole: on Community the role's reads answer
// EDITION_REQUIRED and nothing is read; a caller whose other role admits the
// read is not gated by this edition, and is still audited.
// Covers: F946
func TestF946_EditionGatesTheRole(t *testing.T) {
	l := &auditLog{}
	g := testGate(billing.Community, l)
	for _, proc := range selfMCPReads {
		if ran, _, err := passesWith(g, investigatorCaller(), proc); ran || !errors.Is(err, errSelfMCPEdition) {
			t.Errorf("%s: ran=%v err=%v", proc, ran, err)
		}
	}
	g.editions = nil
	if ran, _, err := passesWith(g, investigatorCaller(), selfMCPReads[0]); ran || !errors.Is(err, errSelfMCPEdition) {
		t.Errorf("no editions: ran=%v err=%v", ran, err)
	}
	g = testGate(billing.Community, l)
	s := &fakeStream{request: &pb.GetRunTimelineRequest{RunId: ids.NewV7().String()}}
	if err := call(g, investigatorCaller(td.RoleAuditor), pantherclawv1connect.InvestigationServiceGetRunTimelineProcedure, s, &pb.GetRunTimelineRequest{}, nil); err != nil {
		t.Fatal(err)
	}
	if len(l.events) != 1 || len(s.sent) != 1 {
		t.Errorf("events %d, sent %d", len(l.events), len(s.sent))
	}
}

// TestHR657_OthersAreNotRecorded: a caller without the role reads as before,
// with no record from this gate.
// Covers: F948
func TestHR657_OthersAreNotRecorded(t *testing.T) {
	l := &auditLog{}
	c := investigatorCaller()
	c.Bindings = []td.Binding{{Role: td.RoleAuditor, Scope: c.Bindings[0].Scope}}
	s := &fakeStream{request: &pb.GetRunTimelineRequest{RunId: ids.NewV7().String()}}
	if err := call(testGate(billing.Team, l), c, pantherclawv1connect.InvestigationServiceGetRunTimelineProcedure, s, &pb.GetRunTimelineRequest{}, nil); err != nil {
		t.Fatal(err)
	}
	if len(l.events) != 0 || len(s.sent) != 1 {
		t.Errorf("events %v sent %d", l.events, len(s.sent))
	}
	if !slices.Contains(selfMCPReads, pantherclawv1connect.InvestigationServiceGetRunTimelineProcedure) {
		t.Fatal("list changed")
	}
}

func passesWith(g *selfMCPGate, c tapp.Caller, procedure string) (bool, tapp.Caller, error) {
	var got tapp.Caller
	ran := false
	err := g.intercept(func(ctx context.Context, _ connect.Spec, _ connect.ServerStream) error {
		ran = true
		got, _ = tapp.CallerFrom(ctx)
		return nil
	})(tapp.WithCaller(context.Background(), c), connect.Spec{Procedure: procedure}, &fakeStream{})
	return ran, got, err
}
