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
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
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
	case *pb.GetThreatTechniqueRequest:
		r := s.request.(*pb.GetThreatTechniqueRequest)
		m.Framework, m.TechniqueId, m.AgentId = r.GetFramework(), r.GetTechniqueId(), r.GetAgentId()
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

// TestF947_EditionGatesTheRole: on Community the role's reads answer
// EDITION_REQUIRED and nothing is read, whatever other role the caller holds
// at whatever scope: an org-wide Auditor binding beside it does not lift the
// gate. A caller without the role is not gated here.
// Covers: F947
func TestF947_EditionGatesTheRole(t *testing.T) {
	g := testGate(billing.Community, nil)
	for _, proc := range selfMCPReads {
		if ran, _, err := passesWith(g, investigatorCaller(), proc); ran || !errors.Is(err, errSelfMCPEdition) {
			t.Errorf("%s: ran=%v err=%v", proc, ran, err)
		}
		if ran, _, err := passesWith(g, investigatorCaller(td.RoleAuditor), proc); ran || !errors.Is(err, errSelfMCPEdition) {
			t.Errorf("%s with Auditor: ran=%v err=%v", proc, ran, err)
		}
	}
	g.editions = nil
	if ran, _, err := passesWith(g, investigatorCaller(), selfMCPReads[0]); ran || !errors.Is(err, errSelfMCPEdition) {
		t.Errorf("no editions: ran=%v err=%v", ran, err)
	}
	c := investigatorCaller()
	c.Bindings = []td.Binding{{Role: td.RoleAuditor, Scope: c.Bindings[0].Scope}}
	if ran, _, err := passesWith(testGate(billing.Community, nil), c, selfMCPReads[0]); !ran || err != nil {
		t.Errorf("without the role: ran=%v err=%v", ran, err)
	}
}

type failingEditions struct{}

func (failingEditions) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{}, errors.New("billing down")
}

// TestF947_EntitlementLookupFailure: when the edition cannot be read the read
// does not run and the caller gets ENTITLEMENT_UNAVAILABLE, not an audit code.
// Covers: F947
func TestF947_EntitlementLookupFailure(t *testing.T) {
	l := &auditLog{}
	g := testGate(billing.Team, l)
	g.editions = failingEditions{}
	ran, _, err := passesWith(g, investigatorCaller(), selfMCPReads[0])
	if ran || !errors.Is(err, errSelfMCPEntitlements) || pcerr.ReasonOf(err) != "ENTITLEMENT_UNAVAILABLE" {
		t.Errorf("ran=%v err=%v", ran, err)
	}
	if len(l.events) != 1 || l.events[0].Outcome != audit.Failure || l.events[0].ReasonCode != "ENTITLEMENT_UNAVAILABLE" {
		t.Errorf("events %+v", l.events)
	}
}

// TestHR657_GateRefusalsAreRecorded: every call of a holder of the role that
// the gate refuses is recorded with its code: a read refused for the
// edition, and a procedure outside the reads that only the role would admit.
// A lost record leaves the refusal as it is.
// Covers: F948
func TestHR657_GateRefusalsAreRecorded(t *testing.T) {
	l := &auditLog{}
	c := investigatorCaller()
	if _, _, err := passesWith(testGate(billing.Community, l), c, selfMCPReads[1]); !errors.Is(err, errSelfMCPEdition) {
		t.Fatalf("edition: %v", err)
	}
	if _, _, err := passesWith(testGate(billing.Team, l), c, pantherclawv1connect.SearchServiceSaveQueryProcedure); !errors.Is(err, errInvestigatorReads) {
		t.Fatalf("write: %v", err)
	}
	want := []struct{ procedure, reason string }{
		{selfMCPReads[1], "EDITION_REQUIRED"},
		{pantherclawv1connect.SearchServiceSaveQueryProcedure, "INVESTIGATOR_READS_ONLY"},
	}
	if len(l.events) != len(want) {
		t.Fatalf("events %+v", l.events)
	}
	for i, w := range want {
		ev := l.events[i]
		if ev.Name != selfMCPAuditName || ev.Outcome != audit.Denied || ev.ReasonCode != w.reason || ev.Details["procedure"] != w.procedure {
			t.Errorf("event %d: %+v", i, ev)
		}
	}
	g := testGate(billing.Community, &auditLog{fail: true})
	if _, _, err := passesWith(g, c, selfMCPReads[0]); !errors.Is(err, errSelfMCPEdition) {
		t.Errorf("lost record: %v", err)
	}
	g.record = nil
	if _, _, err := passesWith(g, c, selfMCPReads[0]); !errors.Is(err, errSelfMCPEdition) {
		t.Errorf("no recorder: %v", err)
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
