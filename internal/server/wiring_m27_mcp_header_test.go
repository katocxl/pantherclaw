// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"connectrpc.com/connect/v2"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/pclaw/selfmcp"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// adminCaller is a service account holding Org Admin, not the Investigator
// role.
func adminCaller() tapp.Caller {
	org := ids.New[ids.Org]()
	return tapp.Caller{Subject: td.Subject{
		Org: org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RoleOrgAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}},
	}}
}

// served runs procedure through a connect server whose only interceptor is
// g, as the API serves it, with the request header client ("" for none).
// The handler is h, or one that answers with the caller it saw.
func served(g *selfMCPGate, c tapp.Caller, procedure, client string, s *fakeStream, h connect.ServerFunc) (tapp.Caller, error) {
	var seen tapp.Caller
	if h == nil {
		h = func(ctx context.Context, _ connect.Spec, st connect.ServerStream) error {
			seen, _ = tapp.CallerFrom(ctx)
			return st.Send(&pb.GetRunTimelineResponse{State: "record"})
		}
	}
	srv := connect.NewServer(g.intercept)
	srv.Register(connect.Method{Spec: connect.Spec{Procedure: procedure}, Handler: h})
	info := &connect.CallInfo{}
	if client != "" {
		info.RequestHeader().Set("Pantherclaw-Client", client)
	}
	err := srv.Call(tapp.WithCaller(context.Background(), c), procedure, info, s)
	return seen, err
}

// TestHR663_AHeaderedReadIsRecordedForAnyKey: each of the five reads,
// called by an Org Admin key with the header of `pclaw mcp self`, is
// recorded with basis client_header before its answer, and decided as
// without the header: the same caller reaches the handler, and the edition
// gate of the role does not apply.
// Covers: F948
func TestHR663_AHeaderedReadIsRecordedForAnyKey(t *testing.T) {
	c := adminCaller()
	c.CredentialID = ids.NewV7()
	for _, proc := range selfMCPReads {
		s := &fakeStream{}
		l := &auditLog{stream: s}
		seen, err := served(testGate(billing.Community, l), c, proc, "mcp-self", s, nil)
		if err != nil || len(s.sent) != 1 {
			t.Fatalf("%s: %v, sent %d", proc, err, len(s.sent))
		}
		if !reflect.DeepEqual(seen, c) {
			t.Errorf("%s: the handler saw %+v, want the caller unchanged", proc, seen)
		}
		if len(l.events) != 1 || l.sentAt[0] != 0 {
			t.Fatalf("%s: events %+v recorded at %v", proc, l.events, l.sentAt)
		}
		ev := l.events[0]
		if ev.Name != selfMCPAuditName || ev.Outcome != audit.Success || ev.Details["basis"] != "client_header" ||
			ev.Details["procedure"] != proc || ev.Details["key_id"] != c.CredentialID.String() {
			t.Errorf("%s: event %+v", proc, ev)
		}
	}
	// A failed read is recorded with its code, and its refusal is the
	// handler's own.
	s := &fakeStream{request: &pb.GetRunTimelineRequest{RunId: ids.NewV7().String()}}
	l := &auditLog{}
	fail := td.ErrPermissionDenied(td.PermEvidenceRead)
	_, err := served(testGate(billing.Team, l), c, pantherclawv1connect.InvestigationServiceGetRunTimelineProcedure, "mcp-self", s,
		handler(&pb.GetRunTimelineRequest{}, fail))
	if !errors.Is(err, fail) || len(l.events) != 1 || l.events[0].Outcome != audit.Denied || l.events[0].Details["basis"] != "client_header" ||
		l.events[0].Object == nil || l.events[0].Object.Type != "run" {
		t.Errorf("a failed read: %v, events %+v", err, l.events)
	}
}

// TestHR663_NoRecordNoAnswer: under HR-657's rule, a headered read whose
// record cannot be written sends nothing.
// Covers: F948
func TestHR663_NoRecordNoAnswer(t *testing.T) {
	s := &fakeStream{}
	_, err := served(testGate(billing.Team, &auditLog{fail: true}), adminCaller(), selfMCPReads[0], "mcp-self", s, nil)
	if !errors.Is(err, errSelfMCPAudit) || len(s.sent) != 0 {
		t.Errorf("err %v, sent %d", err, len(s.sent))
	}
}

// TestHR663_TheHeaderDecidesNothing: without the header nothing is
// recorded; on any other procedure, or with another value, the header is
// ignored: nothing recorded, nothing refused, the caller unchanged.
// Covers: F948
func TestHR663_TheHeaderDecidesNothing(t *testing.T) {
	c := adminCaller()
	for _, tc := range []struct{ name, procedure, client string }{
		{"no header", selfMCPReads[2], ""},
		{"another value", selfMCPReads[2], "pclaw"},
		{"a write", pantherclawv1connect.SearchServiceSaveQueryProcedure, "mcp-self"},
		{"another read", pantherclawv1connect.InvestigationServiceGetPrecedingContextProcedure, "mcp-self"},
	} {
		s := &fakeStream{}
		l := &auditLog{}
		seen, err := served(testGate(billing.Community, l), c, tc.procedure, tc.client, s, nil)
		if err != nil || len(s.sent) != 1 || !reflect.DeepEqual(seen, c) {
			t.Errorf("%s: %v, sent %d, caller %+v", tc.name, err, len(s.sent), seen)
		}
		if len(l.events) != 0 {
			t.Errorf("%s: recorded %+v", tc.name, l.events)
		}
	}
	// A refusal stays the handler's, with or without the header.
	fail := td.ErrPermissionDenied(td.PermEvidenceRead)
	for _, client := range []string{"", "mcp-self"} {
		_, err := served(testGate(billing.Team, nil), c, pantherclawv1connect.SearchServiceSaveQueryProcedure, client,
			&fakeStream{request: &pb.SearchRequest{}}, handler(&pb.SearchRequest{}, fail))
		if !errors.Is(err, fail) {
			t.Errorf("header %q: %v", client, err)
		}
	}
}

// TestHR663_TheRoleKeepsItsRecords: the role's records say basis role, with
// or without the header, and its gate refusals stand as before.
// Covers: F948
func TestHR663_TheRoleKeepsItsRecords(t *testing.T) {
	for _, client := range []string{"", "mcp-self"} {
		s := &fakeStream{}
		l := &auditLog{stream: s}
		if _, err := served(testGate(billing.Team, l), investigatorCaller(), selfMCPReads[1], client, s, nil); err != nil || len(s.sent) != 1 {
			t.Fatalf("header %q: %v", client, err)
		}
		if len(l.events) != 1 || l.events[0].Details["basis"] != "role" {
			t.Errorf("header %q: events %+v", client, l.events)
		}
		l = &auditLog{}
		if _, err := served(testGate(billing.Community, l), investigatorCaller(), selfMCPReads[1], client, &fakeStream{}, nil); !errors.Is(err, errSelfMCPEdition) {
			t.Errorf("header %q on Community: %v", client, err)
		}
		if len(l.events) != 1 || l.events[0].Details["basis"] != "role" || l.events[0].ReasonCode != "EDITION_REQUIRED" {
			t.Errorf("header %q: refusal events %+v", client, l.events)
		}
	}
}

// TestHR663_ServerAndClientNameTheSameHeader ties the server's header to the
// one `pclaw mcp self` sends.
func TestHR663_ServerAndClientNameTheSameHeader(t *testing.T) {
	if selfMCPClientHeader != selfmcp.ClientHeader || selfMCPClientValue != selfmcp.ClientValue {
		t.Fatalf("server %s: %s, client %s: %s", selfMCPClientHeader, selfMCPClientValue, selfmcp.ClientHeader, selfmcp.ClientValue)
	}
}
