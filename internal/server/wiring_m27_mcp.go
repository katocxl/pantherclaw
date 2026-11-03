// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"log/slog"
	"slices"
	"strconv"
	"strings"

	"connectrpc.com/connect/v2"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// Refusals of the gate.
var (
	// errInvestigatorReads refuses the Investigator role outside its reads.
	errInvestigatorReads = pcerr.New(pcerr.PermissionDenied, "INVESTIGATOR_READS_ONLY",
		"the Investigator role reads what happened, run timelines, search and breach radius, and nothing else")
	// errSelfMCPEdition: the org's plan has no SelfMCP.
	errSelfMCPEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED",
		"reading through PantherClaw's own MCP server needs the Team edition or above")
	// errSelfMCPAudit: the read's audit record could not be written, so
	// the read is not answered (HR-657).
	errSelfMCPAudit = pcerr.New(pcerr.Unavailable, "AUDIT_UNAVAILABLE", "the read could not be audited; try again")
	// errSelfMCPEntitlements: the org's entitlements could not be read, so
	// the edition is unknown and the read is not answered.
	errSelfMCPEntitlements = pcerr.New(pcerr.Unavailable, "ENTITLEMENT_UNAVAILABLE",
		"the organization's edition could not be checked; try again")
)

// selfMCPAuditName is the event of one read by the role: kind
// audit.self_mcp.read.
const selfMCPAuditName = "self_mcp.read"

// The header `pclaw mcp self` sends on every call (selfmcp.ClientHeader,
// selfmcp.ClientValue; HR-663). It is the client's claim: it only adds a
// record, and never grants, refuses or changes a decision.
const (
	selfMCPClientHeader = "Pantherclaw-Client"
	selfMCPClientValue  = "mcp-self"
)

// Why a read is recorded, the record's basis detail (HR-663): the caller
// holds the Investigator role, or a caller without it sent the client
// header.
const (
	selfMCPBasisRole   = "role"
	selfMCPBasisHeader = "client_header"
)

// selfMCPEditions reports the org's entitlements (billing.Service).
type selfMCPEditions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// selfMCPRecorder writes one audit event in the caller's org.
type selfMCPRecorder func(ctx context.Context, org ids.OrgID, ev audit.Event) error

// selfMCPInterceptors hold the Investigator role to selfMCPReads on the
// server, gate them on the edition and audit each one, so a key taken from a
// SOC agent's host writes nothing and reads nothing unrecorded, whatever
// client it uses (G0 M27 D510, HR-655, HR-657).
func selfMCPInterceptors(d apiDeps) []connect.ServerInterceptor {
	g := &selfMCPGate{log: d.log}
	if d.billing != nil {
		g.editions = d.billing
	}
	if d.pool != nil {
		g.record = poolRecorder(d.pool)
	}
	return []connect.ServerInterceptor{g.intercept}
}

func poolRecorder(pool *db.Pool) selfMCPRecorder {
	return func(ctx context.Context, org ids.OrgID, ev audit.Event) error {
		return pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := audit.Record(ctx, tx, ev)
			return err
		})
	}
}

// selfMCPGate runs after authentication and validation, with the caller in
// the context. Outside selfMCPReads the role does not count: the call goes on
// with the caller's other bindings, or is refused when those do not admit
// it. On the reads, a holder of the role needs the edition, whatever else it
// holds, and is audited. Every refusal the gate makes to a holder is audited
// too. A nil editions or record fails closed. A caller without the role is
// audited on the reads only when it sends the client header of
// `pclaw mcp self`, and is otherwise left as it is (HR-663).
type selfMCPGate struct {
	editions selfMCPEditions
	record   selfMCPRecorder
	log      *slog.Logger
}

func (g *selfMCPGate) intercept(next connect.ServerFunc) connect.ServerFunc {
	return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
		c, err := tapp.CallerFrom(ctx)
		if err != nil {
			return next(ctx, spec, stream) // public, workload and gateway calls carry no caller here
		}
		if !tapp.IsInvestigator(c) {
			if slices.Contains(selfMCPReads, spec.Procedure) && fromSelfMCP(ctx) {
				// Recorded as the role's reads are, and decided as without
				// the header: no edition gate, the same caller (HR-663).
				return g.audited(ctx, c, spec, stream, next, selfMCPBasisHeader)
			}
			return next(ctx, spec, stream)
		}
		rest := tapp.WithoutInvestigator(c)
		if !slices.Contains(selfMCPReads, spec.Procedure) {
			if !procedureAdmits(rest, spec.Procedure) {
				return g.refuse(ctx, c, spec.Procedure, errInvestigatorReads)
			}
			return next(tapp.WithCaller(ctx, rest), spec, stream)
		}
		if err := g.edition(ctx); err != nil {
			return g.refuse(ctx, c, spec.Procedure, err)
		}
		return g.audited(ctx, c, spec, stream, next, selfMCPBasisRole)
	}
}

// fromSelfMCP reports whether the call carries the client header of
// `pclaw mcp self` (HR-663).
func fromSelfMCP(ctx context.Context) bool {
	info, ok := connect.CallInfoForServerContext(ctx)
	return ok && info.RequestHeader().Get(selfMCPClientHeader) == selfMCPClientValue
}

// refuse records the gate's refusal of a holder of the role (HR-657) and
// returns it. The call is refused either way; a lost record is logged.
func (g *selfMCPGate) refuse(ctx context.Context, c tapp.Caller, procedure string, refusal error) error {
	if g.record == nil {
		g.logger().ErrorContext(ctx, "self_mcp.audit_failed", slog.String("procedure", procedure))
		return refusal
	}
	outcome := audit.Denied
	if pcerr.CodeOf(refusal) == pcerr.Unavailable {
		outcome = audit.Failure
	}
	ev := selfMCPEvent(c, procedure, nil, outcome, selfMCPBasisRole)
	ev.ReasonCode = pcerr.ReasonOf(refusal)
	if err := g.record(context.WithoutCancel(ctx), c.Org, ev); err != nil {
		g.logger().ErrorContext(ctx, "self_mcp.audit_failed", slog.String("procedure", procedure), pclog.Err(err))
	}
	return refusal
}

func (g *selfMCPGate) edition(ctx context.Context) error {
	if g.editions == nil {
		return errSelfMCPEdition
	}
	e, err := g.editions.Current(ctx)
	if err != nil {
		return errSelfMCPEntitlements
	}
	if !e.SelfMCP() {
		return errSelfMCPEdition
	}
	return nil
}

// audited runs the read and records it, with basis, before its answer
// leaves: the record is written when the handler sends, and a failure to
// write it fails the call with nothing sent. A read that fails is recorded
// with its code.
func (g *selfMCPGate) audited(ctx context.Context, c tapp.Caller, spec connect.Spec, stream connect.ServerStream,
	next connect.ServerFunc, basis string,
) error {
	if g.record == nil {
		return errSelfMCPAudit
	}
	s := &auditedStream{ServerStream: stream, ctx: ctx, g: g, c: c, procedure: spec.Procedure, basis: basis}
	err := next(ctx, spec, s)
	if err != nil && !s.recorded {
		reason := pcerr.ReasonOf(err)
		outcome := audit.Failure
		if connect.CodeOf(err) == connect.CodePermissionDenied || pcerr.CodeOf(err) == pcerr.PermissionDenied {
			outcome = audit.Denied
		}
		// The call fails either way; a lost failure record is logged.
		if rerr := s.write(context.WithoutCancel(ctx), outcome, reason); rerr != nil {
			g.logger().ErrorContext(ctx, "self_mcp.audit_failed", slog.String("procedure", spec.Procedure), pclog.Err(rerr))
		}
	}
	return err
}

func (g *selfMCPGate) logger() *slog.Logger {
	if g.log == nil {
		return pclog.Discard()
	}
	return g.log
}

// auditedStream keeps the request and writes the record on the first send.
type auditedStream struct {
	connect.ServerStream
	ctx       context.Context //nolint:containedctx // the call's own context, for the record the send writes
	g         *selfMCPGate
	c         tapp.Caller
	procedure string
	basis     string
	request   any
	recorded  bool
}

func (s *auditedStream) Receive(msg any) error {
	if err := s.ServerStream.Receive(msg); err != nil {
		return err
	}
	if s.request == nil {
		s.request = msg
	}
	return nil
}

func (s *auditedStream) Send(msg any) error {
	if !s.recorded {
		if err := s.write(s.ctx, audit.Success, ""); err != nil {
			s.g.logger().ErrorContext(s.ctx, "self_mcp.audit_failed", slog.String("procedure", s.procedure), pclog.Err(err))
			return errSelfMCPAudit
		}
	}
	return s.ServerStream.Send(msg)
}

func (s *auditedStream) write(ctx context.Context, outcome audit.Outcome, reason string) error {
	s.recorded = true
	ev := selfMCPEvent(s.c, s.procedure, s.request, outcome, s.basis)
	if reason != "" && reasonShape(reason) {
		ev.ReasonCode = reason
	}
	return s.g.record(ctx, s.c.Org, ev)
}

func reasonShape(r string) bool {
	if len(r) > 64 || r == "" || r[0] < 'A' || r[0] > 'Z' {
		return false
	}
	return strings.Trim(r, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") == ""
}

// selfMCPEvent names the read, why it is recorded (basis, HR-663) and what
// it asked for: an id, a scope or an entity, never filter text or results
// (HR-657).
func selfMCPEvent(c tapp.Caller, procedure string, request any, outcome audit.Outcome, basis string) audit.Event {
	ev := audit.Event{
		Name: selfMCPAuditName, Actor: c.Actor(), Outcome: outcome,
		Details: map[string]string{"procedure": procedure, "basis": basis},
	}
	if !c.CredentialID.IsZero() {
		ev.Details["key_id"] = c.CredentialID.String()
	}
	object := func(typ, id string) {
		if _, err := ids.ParseUUID(id); err == nil {
			ev.Object = &audit.Object{Type: typ, ID: id}
		}
	}
	switch r := request.(type) {
	case *pb.WhatHappenedRequest:
		object("transaction", r.GetTransactionId())
	case *pb.GetRunTimelineRequest:
		object("run", r.GetRunId())
	case *pb.GetGraphRequest:
		object(r.GetScope().GetType(), r.GetScope().GetId())
		ev.Details["mode"] = strings.ToLower(strings.TrimPrefix(r.GetMode().String(), "GRAPH_MODE_"))
	case *pb.SearchRequest:
		ev.Details["entity"] = r.GetQuery().GetEntity()
		ev.Details["page_size"] = strconv.Itoa(int(r.GetPageSize()))
	}
	return ev
}
