// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	bdomain "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/response/adapters/pgresponse"
	rdomain "github.com/katocxl/pantherclaw/internal/response/domain"
)

// Errors of containment requests (D21–D23, D26).
var (
	ErrPreviewStale = pcerr.New(pcerr.FailedPrecondition, "PREVIEW_STALE",
		"this control is wider than one run or agent: preview it and confirm the preview's digest, which no longer matches")
	ErrScopeNotFound  = pcerr.New(pcerr.NotFound, "SCOPE_NOT_FOUND", "the scope's subject was not found")
	ErrIdempotency    = pcerr.New(pcerr.AlreadyExists, "ALREADY_EXISTS", "the idempotency key was used for a different request")
	ErrActor          = pcerr.New(pcerr.InvalidArgument, "ACTOR_INVALID", "the actor must be a user, a service account or the identity playbook")
	ErrActionNotFound = pcerr.New(pcerr.NotFound, "ACTION_NOT_FOUND", "response action not found")
)

// PlaybookActor is the actor of a control the identity playbook adds (D38):
// pre-authorized by its two-person enablement, so it needs no preview.
var PlaybookActor = reflexdomain.Subject{Type: "system", ID: "identity_playbook"}

// Editions reports the licence's entitlements (Team and above preview the
// reach and stage restorations; Business and above accept SOAR requests).
// Nil is Community (fail closed).
type Editions interface {
	Current(ctx context.Context) (bdomain.Entitlements, error)
}

// Containment serves graduated containment (D21–D23): it adds controls the
// Authority enforces, records the response action and the paths it must
// reach, and previews wider controls. It implements reflexdomain.Container.
type Containment struct {
	Pool *db.Pool
	// Raiser raises the non-suppressible signal of failed containment
	// (HR-249); Failures records it as an owned failure. Either may be nil
	// in tests.
	Raiser   reflexdomain.Raiser
	Failures reflexdomain.FailureSink
	// Reach previews the reach before and after (exposure, D27); nil or a
	// Community licence omits it with a note.
	Reach    reflexdomain.ReachPreviewer
	Editions Editions
	Notify   Notifier
}

var _ reflexdomain.Container = (*Containment)(nil)

// scopeOf maps a request's subject to a control scope.
func scopeOf(s reflexdomain.Subject) (string, string, error) {
	switch s.Type {
	case reflexdomain.SubjectAgent:
		return rdomain.ScopeAgent, s.ID, nil
	case reflexdomain.SubjectRun:
		return rdomain.ScopeRun, s.ID, nil
	case reflexdomain.SubjectGrant:
		return rdomain.ScopeGrant, s.ID, nil
	case reflexdomain.SubjectConnection:
		return rdomain.ScopeConnection, s.ID, nil
	case reflexdomain.SubjectResource:
		return rdomain.ScopeResource, s.ID, nil
	case reflexdomain.SubjectUser, reflexdomain.SubjectServiceAccount:
		return rdomain.ScopePrincipal, string(s.Type) + ":" + s.ID, nil
	case reflexdomain.SubjectInstance, reflexdomain.SubjectTransaction, reflexdomain.SubjectCredential, reflexdomain.SubjectGateway,
		reflexdomain.SubjectPackage, reflexdomain.SubjectPolicyVersion, reflexdomain.SubjectAlert, reflexdomain.SubjectIncident,
		reflexdomain.SubjectCase, reflexdomain.SubjectFinding:
	}
	return "", "", rdomain.ErrScope
}

// actorOf is how an action records its actor, and where it came from.
func actorOf(a reflexdomain.Subject) (string, string, evdomain.Actor, error) {
	switch {
	case a == PlaybookActor:
		return "system:identity_playbook", rdomain.SourcePlaybook, evdomain.Actor{Type: "system", ID: "identity_playbook"}, nil
	case a.Type == reflexdomain.SubjectUser:
		if _, err := ids.ParseUUID(a.ID); err == nil {
			return "user:" + a.ID, rdomain.SourceUser, evdomain.Actor{Type: "user", ID: a.ID}, nil
		}
	case a.Type == reflexdomain.SubjectServiceAccount:
		if _, err := ids.ParseUUID(a.ID); err == nil {
			return "service_account:" + a.ID, rdomain.SourceSOAR, evdomain.Actor{Type: "service_account", ID: a.ID}, nil
		}
	}
	return "", "", evdomain.Actor{}, ErrActor
}

// requestDigest is the canonical request an idempotency key stands for.
func requestDigest(c rdomain.Control, caseID, incidentID *ids.UUID) []byte {
	b, _ := json.Marshal(struct {
		ScopeType, ScopeID, Control, Operation, Reason string
		Case, Incident                                 string
	}{c.ScopeType, c.ScopeID, c.Control, c.Operation, c.Reason, uuidString(caseID), uuidString(incidentID)}, json.Deterministic(true))
	sum := sha256.Sum256(b)
	return sum[:]
}

func uuidString(u *ids.UUID) string {
	if u == nil {
		return ""
	}
	return u.String()
}

// Contain implements reflexdomain.Container: it adds one control in tx (the
// caller's tenant transaction, which it checks belongs to r.Org), with its
// response action and paths, and raises the containment epoch (HR-248). A
// wider control needs the digest of its current preview (HR-252), except
// when it comes from the identity playbook or a SOAR service account (whose
// scopes RequestControl already narrowed, HR-251). A repeat of the same
// idempotency key returns the first result; a different request under the
// key is refused.
func (s *Containment) Contain(ctx context.Context, ptx pgx.Tx, r reflexdomain.ContainRequest) (reflexdomain.ContainResult, error) {
	tx, err := db.AdoptTenantTx(ctx, ptx, r.Org)
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	scopeType, scopeID, err := scopeOf(r.Scope)
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	actor, source, evActor, err := actorOf(r.Actor)
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	c := rdomain.Control{ScopeType: scopeType, ScopeID: scopeID, Control: r.Control, Operation: r.Operation, Reason: r.Reason}
	if err := c.Validate(); err != nil {
		return reflexdomain.ContainResult{}, err
	}
	return s.contain(ctx, tx, r.Org, c, containOpts{
		actor: actor, source: source, evActor: evActor, caseID: r.CaseID, incidentID: r.IncidentID,
		previewDigest: r.PreviewDigest, idempotency: r.Idempotency,
	})
}

type containOpts struct {
	actor, source      string
	evActor            evdomain.Actor
	caseID, incidentID *ids.UUID
	previewDigest      []byte
	skipReason         string
	skipStepUpAt       *time.Time
	idempotency        string
	expires            *time.Time
}

func (s *Containment) contain(ctx context.Context, tx db.TenantTx, org ids.OrgID, c rdomain.Control, o containOpts) (reflexdomain.ContainResult, error) {
	q := dbq.New(tx)
	var reqDigest []byte
	if o.idempotency != "" {
		reqDigest = requestDigest(c, o.caseID, o.incidentID)
		prev, err := q.ResponseActionByKey(ctx, org, &o.idempotency)
		switch {
		case err == nil:
			if !bytes.Equal(prev.RequestDigest, reqDigest) {
				return reflexdomain.ContainResult{}, ErrIdempotency
			}
			return reflexdomain.ContainResult{ActionID: prev.ID, Status: prev.Status}, nil
		case !db.IsNoRows(err):
			return reflexdomain.ContainResult{}, err
		}
	}
	if err := exists(ctx, q, org, c); err != nil {
		return reflexdomain.ContainResult{}, err
	}
	p, err := preview(ctx, tx, org, c)
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	// A digest, when given, must match; a wider control needs one unless an
	// emergency skip, the identity playbook or a SOAR request stands in.
	preauthorized := o.skipReason != "" || o.source == rdomain.SourcePlaybook || o.source == rdomain.SourceSOAR
	if (len(o.previewDigest) > 0 && !bytes.Equal(o.previewDigest, p.Digest)) ||
		(len(o.previewDigest) == 0 && !c.Narrow() && !preauthorized) {
		return reflexdomain.ContainResult{}, ErrPreviewStale
	}
	a := pgresponse.Action{
		ID: ids.NewV7(), Kind: rdomain.KindContain, ScopeType: c.ScopeType, ScopeID: c.ScopeID, Control: c.Control,
		Operation: c.Operation, Reason: c.Reason, CaseID: o.caseID, IncidentID: o.incidentID, Actor: o.actor, Source: o.source,
		SkipReason: o.skipReason, SkipStepUpAt: o.skipStepUpAt, IdempotencyKey: o.idempotency, RequestDigest: reqDigest,
	}
	if len(o.previewDigest) > 0 {
		a.PreviewDigest = p.Digest
	}
	added, err := pgresponse.AddControl(ctx, tx, org, a, o.expires)
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	if err := planPaths(ctx, tx, a.ID, rdomain.KindContain, p, added.Epoch); err != nil {
		return reflexdomain.ContainResult{}, err
	}
	status, err := s.settle(ctx, tx, org, a.ID)
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	details := map[string]string{
		"action": a.ID.String(), "control_id": added.ControlID.String(), "scope_type": c.ScopeType, "scope": c.ScopeID,
		"control": c.Control, "epoch": strconv.FormatInt(added.Epoch, 10), "source": o.source,
	}
	if c.Operation != "" {
		details["operation"] = c.Operation
	}
	if o.skipReason != "" {
		details["preview_skipped"] = "true"
	}
	if err := recordAction(ctx, tx, o.evActor, "response.contain", a.ID, details, c.Reason); err != nil {
		return reflexdomain.ContainResult{}, err
	}
	return reflexdomain.ContainResult{ActionID: a.ID, Status: string(status)}, nil
}

// exists checks that the scope's subject is the org's.
func exists(ctx context.Context, q *dbq.Queries, org ids.OrgID, c rdomain.Control) error {
	kind, id := c.ScopeType, c.ScopeID
	switch c.ScopeType {
	case rdomain.ScopeResource:
		return nil
	case rdomain.ScopePrincipal:
		var cut bool
		kind, id, cut = cutPrincipal(c.ScopeID)
		if !cut {
			return rdomain.ErrPrincipal
		}
	}
	u, err := ids.ParseUUID(id)
	if err != nil {
		return rdomain.ErrScope
	}
	found, err := q.ScopeExists(ctx, kind, org.UUID(), u)
	if err != nil {
		return err
	}
	if !found {
		return ErrScopeNotFound
	}
	return nil
}

func cutPrincipal(s string) (string, string, bool) {
	for i := range s {
		if s[i] == ':' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

// recordAction writes the response.action ledger entry (D6: ids and
// subjects only) and the audit event, in the change's transaction.
func recordAction(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, name string, action ids.UUID, details map[string]string, reason string) error {
	body, err := evdomain.CanonicalBody(details)
	if err != nil {
		return err
	}
	if len(body) > reflexdomain.MaxLedgerBody {
		return errors.New("response: action ledger body too large")
	}
	if _, err := ledger.Append(ctx, tx, reflexdomain.KindResponseAction, actor, body); err != nil {
		return err
	}
	_, err = audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: actor, Outcome: audit.Success, Object: &audit.Object{Type: "response_action", ID: action.String()},
		Details: withReason(details, reason),
	})
	return err
}
