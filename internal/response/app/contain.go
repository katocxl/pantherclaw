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
	"strings"
	"time"
	"unicode/utf8"

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
	reflexports "github.com/katocxl/pantherclaw/internal/reflex/ports"
	"github.com/katocxl/pantherclaw/internal/response/adapters/pgresponse"
	rdomain "github.com/katocxl/pantherclaw/internal/response/domain"
)

// Errors of containment requests (D21–D23, D26).
var (
	ErrPreviewStale = pcerr.New(pcerr.FailedPrecondition, "PREVIEW_STALE",
		"this control is wider than one run or agent: preview it and confirm the preview's digest, which no longer matches")
	ErrScopeNotFound = pcerr.New(pcerr.NotFound, "SCOPE_NOT_FOUND", "the scope's subject was not found")
	// ErrIdempotencyBusy: another request under the same key held it past the
	// lock timeout; nothing was done, and the request may be retried (D72).
	ErrIdempotencyBusy = pcerr.New(pcerr.Unavailable, "IDEMPOTENCY_BUSY", "another request with this idempotency key is being processed; retry")
	ErrIdempotency     = pcerr.New(pcerr.AlreadyExists, "ALREADY_EXISTS", "the idempotency key was used for a different request")
	ErrActor           = pcerr.New(pcerr.InvalidArgument, "ACTOR_INVALID", "the actor must be a user, a service account, an automation or the identity playbook")
	ErrActionNotFound  = pcerr.New(pcerr.NotFound, "ACTION_NOT_FOUND", "response action not found")
)

// PlaybookActor is the actor of a control the identity playbook adds (D38):
// pre-authorized by its two-person enablement, so it needs no preview.
var PlaybookActor = reflexdomain.Subject{Type: reflexdomain.SubjectSystem, ID: reflexdomain.SystemIdentityPlaybook}

// Editions reports the licence's entitlements (Team and above preview the
// reach and stage restorations; Business and above accept SOAR requests).
// Nil is Community (fail closed).
type Editions interface {
	Current(ctx context.Context) (bdomain.Entitlements, error)
}

// Containment serves graduated containment (D21–D23): it adds controls the
// Authority enforces, records the response action and the paths it must
// reach, and previews wider controls. It implements reflexports.Container.
type Containment struct {
	Pool *db.Pool
	// Raiser raises the non-suppressible signal of failed containment
	// (HR-249); Failures records it as an owned failure. Either may be nil
	// in tests.
	Raiser   reflexports.Raiser
	Failures reflexports.FailureSink
	// Reach previews the reach before and after (exposure, D27); nil or a
	// Community licence omits it with a note.
	Reach    reflexdomain.ReachPreviewer
	Editions Editions
	Notify   Notifier
}

var _ reflexports.Container = (*Containment)(nil)

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
		reflexdomain.SubjectCase, reflexdomain.SubjectFinding, reflexdomain.SubjectSystem, reflexdomain.SubjectAutomation,
		reflexdomain.SubjectAutomationExecution:
	}
	return "", "", rdomain.ErrScope
}

// automationActor prefixes the actor of an automation's action.
const automationActor = "automation:"

// actorOf is how an action records its actor, and where it came from.
func actorOf(a reflexdomain.Subject) (string, string, evdomain.Actor, error) {
	switch {
	case a == PlaybookActor:
		return "system:identity_playbook", rdomain.SourcePlaybook, evdomain.Actor{Type: "system", ID: "identity_playbook"}, nil
	case a.Type == reflexdomain.SubjectUser:
		if _, err := ids.ParseUUID(a.ID); err == nil {
			return "user:" + a.ID, rdomain.SourcePerson, evdomain.Actor{Type: "user", ID: a.ID}, nil
		}
	case a.Type == reflexdomain.SubjectServiceAccount:
		if _, err := ids.ParseUUID(a.ID); err == nil {
			return "service_account:" + a.ID, rdomain.SourceSOAR, evdomain.Actor{Type: "service_account", ID: a.ID}, nil
		}
	case a.Type == reflexdomain.SubjectAutomation:
		// A governed automation's contain step (M11 D61, HR-284): a
		// playbook, never SOAR, recorded with the automation as actor.
		if _, err := ids.ParseUUID(a.ID); err == nil {
			return automationActor + a.ID, rdomain.SourcePlaybook, evdomain.Actor{Type: "automation", ID: a.ID}, nil
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

// Contain implements reflexports.Container: it adds one control in tx (the
// caller's tenant transaction, which it checks belongs to r.Org), with its
// response action and paths, and raises the containment epoch (HR-248). The
// source is the server's (D50): PERSON for a user actor, PLAYBOOK only for
// PlaybookActor; a SOAR request goes through RequestControl. A wider
// control needs the digest of its current preview (HR-252) unless it comes
// from the identity playbook, whose scope is limited to a person and the
// grants they issued. A repeat of the same idempotency key returns the
// first result; a different request under the key is refused.
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
	if source == rdomain.SourceSOAR {
		return reflexdomain.ContainResult{}, ErrSOARPort
	}
	c := rdomain.Control{ScopeType: scopeType, ScopeID: scopeID, Control: r.Control, Operation: r.Operation, Reason: r.Reason}
	c, err = c.Canonical()
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	return s.contain(ctx, tx, r.Org, c, containOpts{
		actor: actor, source: source, evActor: evActor, caseID: r.CaseID, incidentID: r.IncidentID,
		previewDigest: r.PreviewDigest, idempotency: r.Idempotency, execution: r.Execution,
	})
}

type containOpts struct {
	actor, source      string
	evActor            evdomain.Actor
	execution          *ids.UUID
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
		// Requests under one key wait for each other, so a repeat returns
		// the first result instead of hitting the unique index (D61).
		if err := q.LockIdempotency(ctx, org.String(), o.idempotency); db.IsLockTimeout(err) {
			return reflexdomain.ContainResult{}, ErrIdempotencyBusy
		} else if err != nil {
			return reflexdomain.ContainResult{}, err
		}
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
	if o.source == rdomain.SourcePlaybook {
		if err := playbookScope(ctx, q, org, c, strings.HasPrefix(o.actor, automationActor)); err != nil {
			return reflexdomain.ContainResult{}, err
		}
	}
	p, err := preview(ctx, tx, org, c)
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	// A digest, when given, must match; a wider control needs one unless an
	// emergency skip, the identity playbook or a SOAR request stands in. The
	// preview computed now is recorded either way (D50).
	preauthorized := o.skipReason != "" || o.source == rdomain.SourcePlaybook || o.source == rdomain.SourceSOAR
	if (len(o.previewDigest) > 0 && !bytes.Equal(o.previewDigest, p.Digest)) ||
		(len(o.previewDigest) == 0 && !c.Narrow() && !preauthorized) {
		return reflexdomain.ContainResult{}, ErrPreviewStale
	}
	a := pgresponse.Action{
		ID: ids.NewV7(), Kind: rdomain.KindContain, ScopeType: c.ScopeType, ScopeID: c.ScopeID, Control: c.Control,
		Operation: c.Operation, Reason: c.Reason, CaseID: o.caseID, IncidentID: o.incidentID, Actor: o.actor, Source: o.source,
		SkipReason: o.skipReason, SkipStepUpAt: o.skipStepUpAt, IdempotencyKey: o.idempotency, RequestDigest: reqDigest,
		Execution: o.execution,
	}
	a.PreviewDigest, a.PreviewSummary = p.Digest, summaryOf(p)
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

func sha(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func reasonOK1000(r string) bool {
	n := utf8.RuneCountInString(r)
	return utf8.ValidString(r) && n >= 1 && n <= rdomain.MaxReason
}

func auditRecord(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, name, objType, objID string, details map[string]string) (evdomain.Entry, error) {
	return audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: actor, Outcome: audit.Success, Object: &audit.Object{Type: objType, ID: objID}, Details: details,
	})
}

// Errors of the playbook and SOAR sources (D50).
var (
	ErrSOARPort = pcerr.New(pcerr.InvalidArgument, "SOAR_THROUGH_REQUEST_CONTROL",
		"a SOAR integration asks through RequestControl, which sets its source")
	ErrPlaybookScope = pcerr.New(pcerr.InvalidArgument, "PLAYBOOK_SCOPE",
		"the identity playbook contains only a person (DENY_ALL) and the grants that person issued")
)

// playbookScope limits the identity playbook (D50): a DENY_ALL on a user,
// or a control on a grant whose issuer the playbook already contains.
// An automation (M11 D61) may only DENY_ALL the triggering run.
func playbookScope(ctx context.Context, q *dbq.Queries, org ids.OrgID, c rdomain.Control, automation bool) error {
	if automation {
		// An automation suspends only the triggering run (HR-284); its
		// grants are revoked through the grants use case, not here.
		if c.ScopeType == rdomain.ScopeRun && c.Control == rdomain.DenyAll {
			return nil
		}
		return ErrPlaybookScope
	}
	switch c.ScopeType {
	case rdomain.ScopePrincipal:
		if kind, _, _ := cutPrincipal(c.ScopeID); kind == "user" && c.Control == rdomain.DenyAll {
			return nil
		}
	case rdomain.ScopeGrant:
		id, err := ids.ParseUUID(c.ScopeID)
		if err != nil {
			return rdomain.ErrScope
		}
		ok, err := q.PlaybookContainedIssuer(ctx, org, id)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
	}
	return ErrPlaybookScope
}

// summaryOf is the recorded summary of a preview (D50): counts and the
// first ids, never more than the column holds.
func summaryOf(p Preview) []byte {
	first := func(xs []ids.UUID, n int) []string { return idStrings(xs[:min(len(xs), n)]) }
	b, err := json.Marshal(map[string]any{
		"narrow": p.Narrow, "runs": len(p.Runs), "runs_over": p.RunsOver, "agents": first(p.Agents, 20), "agent_count": len(p.Agents),
		"waiting": p.Waiting, "gateways": len(p.Gateways), "alternatives": len(p.Alternatives), "unknown": len(p.Unknown),
	}, json.Deterministic(true))
	if err != nil {
		return nil
	}
	return b
}
