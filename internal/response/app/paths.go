// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"strconv"
	"time"

	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/response/adapters/pgresponse"
	rdomain "github.com/katocxl/pantherclaw/internal/response/domain"
)

// GatewayDeadline is how long a gateway path may wait for its gateway to
// be sent the action's epoch before the path fails (D22): a gateway whose
// stream is quiet refuses to dispatch (HR-010), but containment on it is
// then not confirmed, and failed containment is raised (HR-249).
const GatewayDeadline = 5 * time.Minute

// Path controls: how a path is enforced or why it is open.
const (
	pathEpoch      = "epoch"
	pathAgentHeld  = "agent_held"
	pathDispatched = "dispatched"
	// coverageNone marks an agent with no coverage record.
	coverageNone = "UNKNOWN"
)

// planPaths records the paths an action must reach (D22): every gateway
// serving the scope (confirmed once sent the action's epoch); every
// coverage route of the affected agents (ENFORCED and PARTIAL through
// their gateway, OBSERVE_ONLY and UNKNOWN bypass routes open until a
// credential change closes them, and one UNKNOWN route for an agent with
// no coverage record); every agent-held credential they reach; and the
// dispatched work still in flight, material for a termination and listed
// as historical exposure for a containment (F561).
func planPaths(ctx context.Context, tx db.TenantTx, action ids.UUID, kind string, p Preview, epoch int64) error {
	org := tx.OrgID()
	q := dbq.New(tx)
	add := func(typ, subjectType, subjectID string, material bool, control string, status rdomain.PathStatus, evidence map[string]string, cancel *string) error {
		ev, err := json.Marshal(evidence, json.Deterministic(true))
		if err != nil {
			return err
		}
		return q.InsertResponsePath(ctx, dbq.InsertResponsePathParams{
			OrgID: org, ActionID: action, ID: ids.NewV7(), PathType: typ, SubjectType: subjectType, SubjectID: subjectID,
			Material: material, Control: control, Status: string(status), Evidence: ev, CancelCapability: cancel,
		})
	}
	need := map[string]string{"epoch": strconv.FormatInt(epoch, 10)}
	for _, g := range p.Gateways {
		if err := add(rdomain.PathGateway, "gateway", g.String(), true, pathEpoch, rdomain.PathPending, need, nil); err != nil {
			return err
		}
	}
	if len(p.Agents) > 0 {
		cov, err := q.AgentCoverage(ctx, org, p.Agents)
		if err != nil {
			return err
		}
		covered := map[ids.UUID]bool{}
		for _, r := range cov {
			covered[r.AgentID] = true
			ev := map[string]string{"gateway": r.GatewayID.String(), "connection": r.ConnectionID.String()}
			status := rdomain.PathPending
			if bypass(r.State) {
				status, ev["bypass"] = rdomain.PathUnresolved, "true"
			}
			if err := add(rdomain.PathRoute, "connection", routeID(r.AgentID, r.ConnectionID, r.Operation), true, r.State, status, ev, nil); err != nil {
				return err
			}
		}
		for _, a := range p.Agents {
			if !covered[a] {
				if err := add(rdomain.PathRoute, "agent", a.String(), true, coverageNone, rdomain.PathUnresolved,
					map[string]string{"bypass": "true", "note": "no coverage record"}, nil); err != nil {
					return err
				}
			}
		}
		held, err := q.AgentHeldConnections(ctx, org, p.Agents)
		if err != nil {
			return err
		}
		for _, c := range held {
			if err := add(rdomain.PathCredential, "connection", c.ID.String(), true, pathAgentHeld, rdomain.PathUnresolved,
				map[string]string{"connection": c.ID.String()}, nil); err != nil {
				return err
			}
		}
	}
	if len(p.Runs) > 0 {
		inflight, err := q.InFlightTransactions(ctx, org, p.Runs)
		if err != nil {
			return err
		}
		unknown := "UNKNOWN"
		for _, t := range inflight {
			if err := add(rdomain.PathInFlight, "transaction", t.ID.String(), kind == rdomain.KindTerminate, pathDispatched, rdomain.PathPending,
				map[string]string{"run": t.RunID.String(), "permit": t.State}, &unknown); err != nil {
				return err
			}
		}
	}
	return nil
}

// Advance looks for confirmation evidence of an unsettled action's open
// paths and moves the action to the status its material paths give
// (HR-249). It reports whether the status changed.
func (s *Containment) Advance(ctx context.Context, tx db.TenantTx, a dbq.PcResponseAction) (bool, error) {
	if err := confirm(ctx, tx, a); err != nil {
		return false, err
	}
	before := a.Status
	status, err := s.settle(ctx, tx, tx.OrgID(), a.ID)
	return err == nil && string(status) != before, err
}

// confirm records the evidence each open path now has.
func confirm(ctx context.Context, tx db.TenantTx, a dbq.PcResponseAction) error {
	org := tx.OrgID()
	q := dbq.New(tx)
	now, err := q.DBNow(ctx)
	if err != nil {
		return err
	}
	paths, err := q.ListResponsePaths(ctx, org, a.ID)
	if err != nil {
		return err
	}
	epoch := a.Epoch.Int64
	update := func(p dbq.PcResponsePath, status rdomain.PathStatus, evidence map[string]string, failure string) error {
		var prev map[string]string
		_ = json.Unmarshal(p.Evidence, &prev)
		if prev == nil {
			prev = map[string]string{}
		}
		for k, v := range evidence {
			prev[k] = v
		}
		ev, err := json.Marshal(prev, json.Deterministic(true))
		if err != nil {
			return err
		}
		var f *string
		if failure != "" {
			f = &failure
		}
		_, err = q.UpdateResponsePath(ctx, dbq.UpdateResponsePathParams{
			OrgID: org, ActionID: a.ID, ID: p.ID, Expected: p.Status, Status: string(status), Evidence: ev, Failure: f,
		})
		return err
	}
	delivered := func(gw string) (map[string]string, bool, error) {
		id, ok := parseUUID(gw)
		if !ok {
			return nil, false, nil // a path without a gateway id never confirms
		}
		if st, err := q.GatewayStateOf(ctx, org, id); err == nil && st == "REVOKED" {
			return map[string]string{"gateway_state": "REVOKED"}, true, nil
		} else if err != nil && !db.IsNoRows(err) {
			return nil, false, err
		}
		d, err := q.GatewayEpochDelivery(ctx, org, id)
		switch {
		case db.IsNoRows(err):
			return nil, false, nil
		case err != nil:
			return nil, false, err
		case d.Epoch < epoch:
			return nil, false, nil
		}
		return map[string]string{"delivered_epoch": strconv.FormatInt(d.Epoch, 10), "delivered_at": d.DeliveredAt.UTC().Format(time.RFC3339)}, true, nil
	}
	for _, p := range paths {
		if p.Status != string(rdomain.PathPending) && p.Status != string(rdomain.PathUnresolved) {
			continue
		}
		var ev map[string]string
		_ = json.Unmarshal(p.Evidence, &ev)
		switch p.PathType {
		case rdomain.PathGateway:
			got, ok, err := delivered(p.SubjectID)
			if err != nil {
				return err
			}
			switch {
			case ok:
				err = update(p, rdomain.PathConfirmed, got, "")
			case now.Sub(a.RequestedAt) > GatewayDeadline:
				err = update(p, rdomain.PathFailed, nil, "the gateway was not sent containment epoch "+strconv.FormatInt(epoch, 10)+" within 5 minutes")
			}
			if err != nil {
				return err
			}
		case rdomain.PathRoute:
			if ev["bypass"] == "true" {
				// A bypass route closes only when the credential it uses
				// changed after the action (D22, D25).
				if conn := ev["connection"]; conn != "" {
					if ok, at, err := credentialChangedSince(ctx, q, org, conn, a.RequestedAt); err != nil {
						return err
					} else if ok {
						if err := update(p, rdomain.PathConfirmed, map[string]string{"credential_changed_at": at}, ""); err != nil {
							return err
						}
					}
				}
				continue
			}
			got, ok, err := delivered(ev["gateway"])
			if err != nil {
				return err
			}
			if ok {
				if err := update(p, rdomain.PathConfirmed, got, ""); err != nil {
					return err
				}
			}
		case rdomain.PathCredential:
			if gw := ev["gateway"]; gw != "" {
				// A rotated GitHub App credential: the gateway mints fresh
				// tokens once sent the new epoch.
				got, ok, err := delivered(gw)
				if err != nil {
					return err
				}
				if ok {
					if err := update(p, rdomain.PathConfirmed, got, ""); err != nil {
						return err
					}
				}
				continue
			}
			if ok, at, err := credentialChangedSince(ctx, q, org, p.SubjectID, a.RequestedAt); err != nil {
				return err
			} else if ok {
				if err := update(p, rdomain.PathConfirmed, map[string]string{"credential_changed_at": at}, ""); err != nil {
					return err
				}
			}
		case rdomain.PathInFlight:
			id, err := ids.ParseUUID(p.SubjectID)
			if err != nil {
				continue
			}
			st, err := q.PermitState(ctx, org, id)
			if err != nil && !db.IsNoRows(err) {
				return err
			}
			if st == "DISPATCHED" || st == "RELEASED" {
				if err := update(p, rdomain.PathConfirmed, map[string]string{"permit": st}, ""); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// historicalItem is one entry of an action's historical exposure (F561):
// work already dispatched before the control, which stopping new access
// does not undo.
type historicalItem struct {
	Transaction string `json:"transaction"`
	Permit      string `json:"permit"`
}

// settle moves the action to the status its paths give, records whether
// new access is stopped and the historical exposure, and on a change tells
// the org: PARTIAL notifies, FAILED raises a non-suppressible signal and an
// owned failure (HR-249).
func (s *Containment) settle(ctx context.Context, tx db.TenantTx, org ids.OrgID, action ids.UUID) (rdomain.Status, error) {
	q := dbq.New(tx)
	a, err := q.GetResponseAction(ctx, org, action)
	if err != nil {
		return "", err
	}
	rows, err := q.ListResponsePaths(ctx, org, action)
	if err != nil {
		return "", err
	}
	var paths []rdomain.Path
	historical := []historicalItem{}
	future, gateways := true, 0
	for _, r := range rows {
		paths = append(paths, rdomain.Path{
			ID: r.ID, Type: r.PathType, SubjectType: r.SubjectType, SubjectID: r.SubjectID, Material: r.Material,
			Control: r.Control, Status: rdomain.PathStatus(r.Status),
		})
		switch r.PathType {
		case rdomain.PathGateway:
			gateways++
			future = future && r.Status == string(rdomain.PathConfirmed)
		case rdomain.PathInFlight:
			var ev map[string]string
			_ = json.Unmarshal(r.Evidence, &ev)
			historical = append(historical, historicalItem{Transaction: r.SubjectID, Permit: ev["permit"]})
		}
	}
	cur := rdomain.Status(a.Status)
	next := rdomain.StatusOf(paths)
	if next == rdomain.StatusRequested {
		next = cur
	}
	futureConfirmed := gateways > 0 && future
	hist, err := json.Marshal(historical, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	if next == cur && futureConfirmed == a.FutureConfirmed && string(hist) == string(a.HistoricalOpen) {
		return cur, nil
	}
	if err := pgresponse.Settle(ctx, tx, org, action, cur, next, futureConfirmed, hist); err != nil {
		return "", err
	}
	if next == cur {
		return next, nil
	}
	if err := s.told(ctx, tx, a, next); err != nil {
		return "", err
	}
	return next, nil
}

// told records a status change: a response.path ledger entry, and a
// notification for PARTIAL, or the signal and owned failure for FAILED.
func (s *Containment) told(ctx context.Context, tx db.TenantTx, a dbq.PcResponseAction, status rdomain.Status) error {
	org := tx.OrgID()
	body := map[string]string{"action": a.ID.String(), "status": string(status), "scope_type": a.ScopeType, "scope": a.ScopeID}
	if err := appendLedger(ctx, tx, reflexdomain.KindResponsePath, body); err != nil {
		return err
	}
	subject := subjectOfScope(a.ScopeType, a.ScopeID)
	switch status {
	case rdomain.StatusPartial:
		return s.notifyType(ctx, tx, org, reflexdomain.NotifyContainmentPartial, a.ID, status)
	case rdomain.StatusFailed:
		now, err := dbq.New(tx).DBNow(ctx)
		if err != nil {
			return err
		}
		if s.Raiser != nil {
			if _, err := s.Raiser.Raise(ctx, tx.Pgx(), reflexdomain.Signal{
				Org: org, Source: reflexdomain.SourceResponse, Title: "Containment failed",
				Summary:  "Response action " + a.ID.String() + " could not be confirmed on every path; new access may still be possible.",
				Severity: reflexdomain.SeverityHigh, Attention: reflexdomain.AttentionAlert, Basis: reflexdomain.BasisObserved,
				Subjects: subject, GroupKey: a.ScopeType + ":" + a.ScopeID, DedupeKey: "response.failed:" + a.ID.String(),
				OccurredAt: now, Facts: map[string]string{"action": a.ID.String(), "status": string(status)},
			}); err != nil {
				return err
			}
		}
		if s.Failures != nil {
			if _, err := s.Failures.Report(ctx, tx.Pgx(), reflexdomain.Failure{
				Org: org, Kind: "containment_failed", Summary: "Containment action " + a.ID.String() + " failed on at least one path.",
				NextStep: "Open the action's paths, fix or revoke the gateway or credential that did not confirm, then contain again.",
				Scope:    subject, Deadline: now.Add(time.Hour), DedupeKey: "response.failed:" + a.ID.String(),
			}); err != nil {
				return err
			}
		}
		return s.notifyType(ctx, tx, org, reflexdomain.NotifyContainmentFailed, a.ID, status)
	case rdomain.StatusRequested, rdomain.StatusConfirmed, rdomain.StatusUnsupported:
	}
	return nil
}

func (s *Containment) notifyType(ctx context.Context, tx db.TenantTx, org ids.OrgID, typ string, action ids.UUID, status rdomain.Status) error {
	if s.Notify == nil {
		return nil
	}
	_, err := s.Notify.Enqueue(ctx, tx, napp.Message{Org: org, Type: typ, Params: map[string]string{"action": action.String(), "status": string(status)}})
	return err
}

// subjectOfScope is the reflex subject of a control scope.
func subjectOfScope(scopeType, scopeID string) []reflexdomain.Subject {
	switch scopeType {
	case rdomain.ScopePrincipal:
		k, id, _ := cutPrincipal(scopeID)
		return []reflexdomain.Subject{{Type: reflexdomain.SubjectType(k), ID: id}}
	case "credential", "transaction":
		return []reflexdomain.Subject{{Type: reflexdomain.SubjectType(scopeType), ID: scopeID}}
	}
	return []reflexdomain.Subject{{Type: reflexdomain.SubjectType(scopeType), ID: scopeID}}
}

func appendLedger(ctx context.Context, tx db.TenantTx, kind string, body map[string]string) error {
	b, err := evdomain.CanonicalBody(body)
	if err != nil {
		return err
	}
	_, err = ledger.Append(ctx, tx, kind, sweeperActor, b)
	return err
}

// sweeperActor records the status changes the confirmation sweep finds.
var sweeperActor = evdomain.Actor{Type: string(reflexdomain.SubjectSystem), ID: reflexdomain.SystemSweeper}

// credentialChangedSince reports whether the sealed credential of a
// connection was revoked or superseded after since (D25), and when.
func credentialChangedSince(ctx context.Context, q *dbq.Queries, org ids.OrgID, connection string, since time.Time) (bool, string, error) {
	id, ok := parseUUID(connection)
	if !ok {
		return false, "", nil
	}
	at, err := q.CredentialChangedSince(ctx, org, id, since)
	switch {
	case db.IsNoRows(err):
		return false, "", nil
	case err != nil:
		return false, "", err
	}
	return true, at.UTC().Format(time.RFC3339), nil
}

func parseUUID(s string) (ids.UUID, bool) {
	u, err := ids.ParseUUID(s)
	return u, err == nil
}
