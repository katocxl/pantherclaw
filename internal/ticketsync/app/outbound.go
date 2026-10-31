// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"strconv"

	casesdomain "github.com/katocxl/pantherclaw/internal/cases/domain"
	casesstore "github.com/katocxl/pantherclaw/internal/cases/store"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/ticketsync/domain"
)

// Outbound ticket sync (G0 M20 D255). Opening the ticket of a case or an
// incident is a task of purpose ticket_sync on the configuration's
// connection: the org's gateway leases it once, sends the package's
// jira.issue.create with its sealed credential (HR-060, no exception) and
// reports the status and the new issue's key, which links the ticket. The
// ticket carries the title, the PantherClaw id and the link only.
// The gateway first reads whether the project is customer-visible and
// sends nothing there (D277, HR-522). One open waits at a time: a second
// returns the first, and a task that expires with no report ends its row.

// Outbound actions (migration 00243).
const (
	ActionCreate  = "CREATE"
	ActionComment = "COMMENT"
)

// Refused is the field a gateway reports a write it would not send with, a
// JSON pointer like every report field; RefusedExternal is its value for a
// customer-visible or unread project, and the result code it becomes.
const (
	Refused         = "/refused"
	RefusedExternal = "external_project"
)

// issueType is the Jira issue type of a ticket the sync opens.
const issueType = "Task"

// ticketRequest is a ticket sync task's request: what the gateway sends.
type ticketRequest struct {
	Mode   string            `json:"mode"`
	Target ticketTarget      `json:"target"`
	Params map[string]string `json:"params"`
}

type ticketTarget struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// OpenCaseTicket opens a ticket for case c in the configuration's project.
//
// permission: case.manage
func (s *Service) OpenCaseTicket(ctx context.Context, c, config ids.UUID) (ids.UUID, error) {
	return s.open(ctx, td.PermCaseManage, &c, nil, config)
}

// OpenIncidentTicket opens a ticket for incident i in the configuration's
// project.
//
// permission: incident.manage
func (s *Service) OpenIncidentTicket(ctx context.Context, i, config ids.UUID) (ids.UUID, error) {
	return s.open(ctx, td.PermIncidentManage, nil, &i, config)
}

// open stores the task and its outbound row; it returns the outbound id:
// the waiting one when an open is already waiting.
func (s *Service) open(ctx context.Context, perm td.Permission, kase, incident *ids.UUID, config ids.UUID) (ids.UUID, error) {
	c, err := person(ctx, perm)
	if err != nil {
		return ids.UUID{}, err
	}
	if err := s.business(ctx); err != nil {
		return ids.UUID{}, err
	}
	out := ids.NewV7()
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		cfg, err := q.GetTicketSyncConfig(ctx, c.Org, config)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if cfg.State != StateActive {
			return ErrNotFound
		}
		var title, subject string
		var refs []dbq.PcExternalRef
		if kase != nil {
			k, err := casesstore.Get(ctx, tx, *kase)
			if err != nil {
				return err
			}
			title, subject = k.Title, "PantherClaw case "+kase.String()
			refs, err = q.ExternalRefsOfCase(ctx, c.Org, kase)
			if err != nil {
				return err
			}
		} else {
			inc, err := q.IncidentTitle(ctx, c.Org, *incident)
			if db.IsNoRows(err) {
				return ErrNotFound
			} else if err != nil {
				return err
			}
			title, subject = inc, "PantherClaw incident "+incident.String()
			refs, err = q.ExternalRefsOfIncident(ctx, c.Org, incident)
			if err != nil {
				return err
			}
		}
		if len(refs) > 0 {
			return ErrLinked
		}
		waiting, err := q.WaitingTicketOpen(ctx, c.Org, kase, incident)
		if err == nil {
			out = waiting
			return errWaiting
		} else if !db.IsNoRows(err) {
			return err
		}
		body, err := json.Marshal(ticketRequest{
			Mode: "ticket_sync", Target: ticketTarget{Type: "jira_project", ID: cfg.ProjectKey},
			Params: map[string]string{
				"summary":     domain.Clean(title, 255),
				"description": subject + ". It is handled in PantherClaw; a ticket status never restores authority or lifts containment.",
				"issue_type":  issueType,
			},
		}, json.Deterministic(true))
		if err != nil {
			return err
		}
		task := ids.NewV7()
		if err := q.InsertTicketSyncVerification(ctx, dbq.InsertTicketSyncVerificationParams{
			OrgID: c.Org, ID: task, ConnectionID: cfg.ConnectionID, Operation: "jira.issue.create", Request: body,
		}); err != nil {
			return err
		}
		if err := q.InsertTicketOutbound(ctx, dbq.InsertTicketOutboundParams{
			OrgID: c.Org, ID: out, ConfigID: config, CaseID: kase, IncidentID: incident, Action: ActionCreate, VerificationID: task,
		}); err != nil {
			return err
		}
		return s.audit(ctx, tx, c.Actor(), "ticket.open_requested", "ticket_outbound", out, map[string]string{"project": cfg.ProjectKey})
	})
	switch {
	case errors.Is(err, errWaiting):
		return out, nil
	case db.IsUniqueViolation(err): // a concurrent open won: this one rolled back
		err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			out, err = dbq.New(tx).WaitingTicketOpen(ctx, c.Org, kase, incident)
			return err
		}, db.ReadOnly())
	}
	return out, err
}

// errWaiting ends open's transaction when an open is already waiting.
var errWaiting = errors.New("ticketsync: an open is waiting")

// EndUnreported ends the rows whose task expired with no report, in the
// sweep's transaction.
func (s *Service) EndUnreported(ctx context.Context, tx db.TenantTx, org ids.OrgID) error {
	ended, err := dbq.New(tx).FailEndedTicketOutbound(ctx, org)
	if err != nil {
		return err
	}
	for _, id := range ended {
		if err := s.audit(ctx, tx, domain.Actor, "ticket.sync_failed", "ticket_outbound", id, map[string]string{"code": "not_reported"}); err != nil {
			return err
		}
	}
	return nil
}

// ReportTicketSync takes the gateway's report of a ticket sync task under
// its live lease, in the report's transaction. It returns false when task
// is not such a task. A report always finishes the task: a write is never
// sent twice. A created issue's key links the case or incident.
func (s *Service) ReportTicketSync(ctx context.Context, tx db.TenantTx, org ids.OrgID, gateway, task ids.UUID, leaseHash []byte,
	status int, fields map[string]string,
) (bool, error) {
	q := dbq.New(tx)
	gw := gateway
	l, err := q.LeasedTicketSync(ctx, dbq.LeasedTicketSyncParams{OrgID: org, ID: task, GatewayID: &gw, LeaseHash: leaseHash})
	if db.IsNoRows(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	state, code := "DONE", ""
	key := fields["/key"]
	switch {
	case fields[Refused] == RefusedExternal:
		state, code = "FAILED", RefusedExternal // nothing was sent
	case status < 200 || status > 299:
		state, code = "FAILED", "http_"+strconv.Itoa(status)
		if status == 0 {
			code = "no_answer"
		}
	case l.Action == ActionCreate && (!domain.ValidIssueKey(key) || len(key) <= len(l.ProjectKey) || key[:len(l.ProjectKey)+1] != l.ProjectKey+"-"):
		state, code = "FAILED", "bad_issue_key"
	}
	if err := q.FinishVerification(ctx, "DONE", org, task); err != nil {
		return true, err
	}
	var rc *string
	if code != "" {
		rc = &code
	}
	if _, err := q.FinishTicketOutbound(ctx, dbq.FinishTicketOutboundParams{State: state, ResultCode: rc, OrgID: org, ID: l.OutboundID}); err != nil {
		return true, err
	}
	actor := domain.Actor
	if state != "DONE" {
		return true, s.audit(ctx, tx, actor, "ticket.sync_failed", "ticket_outbound", l.OutboundID, map[string]string{
			"operation": l.Operation, "code": code,
		})
	}
	if l.Action == ActionCreate {
		var id *string
		if v := fields["/id"]; v != "" && len(v) <= 20 {
			id = &v
		}
		ref, err := q.InsertExternalRef(ctx, dbq.InsertExternalRefParams{
			OrgID: org, ID: ids.NewV7(), CaseID: l.CaseID, IncidentID: l.IncidentID, System: l.System, ConnectionID: l.ConnectionID,
			ExternalKey: key, ExternalID: id, CreatedBy: domain.Principal,
		})
		if db.IsUniqueViolation(err) {
			// Linked by hand meanwhile: the new ticket is recorded, not linked.
			return true, s.audit(ctx, tx, actor, "ticket.created_unlinked", "ticket_outbound", l.OutboundID, map[string]string{"key": key})
		} else if err != nil {
			return true, err
		}
		if l.CaseID != nil {
			if _, err := casesstore.Append(ctx, tx, *l.CaseID, caseAuthor, casesdomain.Draft{
				Kind: casesdomain.KindNote, Text: string(domain.SystemJira) + " ticket " + key + " opened for this case",
			}); err != nil {
				return true, err
			}
		}
		return true, s.audit(ctx, tx, actor, "ticket.created", "external_ref", ref.ID, map[string]string{"key": key, "system": l.System})
	}
	return true, nil
}
