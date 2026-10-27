// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"strings"

	pgapprovals "github.com/katocxl/pantherclaw/internal/approvals/adapters/pgapprovals"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	notifapp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Notifier enqueues a notification in the caller's transaction
// (notifications/app.Service), so a rolled-back change sends nothing.
type Notifier interface {
	Enqueue(ctx context.Context, tx db.TenantTx, m notifapp.Message) (notifapp.Enqueued, error)
}

// tell sends a request's outcome notice (slice 211) in tx, once, to the
// people it was routed to and to the person who asked for it, when the
// request is in state want. A notice names ids, the operation and codes
// only. Without a notifier it does nothing.
func tell(ctx context.Context, tx db.TenantTx, n Notifier, org ids.OrgID, request ids.UUID, want, typ string, params map[string]string) error {
	if n == nil {
		return nil
	}
	q := dbq.New(tx)
	row, err := q.GetApprovalRequest(ctx, org, request)
	if err != nil || row.State != want {
		return err
	}
	people, err := q.RequestRecipients(ctx, org, request)
	if err != nil {
		return err
	}
	return send(ctx, tx, n, org, row, typ, params, people)
}

// tellAdmins sends a request's notice once to the org's admins and Security
// Admins.
func tellAdmins(ctx context.Context, tx db.TenantTx, n Notifier, org ids.OrgID, row dbq.PcApprovalRequest, typ string) error {
	if n == nil {
		return nil
	}
	admins, err := dbq.New(tx).OrgUsersWithRoles(ctx, org, []string{string(td.RoleOrgAdmin), string(td.RoleSecurityAdmin)})
	if err != nil {
		return err
	}
	return send(ctx, tx, n, org, row, typ, nil, admins)
}

func send(ctx context.Context, tx db.TenantTx, n Notifier, org ids.OrgID, row dbq.PcApprovalRequest, typ string, params map[string]string,
	people []ids.UUID,
) error {
	p := map[string]string{"operation": row.Operation, "request": row.ID.String()}
	if row.AgentID != nil {
		p["agent"] = row.AgentID.String()
	}
	if row.SubjectKind == subjectGate {
		var err error
		if typ, p, err = gateNotice(ctx, dbq.New(tx), org, row, typ); err != nil {
			return err
		}
	}
	for k, v := range params {
		p[k] = v
	}
	_, err := n.Enqueue(ctx, tx, notifapp.Message{
		Org: org, Type: typ, Params: p, Personal: people, Subject: &notifapp.Subject{Type: "approval_request", ID: row.ID},
		DedupeKey: typ + ":" + row.ID.String(),
	})
	return err
}

// gateNotice maps an approval notice of an automation gate to its gate
// type (approval.decided → automation.gate_decided), naming the automation
// and the step instead of an agent and an operation (D25a).
func gateNotice(ctx context.Context, q *dbq.Queries, org ids.OrgID, row dbq.PcApprovalRequest, typ string,
) (string, map[string]string, error) {
	name := ""
	if row.RequestedByAutomation != nil {
		a, err := q.GetAutomation(ctx, org, *row.RequestedByAutomation)
		if err != nil {
			return "", nil, err
		}
		name = a.Name
	}
	step := ""
	if row.StepID != nil {
		step = *row.StepID
	}
	return "automation.gate_" + strings.TrimPrefix(typ, "approval."),
		map[string]string{"automation": name, "step": step, "request": row.ID.String()}, nil
}

// ExpireAtUse expires a request at use, in the finalization that found it
// past a deadline (HR-039), and tells its outcome there, as the janitor
// tells the expiries it finds (slice 211c, HR-173): approval.expired, once
// per request, to the people it was routed to and the person who asked.
// Without a notifier it only expires the request.
func ExpireAtUse(ctx context.Context, tx db.TenantTx, n Notifier, org ids.OrgID, request ids.UUID, actor evdomain.Actor) error {
	if err := pgapprovals.Expire(ctx, tx, org, request, actor); err != nil {
		return err
	}
	return tell(ctx, tx, n, org, request, string(apdomain.StateExpired), "approval.expired", nil)
}
