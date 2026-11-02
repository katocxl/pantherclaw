// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgtransactions

import (
	"context"
	"strconv"
	"strings"

	agentsapp "github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/transactions/app"
)

// saasOrTicket hands a report that matched no other lease to a SaaS scan, and
// failing that to the ticket sync (G0 M26 D407).
func (s *Store) saasOrTicket(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, gateway ids.UUID, r app.Report, hash []byte,
	out *app.Applied,
) error {
	gw := gateway
	task, err := q.LeasedSaasScan(ctx, dbq.LeasedSaasScanParams{OrgID: org, ID: r.Task, GatewayID: &gw, LeaseHash: hash})
	if db.IsNoRows(err) {
		return s.ticketSync(ctx, tx, org, gateway, r, hash, out)
	} else if err != nil {
		return err
	}
	*out, err = saasScan(ctx, tx, q, s.Notify, org, gateway, task, r)
	return err
}

// saasScan finishes a SaaS scan from its gateway's report. As with an
// organization scan, the fields are the run's summary and nothing else:
// /counts/<name>, /scanned/<read> and /not_scanned/<read or note>. The server
// keeps the catalog of what a source reads: a read left out is recorded as
// not reported, a name outside it is refused, and a read not finished is
// never "none found" (HR-637). A report that reached nothing fails the run.
// The findings came separately, through SubmitScanFindings.
func saasScan(ctx context.Context, tx db.TenantTx, q *dbq.Queries, notify agentsapp.Notifier, org ids.OrgID, gateway ids.UUID,
	task dbq.LeasedSaasScanRow, r app.Report,
) (app.Applied, error) {
	counts, reported, read := map[string]int64{}, map[string]string{}, []string{}
	for k, v := range r.Fields {
		kind, name, ok := strings.Cut(strings.TrimPrefix(k, "/"), "/")
		if !ok || name == "" || strings.Contains(name, "/") {
			return app.Applied{}, app.ErrUndeclared
		}
		switch kind {
		case "counts":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 0 {
				return app.Applied{}, app.ErrUndeclared
			}
			counts[name] = n
		case "scanned":
			read = append(read, name)
		case "not_scanned":
			reported[name] = v
		default:
			return app.Applied{}, app.ErrUndeclared
		}
	}
	scanned, notScanned, err := agentsapp.NormalizeSaaSReport(task.Source, read, reported)
	if err != nil {
		return app.Applied{}, app.ErrUndeclared
	}
	state := "DONE"
	if !r.Found {
		state = "FAILED"
	}
	if err := agentsapp.FinishSaaSRun(ctx, q, org, task.RunID, state, counts, scanned, notScanned); err != nil {
		return app.Applied{}, err
	}
	if err := agentsapp.SaaSScanFinished(ctx, tx, q, notify, gateway, task.Source, task.Tenant, task.RunID, state, scanned, notScanned); err != nil {
		return app.Applied{}, err
	}
	if _, err := audit.Record(ctx, tx, audit.Event{
		Name: "saas.scan_finished", Actor: evdomain.Actor{Type: "gateway", ID: gateway.String()}, Outcome: audit.Success,
		Details: map[string]string{
			"scan": task.RunID.String(), "source": task.Source, "state": state, "not_scanned": strconv.Itoa(len(notScanned)),
		},
	}); err != nil {
		return app.Applied{}, err
	}
	return app.Applied{Done: true}, q.FinishVerification(ctx, "DONE", org, task.ID)
}
