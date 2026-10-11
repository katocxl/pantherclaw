// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgtransactions

import (
	"context"
	"encoding/json/v2"
	"slices"
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/transactions/app"
)

// orgScan finishes an organization scan from its gateway's report (G0 M8,
// PN-001.2, HR-209). The report's fields are the run's summary, nothing
// else: /counts/<kind> (a count), /scanned/<source> and
// /not_scanned/<source> (why). A source not read is recorded as not
// scanned, never as "none found". A report that found nothing to scan
// (the App could not be used at all) fails the run. The findings come
// separately, through SubmitScanFindings on the gateway listener.
func orgScan(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, gateway ids.UUID, task dbq.LeasedOrgScanRow,
	r app.Report,
) (app.Applied, error) {
	counts, notScanned, scanned := map[string]int64{}, map[string]string{}, []string{}
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
			scanned = append(scanned, name)
		case "not_scanned":
			notScanned[name] = v
		default:
			return app.Applied{}, app.ErrUndeclared
		}
	}
	slices.Sort(scanned)
	state := "DONE"
	if !r.Found {
		state = "FAILED"
	}
	c, err := json.Marshal(counts, json.Deterministic(true))
	if err != nil {
		return app.Applied{}, err
	}
	n, err := json.Marshal(notScanned, json.Deterministic(true))
	if err != nil {
		return app.Applied{}, err
	}
	if err := q.FinishGitHubScanRun(ctx, dbq.FinishGitHubScanRunParams{
		State: state, Counts: c, Scanned: scanned, NotScanned: n, OrgID: org, ID: task.RunID,
	}); err != nil {
		return app.Applied{}, err
	}
	if _, err := audit.Record(ctx, tx, audit.Event{
		Name: "github.scan_finished", Actor: evdomain.Actor{Type: "gateway", ID: gateway.String()}, Outcome: audit.Success,
		Object:  &audit.Object{Type: "connection", ID: task.ConnectionID.String()},
		Details: map[string]string{"scan": task.RunID.String(), "state": state, "not_scanned": strconv.Itoa(len(notScanned))},
	}); err != nil {
		return app.Applied{}, err
	}
	return app.Applied{Done: true}, q.FinishVerification(ctx, "DONE", org, task.ID)
}
