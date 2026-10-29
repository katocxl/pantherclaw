// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgtransactions

import (
	"context"
	"encoding/json/v2"
	agentsapp "github.com/katocxl/pantherclaw/internal/agents/app"
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
// /not_scanned/<source> (why). The server keeps the catalog of sources: a
// source is either read or not read, never both, and one the report leaves
// out is recorded as not reported; a name outside the catalog is refused.
// A source not read is never taken for "none found". A report that found
// nothing to scan (the App could not be used at all) fails the run. The
// findings come separately, through SubmitScanFindings on the gateway
// listener.
// scanSources are the sources an organization scan accounts for, each
// reported read or not read (F450).
var scanSources = []string{"mcp_configs", "org_installations", "repositories", "rulesets", "workflows"}

// scanNotes are further reasons a report may give for what it did not
// read: repositories it could not read, an App it could not use, findings
// it could not submit or the server dropped.
var scanNotes = []string{"contents", "findings", "organization"}

func orgScan(ctx context.Context, tx db.TenantTx, q *dbq.Queries, notify agentsapp.Notifier, org ids.OrgID, gateway ids.UUID,
	task dbq.LeasedOrgScanRow, r app.Report,
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
			if !slices.Contains(scanSources, name) {
				return app.Applied{}, app.ErrUndeclared
			}
			scanned = append(scanned, name)
		case "not_scanned":
			if !slices.Contains(scanSources, name) && !slices.Contains(scanNotes, name) {
				return app.Applied{}, app.ErrUndeclared
			}
			notScanned[name] = v
		default:
			return app.Applied{}, app.ErrUndeclared
		}
	}
	for _, s := range scanned {
		if _, both := notScanned[s]; both {
			return app.Applied{}, app.ErrUndeclared // read and not read
		}
	}
	for _, s := range scanSources {
		if _, read := notScanned[s]; !read && !slices.Contains(scanned, s) {
			notScanned[s] = "not reported"
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
	// Continuous discovery counts what this run missed (PN-001.3, D114).
	if err := agentsapp.OrgScanFinished(ctx, tx, q, notify, gateway, task.ConnectionID, task.RunID, state, scanned, notScanned); err != nil {
		return app.Applied{}, err
	}
	read, err := recordInstallation(ctx, q, org, gateway, task, r.Installation)
	if err != nil {
		return app.Applied{}, err
	}
	if _, err := audit.Record(ctx, tx, audit.Event{
		Name: "github.scan_finished", Actor: evdomain.Actor{Type: "gateway", ID: gateway.String()}, Outcome: audit.Success,
		Object: &audit.Object{Type: "connection", ID: task.ConnectionID.String()},
		Details: map[string]string{
			"scan": task.RunID.String(), "state": state, "not_scanned": strconv.Itoa(len(notScanned)),
			"installation_read": strconv.FormatBool(read),
		},
	}); err != nil {
		return app.Applied{}, err
	}
	return app.Applied{Done: true}, q.FinishVerification(ctx, "DONE", org, task.ID)
}

// recordInstallation records the permissions and repository selection of
// the installation behind the scanned connection, as the scan read them
// (G0 M8, F048), and reports whether it did. They are the installation the
// lease was scheduled for. Nothing is recorded when the scan did not read
// it, when the report is out of bounds, or when the connection records
// another installation by now: what was there stays,
// so unread permissions remain "not observed", never "none".
func recordInstallation(ctx context.Context, q *dbq.Queries, org ids.OrgID, gateway ids.UUID, task dbq.LeasedOrgScanRow,
	in *app.InstallationRead,
) (bool, error) {
	id := leaseInstallation(task.Request)
	if in == nil || id <= 0 || len(in.Permissions) > maxInstallationPermissions ||
		(in.RepositorySelection != "all" && in.RepositorySelection != "selected") {
		return false, nil
	}
	perms := in.Permissions
	if perms == nil {
		perms = map[string]string{}
	}
	b, err := json.Marshal(perms, json.Deterministic(true))
	if err != nil || len(b) > 4096 {
		return false, err
	}
	sel := in.RepositorySelection
	n, err := q.RecordInstallationPermissions(ctx, dbq.RecordInstallationPermissionsParams{
		Permissions: b, RepositorySelection: &sel, UpdatedBy: "gateway:" + gateway.String(),
		OrgID: org, ConnectionID: task.ConnectionID, InstallationID: id,
	})
	return n == 1, err
}

// leaseInstallation is the installation an org-scan lease was scheduled
// for, or 0 when its request names none.
func leaseInstallation(request []byte) int64 {
	var req struct {
		Installation string `json:"installation"`
	}
	if json.Unmarshal(request, &req) != nil {
		return 0
	}
	id, err := strconv.ParseInt(req.Installation, 10, 64)
	if err != nil {
		return 0
	}
	return id
}

// maxInstallationPermissions bounds an installation report's permissions.
const maxInstallationPermissions = 128
