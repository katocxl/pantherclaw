// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors of organization scans.
var (
	ErrEdition       = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "scanning a GitHub organization needs the Team edition or above")
	ErrNotGitHubApp  = pcerr.New(pcerr.FailedPrecondition, "NOT_A_GITHUB_APP_CONNECTION", "only an active pc.github connection holding a GitHub App credential scans")
	ErrScanRunning   = pcerr.New(pcerr.FailedPrecondition, "SCAN_RUNNING", "a scan of this connection is already running")
	ErrScanNotFound  = pcerr.New(pcerr.NotFound, "SCAN_NOT_FOUND", "no such scan")
	errNoEntitlement = pcerr.New(pcerr.Unavailable, "EDITION_UNKNOWN", "the edition could not be read")
)

// Entitlements reports the current edition (billing.Service).
type Entitlements interface {
	Current(context.Context) (billing.Entitlements, error)
}

// Scans starts and reads organization scans (PN-001.2, HR-209): each runs
// in the connection's gateway as an org_scan lease, which reads metadata
// and named files only through the connection's App and submits what it
// finds; findings grant nothing.
type Scans struct {
	Pool *db.Pool
	Ents Entitlements
}

// Scan is one scan.
type Scan struct {
	dbq.GetGitHubScanRunRow
	Counts     map[string]int64
	NotScanned map[string]string
}

// scanner is the caller, when a person holding github.scan.run in an
// edition that scans.
func (s *Scans) scanner(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if err := c.Require(td.PermGitHubScanRun, td.OrgPath(c.Org)); err != nil {
		return c, err
	}
	if !c.Human() {
		return c, ErrHumanOnly
	}
	if s.Ents == nil {
		return c, errNoEntitlement
	}
	e, err := s.Ents.Current(ctx)
	if err != nil {
		return c, errNoEntitlement
	}
	if !e.GitHubOrgScan() {
		return c, ErrEdition
	}
	return c, nil
}

// Start schedules a scan of the organization behind a GitHub App
// connection.
func (s *Scans) Start(ctx context.Context, connection ids.UUID) (Scan, error) {
	c, err := s.scanner(ctx)
	if err != nil {
		return Scan{}, err
	}
	run := ids.NewV7()
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		conn, err := q.ScanConnection(ctx, c.Org, connection)
		if db.IsNoRows(err) || (err == nil && (conn.State != "ACTIVE" || conn.Kind != "http" || conn.Package != "pc.github" ||
			conn.CredentialKind != "github_app")) {
			return ErrNotGitHubApp
		} else if err != nil {
			return err
		}
		if open, err := q.OpenOrgScan(ctx, c.Org, connection); err != nil {
			return err
		} else if open {
			return ErrScanRunning
		}
		request, err := json.Marshal(map[string]string{"run": run.String()})
		if err != nil {
			return err
		}
		lease := ids.NewV7()
		if err := q.ScheduleOrgScan(ctx, dbq.ScheduleOrgScanParams{OrgID: c.Org, ID: lease, ConnectionID: connection, Request: request}); err != nil {
			return err
		}
		if err := q.InsertGitHubScanRun(ctx, dbq.InsertGitHubScanRunParams{
			OrgID: c.Org, ID: run, ConnectionID: connection, VerificationID: &lease, StartedBy: c.Principal.String(),
		}); err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "github.scan_started", Actor: c.Actor(), Outcome: audit.Success, Object: &audit.Object{Type: "connection", ID: connection.String()},
			Details: map[string]string{"scan": run.String()},
		})
		return err
	})
	if err != nil {
		return Scan{}, err
	}
	return s.Get(ctx, run)
}

// Get returns a scan.
func (s *Scans) Get(ctx context.Context, id ids.UUID) (Scan, error) {
	c, err := s.scanner(ctx)
	if err != nil {
		return Scan{}, err
	}
	var out Scan
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).GetGitHubScanRun(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrScanNotFound
		} else if err != nil {
			return err
		}
		out = Scan{GetGitHubScanRunRow: row}
		// Stored by the server from a gateway's report; anything else reads
		// as nothing.
		_ = json.Unmarshal(row.Counts, &out.Counts)
		_ = json.Unmarshal(row.NotScanned, &out.NotScanned)
		return nil
	}, db.ReadOnly())
	return out, err
}

// Finding is one thing a scan found: its discovered agent, and its
// untrusted attributes (kind among them).
type Finding struct {
	dbq.ListOrgScanFindingsRow
	Attributes map[string]string
}

// Findings pages through what a scan saw: untrusted observations recorded
// as DISCOVERED agents, which grant nothing (HR-209).
func (s *Scans) Findings(ctx context.Context, scan ids.UUID, size int32, token string) ([]Finding, string, error) {
	c, err := s.scanner(ctx)
	if err != nil {
		return nil, "", err
	}
	pr, err := page.Parse(size, token)
	if err != nil {
		return nil, "", err
	}
	var out []Finding
	var next string
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := q.GetGitHubScanRun(ctx, c.Org, scan); db.IsNoRows(err) {
			return ErrScanNotFound
		} else if err != nil {
			return err
		}
		rows, err := q.ListOrgScanFindings(ctx, dbq.ListOrgScanFindingsParams{OrgID: c.Org, ScanRun: scan.String(), AfterID: pr.After, MaxRows: pr.Limit()})
		if err != nil {
			return err
		}
		rows, next = page.Finish(pr, rows, func(r dbq.ListOrgScanFindingsRow) ids.UUID { return r.ID })
		for _, r := range rows {
			f := Finding{ListOrgScanFindingsRow: r}
			_ = json.Unmarshal(r.Observed, &f.Attributes) // stored as an object of strings
			delete(f.Attributes, "scan_run")
			out = append(out, f)
		}
		return nil
	}, db.ReadOnly())
	return out, next, err
}
