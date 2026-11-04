// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app is SaaS agent discovery (N6, G0 M26 D407): imports of exported
// recordings and gateway scans of a tenant, what they found, and who owns it.
// It reads metadata only, and reports what it could not read as not scanned.
package app

import (
	"context"
	"encoding/json/v2"
	"maps"

	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/saasdiscovery/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors of SaaS discovery.
var (
	ErrEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "SaaS agent discovery needs the Business edition or above")
	// ErrHumanOnly refuses a machine's scan start: a person sends the
	// connection's credential to work.
	ErrHumanOnly = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person starts a SaaS scan")
	// ErrConnection refuses a connection that cannot read the source.
	ErrConnection = pcerr.New(pcerr.FailedPrecondition, "NOT_A_SAAS_CONNECTION",
		"only an active HTTP connection of the source's package, holding its credential kind, scans it")
	ErrScanRunning   = pcerr.New(pcerr.FailedPrecondition, "SCAN_RUNNING", "a scan of this connection is already running")
	ErrScanNotFound  = pcerr.New(pcerr.NotFound, "SCAN_NOT_FOUND", "no such scan")
	ErrAgentNotFound = pcerr.New(pcerr.NotFound, "AGENT_NOT_FOUND", "no such external agent")
	errBadRequest    = pcerr.New(pcerr.InvalidArgument, "SAAS_REQUEST", "a known source and a well-formed tenant are required")
)

// Editions reports the licence's entitlements. Nil is no entitlement.
type Editions interface {
	Current(context.Context) (billing.Entitlements, error)
}

// Service serves SaaS discovery.
type Service struct {
	Pool      *db.Pool
	Inventory *agents.Inventory
	Editions  Editions
}

// Scan is one import or gateway scan.
type Scan struct {
	dbq.GetSaasRunRow
	Counts     map[string]int64
	NotScanned map[string]string
}

// Agent is one external agent. Attributes are untrusted text.
type Agent struct {
	dbq.GetSaasAgentRow
	Attributes map[string]string
}

// edition refuses an edition without SaaS discovery.
func (s *Service) edition(ctx context.Context) error {
	if s.Editions == nil {
		return ErrEdition
	}
	e, err := s.Editions.Current(ctx)
	if err != nil {
		return err
	}
	if !e.SaaSDiscovery() {
		return ErrEdition
	}
	return nil
}

// caller is the caller, holding perm at the org, in an edition with discovery.
func (s *Service) caller(ctx context.Context, perm td.Permission) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if err := c.Require(perm, td.OrgPath(c.Org)); err != nil {
		return c, err
	}
	return c, s.edition(ctx)
}

// Import records a recording parsed on the caller's machine.
func (s *Service) Import(ctx context.Context, r agents.SaaSReport) (Scan, agents.ScanResult, error) {
	if _, err := s.caller(ctx, td.PermAgentManage); err != nil {
		return Scan{}, agents.ScanResult{}, err
	}
	if domain.KindOf(r.Source) == "" || !domain.TenantOK(r.Tenant) {
		return Scan{}, agents.ScanResult{}, errBadRequest
	}
	res, err := s.Inventory.ImportSaaS(ctx, r)
	if err != nil {
		return Scan{}, agents.ScanResult{}, err
	}
	scan, err := s.Get(ctx, res.Run)
	return scan, res.ScanResult, err
}

// Start schedules a gateway's collection through a connection.
func (s *Service) Start(ctx context.Context, connection ids.UUID, source, tenant string) (Scan, error) {
	c, err := s.caller(ctx, td.PermAgentManage)
	if err != nil {
		return Scan{}, err
	}
	if !c.Human() {
		return Scan{}, ErrHumanOnly
	}
	want, ok := domain.CollectorOf(source)
	if !ok || !domain.TenantOK(tenant) {
		return Scan{}, errBadRequest
	}
	run := ids.NewV7()
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		conn, err := q.ScanConnection(ctx, c.Org, connection)
		if db.IsNoRows(err) || (err == nil && (conn.State != "ACTIVE" || conn.Kind != "http" || conn.Package != want.Package ||
			conn.CredentialKind != want.CredentialKind)) {
			return ErrConnection
		} else if err != nil {
			return err
		}
		if open, err := q.OpenSaasScan(ctx, c.Org, connection); err != nil {
			return err
		} else if open {
			return ErrScanRunning
		}
		request, err := json.Marshal(map[string]string{"run": run.String(), "source": source, "tenant": tenant}, json.Deterministic(true))
		if err != nil {
			return err
		}
		lease := ids.NewV7()
		if err := q.ScheduleSaasScan(ctx, dbq.ScheduleSaasScanParams{
			OrgID: c.Org, ID: lease, ConnectionID: connection, Operation: domain.OperationScan, Request: request,
		}); err != nil {
			return err
		}
		if err := q.InsertSaasRun(ctx, dbq.InsertSaasRunParams{
			OrgID: c.Org, ID: run, Source: source, Origin: "gateway", Tenant: tenant, ConnectionID: &connection, VerificationID: &lease,
			StartedBy: c.Principal.String(),
		}); err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: auditkind.SaasScanStarted, Actor: c.Actor(), Outcome: audit.Success, Object: &audit.Object{Type: "connection", ID: connection.String()},
			Details: map[string]string{"scan": run.String(), "source": source, "tenant": tenant},
		})
		return err
	})
	if err != nil {
		return Scan{}, err
	}
	return s.Get(ctx, run)
}

func scanView(r dbq.GetSaasRunRow) Scan {
	out := Scan{GetSaasRunRow: r}
	// Written by the server; anything else reads as nothing.
	_ = json.Unmarshal(r.Counts, &out.Counts)
	_ = json.Unmarshal(r.NotScanned, &out.NotScanned)
	return out
}

// Get returns a run.
func (s *Service) Get(ctx context.Context, id ids.UUID) (Scan, error) {
	c, err := s.caller(ctx, td.PermAgentRead)
	if err != nil {
		return Scan{}, err
	}
	var out Scan
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).GetSaasRun(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrScanNotFound
		} else if err != nil {
			return err
		}
		out = scanView(row)
		return nil
	}, db.ReadOnly())
	return out, err
}

// optAfter is a page's cursor, nil on the first page.
func optAfter(pr page.Request) *ids.UUID {
	if pr.After.IsZero() {
		return nil
	}
	return &pr.After
}

// List pages through the org's runs, newest first.
func (s *Service) List(ctx context.Context, source string, size int32, token string) ([]Scan, string, error) {
	c, err := s.caller(ctx, td.PermAgentRead)
	if err != nil {
		return nil, "", err
	}
	pr, err := page.Parse(size, token)
	if err != nil {
		return nil, "", err
	}
	var out []Scan
	var next string
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListSaasRuns(ctx, dbq.ListSaasRunsParams{OrgID: c.Org, Source: source, BeforeID: optAfter(pr), MaxRows: pr.Limit()})
		if err != nil {
			return err
		}
		rows, next = page.Finish(pr, rows, func(r dbq.ListSaasRunsRow) ids.UUID { return r.ID })
		for _, r := range rows {
			out = append(out, scanView(dbq.GetSaasRunRow(r)))
		}
		return nil
	}, db.ReadOnly())
	return out, next, err
}

func agentView(r dbq.GetSaasAgentRow) Agent {
	out := Agent{GetSaasAgentRow: r}
	_ = json.Unmarshal(r.Observed, &out.Attributes) // stored as an object of strings
	out.Attributes = maps.Clone(out.Attributes)
	for _, k := range []string{"kind", "submitted_by", "scan_run"} {
		delete(out.Attributes, k) // what the server added, not the record
	}
	return out
}

// ListAgents pages through the external agents.
func (s *Service) ListAgents(ctx context.Context, source string, size int32, token string) ([]Agent, string, error) {
	c, err := s.caller(ctx, td.PermAgentRead)
	if err != nil {
		return nil, "", err
	}
	pr, err := page.Parse(size, token)
	if err != nil {
		return nil, "", err
	}
	var out []Agent
	var next string
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListSaasAgents(ctx, dbq.ListSaasAgentsParams{OrgID: c.Org, Source: source, AfterID: optAfter(pr), MaxRows: pr.Limit()})
		if err != nil {
			return err
		}
		rows, next = page.Finish(pr, rows, func(r dbq.ListSaasAgentsRow) ids.UUID { return r.DiscoveryID })
		for _, r := range rows {
			out = append(out, agentView(dbq.GetSaasAgentRow(r)))
		}
		return nil
	}, db.ReadOnly())
	return out, next, err
}

// SetOwner names an external agent's owner, and nothing else (HR-639).
func (s *Service) SetOwner(ctx context.Context, id, owner, backup ids.UUID, reason string) (Agent, error) {
	c, err := s.caller(ctx, td.PermAgentManage)
	if err != nil {
		return Agent{}, err
	}
	if _, err := s.Inventory.SetExternalOwner(ctx, id, owner, backup, reason); err != nil {
		return Agent{}, err
	}
	var out Agent
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).GetSaasAgent(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrAgentNotFound
		} else if err != nil {
			return err
		}
		out = agentView(row)
		return nil
	}, db.ReadOnly())
	return out, err
}
