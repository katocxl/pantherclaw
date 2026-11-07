// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/telemetry"
	"github.com/katocxl/pantherclaw/internal/platform/tenantctx"
	"github.com/katocxl/pantherclaw/internal/saasdiscovery/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// ErrScheduleHumanOnly refuses a machine's schedule change: each daily scan
// is started as the person who set it (G0 M34 D997, HR-768).
var ErrScheduleHumanOnly = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person sets or stops a daily SaaS scan")

// Schedule is a daily scan of one connection and tenant.
type Schedule = dbq.PcSaasScanSchedule

// SetSchedule asks for (daily true) or stops a daily scan of a tenant
// through a connection of the source's package (G0 M34 D997, HR-768).
// People only; the connection must be one Start would scan. A change is
// audited; stopping a schedule that does not exist changes nothing and
// returns nil.
func (s *Service) SetSchedule(ctx context.Context, source string, connection ids.UUID, tenant string, daily bool) (*Schedule, error) {
	c, err := s.caller(ctx, td.PermAgentManage)
	if err != nil {
		return nil, err
	}
	if !c.Human() {
		return nil, ErrScheduleHumanOnly
	}
	want, ok := domain.CollectorOf(source)
	if !ok || connection.IsZero() || !domain.SourceTenantOK(source, tenant) {
		return nil, errBadRequest
	}
	var out *Schedule
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		obj := &audit.Object{Type: "connection", ID: connection.String()}
		if !daily {
			row, err := q.DeleteSaasScanSchedule(ctx, dbq.DeleteSaasScanScheduleParams{OrgID: c.Org, Source: source, ConnectionID: connection, Tenant: tenant})
			if db.IsNoRows(err) {
				return nil
			} else if err != nil {
				return err
			}
			_, err = audit.Record(ctx, tx, audit.Event{
				Name: auditkind.SaasScanScheduleCleared, Actor: c.Actor(), Outcome: audit.Success, Object: obj,
				Details: map[string]string{"source": row.Source, "tenant": row.Tenant, "set_by": row.CreatedBy},
			})
			return err
		}
		conn, err := q.ScanConnection(ctx, c.Org, connection)
		if db.IsNoRows(err) || (err == nil && (conn.State != "ACTIVE" || conn.Kind != "http" || conn.Package != want.Package ||
			conn.CredentialKind != want.CredentialKind)) {
			return ErrConnection
		} else if err != nil {
			return err
		}
		row, err := q.UpsertSaasScanSchedule(ctx, dbq.UpsertSaasScanScheduleParams{
			OrgID: c.Org, Source: source, ConnectionID: connection, Tenant: tenant, CreatedBy: c.Principal.String(),
		})
		if err != nil {
			return err
		}
		out = &row
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: auditkind.SaasScanScheduleSet, Actor: c.Actor(), Outcome: audit.Success, Object: obj,
			Details: map[string]string{"source": source, "tenant": tenant},
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ScheduleMinGap is the least time between two scans a schedule starts: the
// daily job runs hourly, and a schedule whose last start is newer waits.
const ScheduleMinGap = 20 * time.Hour

// MetricScheduleSkipped counts daily scans not started, by reason
// (G0 M34 D997a).
const MetricScheduleSkipped = "pc_saas_schedule_skipped_total"

// Reasons a daily scan is skipped.
const (
	SkipPerson     = "person"     // the person is no longer an active member holding agent.manage
	SkipConnection = "connection" // the connection can no longer scan the source
	SkipRunning    = "running"    // a scan of the connection is running
	SkipEdition    = "edition"    // the edition has no SaaS discovery
)

var skipped, _ = otel.Meter("github.com/katocxl/pantherclaw/internal/saasdiscovery/app").Int64Counter(MetricScheduleSkipped,
	metric.WithDescription("Daily SaaS and cloud agent runtime scans not started, by reason."))

// skipError is a schedule skipped for a reason; last_started_at stays.
type skipError struct{ reason string }

func (e skipError) Error() string { return "saas: daily scan skipped: " + e.reason }

// Scheduler starts the daily scans (G0 M34 D997, FQ34-3).
type Scheduler struct {
	Pool     *db.Pool
	Editions Editions
	Log      *slog.Logger
}

// RunOrg starts one scan for each of org's schedules that is due, each in
// its own transaction. A schedule that cannot start is skipped and logged;
// it never stops the others.
func (s *Scheduler) RunOrg(ctx context.Context, org ids.OrgID) (int, error) {
	var list []Schedule
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		list, err = dbq.New(tx).ListSaasScanSchedules(ctx, org)
		return err
	}, db.ReadOnly())
	if err != nil || len(list) == 0 {
		return 0, err
	}
	// The org's entitlements, as other jobs read them: a job's context
	// carries no caller, so without the org it reads the licence's.
	if !s.entitled(tenantctx.WithOrg(ctx, org)) {
		for _, sch := range list {
			s.skip(ctx, sch, SkipEdition)
		}
		return 0, nil
	}
	started := 0
	for _, sch := range list {
		if sch.LastStartedAt != nil && time.Since(*sch.LastStartedAt) < ScheduleMinGap {
			continue
		}
		err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			return s.StartScheduledTx(ctx, tx, sch)
		})
		var skip skipError
		switch {
		case errors.As(err, &skip):
			s.skip(ctx, sch, skip.reason)
		case err != nil:
			return started, err
		default:
			started++
		}
	}
	return started, nil
}

func (s *Scheduler) entitled(ctx context.Context) bool {
	if s.Editions == nil {
		return false
	}
	e, err := s.Editions.Current(ctx)
	return err == nil && e.SaaSDiscovery()
}

func (s *Scheduler) skip(ctx context.Context, sch Schedule, reason string) {
	skipped.Add(ctx, 1, metric.WithAttributes(attribute.String(telemetry.KeyCode, reason), attribute.String(telemetry.KeyKind, sch.Source)))
	if s.Log != nil {
		s.Log.WarnContext(ctx, "saas.schedule_skipped", slog.String("org_id", sch.OrgID.String()), slog.String("source", sch.Source),
			slog.String("connection_id", sch.ConnectionID.String()), slog.String("reason", reason))
	}
}

// StartScheduledTx starts the daily scan of one schedule in tx (G0 M34
// D997a): it locks the schedule, checks that it is still due and that its
// person is still an ACTIVE member holding agent.manage, and starts a scan
// with origin schedule, started_by the person, audited by System with the
// person in schedule_person. A skip (skipError) leaves last_started_at
// unchanged.
func (s *Scheduler) StartScheduledTx(ctx context.Context, tx db.TenantTx, sch Schedule) error {
	q := dbq.New(tx)
	key := dbq.LockSaasScanScheduleParams{OrgID: sch.OrgID, Source: sch.Source, ConnectionID: sch.ConnectionID, Tenant: sch.Tenant}
	locked, err := q.LockSaasScanSchedule(ctx, key)
	if db.IsNoRows(err) {
		return nil // cleared since it was listed
	} else if err != nil {
		return err
	}
	if locked.LastStartedAt != nil && time.Since(*locked.LastStartedAt) < ScheduleMinGap {
		return nil // another job started it
	}
	if ok, err := personMayScan(ctx, q, sch.OrgID, locked.CreatedBy); err != nil {
		return err
	} else if !ok {
		return skipError{SkipPerson}
	}
	want, ok := domain.CollectorOf(sch.Source)
	if !ok || !domain.SourceTenantOK(sch.Source, sch.Tenant) {
		return skipError{SkipConnection}
	}
	err = startTx(ctx, tx, scanStart{
		org: sch.OrgID, run: ids.NewV7(), connection: sch.ConnectionID, source: sch.Source, tenant: sch.Tenant, want: want,
		origin: "schedule", startedBy: locked.CreatedBy, actor: evdomain.Actor{Type: "system", ID: "saas_schedule"},
		details: map[string]string{"schedule_person": locked.CreatedBy},
	})
	switch {
	case errors.Is(err, ErrConnection):
		return skipError{SkipConnection}
	case errors.Is(err, ErrScanRunning):
		return skipError{SkipRunning}
	case err != nil:
		return err
	}
	return q.MarkSaasScanScheduleStarted(ctx, dbq.MarkSaasScanScheduleStartedParams{
		OrgID: sch.OrgID, Source: sch.Source, ConnectionID: sch.ConnectionID, Tenant: sch.Tenant,
	})
}

// personMayScan reports whether createdBy ("user:<id>") is still an ACTIVE
// member of org holding agent.manage at the org.
func personMayScan(ctx context.Context, q *dbq.Queries, org ids.OrgID, createdBy string) (bool, error) {
	raw, ok := strings.CutPrefix(createdBy, string(td.KindUser)+":")
	if !ok {
		return false, nil
	}
	id, err := ids.ParseUUID(raw)
	if err != nil || id.IsZero() {
		return false, nil //nolint:nilerr // a schedule that names no person is no person who may scan
	}
	u, err := q.GetUser(ctx, org, id)
	if db.IsNoRows(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if u.State != "ACTIVE" {
		return false, nil
	}
	p := td.PrincipalRef{Kind: td.KindUser, ID: id}
	bindings, err := tenancy.Bindings(ctx, q, org, p)
	if err != nil {
		return false, err
	}
	sub := td.Subject{Org: org, Principal: p, Bindings: bindings}
	return sub.Can(td.PermAgentManage, td.OrgPath(org)), nil
}
