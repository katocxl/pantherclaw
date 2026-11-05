// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/saasdiscovery/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// ErrScheduleHumanOnly refuses a machine's schedule change: each daily scan
// is started as the person who set it (G0 M34 D997, HR-768).
var ErrScheduleHumanOnly = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person sets or stops a daily SaaS scan")

// Schedule is a daily scan of one connection.
type Schedule = dbq.PcSaasScanSchedule

// SetSchedule asks for (daily true) or stops a daily scan of a connection
// of the source's package (G0 M34 D997, HR-768). People only; the
// connection must be one Start would scan. A change is audited; stopping a
// schedule that does not exist changes nothing and returns nil.
func (s *Service) SetSchedule(ctx context.Context, source string, connection ids.UUID, daily bool) (*Schedule, error) {
	c, err := s.caller(ctx, td.PermAgentManage)
	if err != nil {
		return nil, err
	}
	if !c.Human() {
		return nil, ErrScheduleHumanOnly
	}
	want, ok := domain.CollectorOf(source)
	if !ok || connection.IsZero() {
		return nil, errBadRequest
	}
	var out *Schedule
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		obj := &audit.Object{Type: "connection", ID: connection.String()}
		if !daily {
			row, err := q.DeleteSaasScanSchedule(ctx, c.Org, source, connection)
			if db.IsNoRows(err) {
				return nil
			} else if err != nil {
				return err
			}
			_, err = audit.Record(ctx, tx, audit.Event{
				Name: auditkind.SaasScanScheduleCleared, Actor: c.Actor(), Outcome: audit.Success, Object: obj,
				Details: map[string]string{"source": row.Source, "set_by": row.CreatedBy},
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
			OrgID: c.Org, Source: source, ConnectionID: connection, CreatedBy: c.Principal.String(),
		})
		if err != nil {
			return err
		}
		out = &row
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: auditkind.SaasScanScheduleSet, Actor: c.Actor(), Outcome: audit.Success, Object: obj,
			Details: map[string]string{"source": source},
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
