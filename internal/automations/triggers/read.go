// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package triggers

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"strconv"
	"strings"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Record is a trigger record as read back.
type Record struct {
	ID, Automation, Version ids.UUID
	Kind                    string
	Mode                    string
	SourceRef               string
	Authenticity            string
	Detail                  map[string]string
	Params                  map[string]string
	State                   string
	Reason                  string
	Execution               *ids.UUID
	Root                    ids.UUID
	Ancestry                []ids.UUID
	Depth                   int
	RetriedFrom             *ids.UUID
	OccurredAt, ReceivedAt  time.Time
}

// Read errors.
var (
	ErrTriggerNotFound = pcerr.New(pcerr.NotFound, "TRIGGER_NOT_FOUND", "trigger not found")
	ErrPageToken       = pcerr.New(pcerr.InvalidArgument, "INVALID_PAGE_TOKEN", "invalid page token")
)

// Paging.
const (
	DefaultPage = 50
	MaxPage     = 200
)

func (s *Service) reader(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	return c, c.Require(td.PermAutomationRead, td.OrgPath(c.Org))
}

func recordOf(r dbq.PcAutomationTrigger) Record {
	out := Record{
		ID: r.ID, Automation: r.AutomationID, Version: r.VersionID, Kind: r.Kind, Mode: r.Mode, SourceRef: r.SourceRef,
		Authenticity: r.Authenticity, State: r.State, Execution: r.ExecutionID, Root: r.RootTriggerID, Ancestry: r.Ancestry,
		Depth: int(r.Depth), RetriedFrom: r.RetriedFrom, OccurredAt: r.OccurredAt, ReceivedAt: r.ReceivedAt,
	}
	if r.Reason != nil {
		out.Reason = *r.Reason
	}
	_ = json.Unmarshal(r.AuthenticityDetail, &out.Detail)
	var ps map[string]autodomain.Value
	if json.Unmarshal(r.Params, &ps) == nil {
		out.Params = make(map[string]string, len(ps))
		for k, v := range ps {
			out.Params[k] = v.Text()
		}
	}
	return out
}

// GetTrigger returns one trigger record (automation.read).
func (s *Service) GetTrigger(ctx context.Context, id ids.UUID) (Record, error) {
	c, err := s.reader(ctx)
	if err != nil {
		return Record{}, err
	}
	var out Record
	err = s.d.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		r, err := dbq.New(tx).GetAutomationTrigger(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrTriggerNotFound
		} else if err != nil {
			return err
		}
		out = recordOf(r)
		return nil
	}, db.ReadOnly())
	return out, err
}

// ListTriggers lists an automation's trigger records, newest first
// (automation.read).
func (s *Service) ListTriggers(ctx context.Context, automation ids.UUID, state string, size int, token string) ([]Record, string, error) {
	c, err := s.reader(ctx)
	if err != nil {
		return nil, "", err
	}
	if size <= 0 {
		size = DefaultPage
	}
	size = min(size, MaxPage)
	var beforeAt *time.Time
	var beforeID ids.UUID
	if token != "" {
		at, id, ok := decodeToken(token)
		if !ok {
			return nil, "", ErrPageToken
		}
		beforeAt, beforeID = &at, id
	}
	var st *string
	if state != "" {
		st = &state
	}
	var out []Record
	next := ""
	err = s.d.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListAutomationTriggers(ctx, dbq.ListAutomationTriggersParams{
			OrgID: c.Org, AutomationID: automation, State: st, BeforeAt: beforeAt, BeforeID: beforeID,
			MaxRows: int32(size + 1), //nolint:gosec // ≤ 201
		})
		if err != nil {
			return err
		}
		for i, r := range rows {
			if i == size {
				last := out[len(out)-1]
				next = encodeToken(last.ReceivedAt, last.ID)
				break
			}
			out = append(out, recordOf(r))
		}
		return nil
	}, db.ReadOnly())
	return out, next, err
}

func encodeToken(at time.Time, id ids.UUID) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(at.UnixNano(), 10) + "." + id.String()))
}

func decodeToken(s string) (time.Time, ids.UUID, bool) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return time.Time{}, ids.UUID{}, false
	}
	ns, idText, ok := strings.Cut(string(b), ".")
	if !ok {
		return time.Time{}, ids.UUID{}, false
	}
	n, err := strconv.ParseInt(ns, 10, 64)
	if err != nil {
		return time.Time{}, ids.UUID{}, false
	}
	id, err := ids.ParseUUID(idText)
	if err != nil {
		return time.Time{}, ids.UUID{}, false
	}
	return time.Unix(0, n).UTC(), id, true
}

// Preview lists a schedule's occurrences for a reader (automation.read).
func (s *Service) Preview(ctx context.Context, expr, zone string, dstShift bool, from time.Time, count int) ([]PreviewEntry, error) {
	if _, err := s.reader(ctx); err != nil {
		return nil, err
	}
	if from.IsZero() {
		from = s.d.Clock.Now()
	}
	if count <= 0 {
		count = 10
	}
	out, err := PreviewSchedule(expr, zone, dstShift, from, count)
	if err != nil {
		return nil, pcerr.New(pcerr.InvalidArgument, "INVALID_SCHEDULE", err.Error())
	}
	return out, nil
}
