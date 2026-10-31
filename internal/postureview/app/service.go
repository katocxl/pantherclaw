// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app serves the ranked posture queue and its trends (G0 M24
// D200-D206; HR-580, HR-581). The queue is computed on each read and changes
// nothing: a finding clears when its source clears, and dismissing one goes
// to its source (D207). What the viewer may read is resolved before any
// source runs, and held to again before anything is ranked.
package app

import (
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"strconv"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	exapp "github.com/katocxl/pantherclaw/internal/exposure/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/postureview/domain"
	"github.com/katocxl/pantherclaw/internal/postureview/ports"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// API errors of the service.
var (
	ErrEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED",
		"the ranked posture queue needs the Team edition or above")
	ErrTrendsEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED",
		"posture trends need the Business edition or above")
)

const defaultPageSize = 50

// SourceState is how a source answered.
type SourceState string

// States.
const (
	SourceComplete     SourceState = "COMPLETE"
	SourceTruncated    SourceState = "TRUNCATED"
	SourceRestricted   SourceState = "RESTRICTED"
	SourceNotInEdition SourceState = "NOT_IN_EDITION"
)

// SourceStatus reports one source of a read.
type SourceStatus struct {
	Source   domain.Source
	State    SourceState
	Findings int
}

// Listing is one page of the queue.
type Listing struct {
	Findings   []domain.RankedFinding
	Next       string
	Restricted bool
	Sources    []SourceStatus
	Total      int
	AsOf       time.Time
}

// Service serves the queue.
type Service struct {
	Pool    *db.Pool
	Ents    exapp.Entitlements
	Sources []ports.Source
}

func (s *Service) entitled(ctx context.Context, want func(billing.Entitlements) bool, refused error) error {
	if s.Ents == nil {
		return refused
	}
	e, err := s.Ents.Current(ctx)
	if err != nil {
		return err
	}
	if !want(e) {
		return refused
	}
	return nil
}

// viewerOf resolves what the caller may read, before any source runs.
func (s *Service) viewerOf(ctx context.Context, c tenancy.Caller) (ports.Viewer, time.Time, error) {
	v := ports.Viewer{Org: c.Org}
	v.Under = func(ctx context.Context, p td.Permission) (ports.Reach, error) {
		if !c.CanAnywhere(p) {
			return ports.Reach{}, td.ErrPermissionDenied(p)
		}
		var r ports.Reach
		err := s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			r, err = reachOf(ctx, c, dbq.New(tx), p)
			return err
		}, db.ReadOnly())
		return r, err
	}
	var now time.Time
	err := s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		if v.Posture, err = reachOf(ctx, c, q, td.PermPostureRead); err != nil {
			return err
		}
		now, err = q.DBNow(ctx)
		return err
	}, db.ReadOnly())
	return v, now, err
}

func reachOf(ctx context.Context, c tenancy.Caller, q *dbq.Queries, p td.Permission) (ports.Reach, error) {
	vis, err := exapp.VisibleAgents(ctx, c, q, p)
	if err != nil {
		return ports.Reach{}, err
	}
	return ports.Reach{All: vis.All, Agents: vis.IDs, Org: c.Can(p, td.OrgPath(c.Org))}, nil
}

// orgViewer reads as the org: the daily rollup counts everything.
func orgViewer(org ids.OrgID) ports.Viewer {
	all := ports.Reach{All: true, Org: true}
	return ports.Viewer{
		Org: org, Posture: all,
		Under: func(context.Context, td.Permission) (ports.Reach, error) { return all, nil },
	}
}

// stateOf classifies a source's error: a refused permission or edition is a
// state to report, anything else a failure of the read.
func stateOf(err error) (SourceState, error) {
	var e *pcerr.Error
	if !errors.As(err, &e) {
		return "", err
	}
	switch {
	case e.Code() == pcerr.PermissionDenied:
		return SourceRestricted, nil
	case e.Code() == pcerr.FailedPrecondition && e.Reason() == "EDITION_REQUIRED":
		return SourceNotInEdition, nil
	}
	return "", err
}

func denied(err error) bool {
	var e *pcerr.Error
	return errors.As(err, &e) && e.Code() == pcerr.PermissionDenied
}

// collect reads every source under v, holds what comes back to v, fills what
// ranking reads and applies f.
func (s *Service) collect(ctx context.Context, v ports.Viewer, f domain.Filter) ([]domain.Finding, []SourceStatus, error) {
	var all []domain.Finding
	statuses := make([]SourceStatus, 0, len(s.Sources))
	for _, src := range s.Sources {
		if f.Source != "" && src.Name() != f.Source {
			continue
		}
		st := SourceStatus{Source: src.Name(), State: SourceComplete}
		found, more, err := src.Findings(ctx, v, f)
		if err != nil {
			if st.State, err = stateOf(err); err != nil {
				return nil, nil, err
			}
			statuses = append(statuses, st)
			continue
		}
		if len(found) > domain.MaxPerSource {
			found, more = found[:domain.MaxPerSource], true
		}
		if more {
			st.State = SourceTruncated
		}
		for _, x := range found {
			if v.Posture.Has(x.AgentID) {
				x.Source = src.Name()
				all = append(all, x.Normalize())
			}
		}
		statuses = append(statuses, st)
	}
	if err := s.fill(ctx, v, all); err != nil {
		return nil, nil, err
	}
	kept := make([]domain.Finding, 0, len(all))
	for _, x := range all {
		if !f.Match(x) {
			continue
		}
		kept = append(kept, x)
		statuses[slices.IndexFunc(statuses, func(st SourceStatus) bool { return st.Source == x.Source })].Findings++
	}
	slices.SortFunc(statuses, func(a, b SourceStatus) int { return cmp.Compare(a.Source, b.Source) })
	return kept, statuses, nil
}

// fill sets what ranking reads of each finding's agent. A label needs
// agent.read over that agent; the ranking facts do not show the agent.
func (s *Service) fill(ctx context.Context, v ports.Viewer, fs []domain.Finding) error {
	want := []ids.UUID{}
	for _, f := range fs {
		if f.AgentID != nil && !slices.Contains(want, *f.AgentID) {
			want = append(want, *f.AgentID)
		}
	}
	if len(want) == 0 {
		return nil
	}
	labels, err := v.Under(ctx, td.PermAgentRead)
	if denied(err) {
		labels, err = ports.Reach{}, nil
	}
	if err != nil {
		return err
	}
	var rows []dbq.PostureQueueAgentsRow
	err = s.Pool.InTenantTx(ctx, v.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		rows, err = dbq.New(tx).PostureQueueAgents(ctx, v.Org, want)
		return err
	}, db.ReadOnly())
	if err != nil {
		return err
	}
	by := make(map[ids.UUID]dbq.PostureQueueAgentsRow, len(rows))
	for _, r := range rows {
		by[r.ID] = r
	}
	for i := range fs {
		f := &fs[i]
		if f.AgentID == nil {
			continue
		}
		r, ok := by[*f.AgentID]
		if !ok {
			continue
		}
		if labels.Has(f.AgentID) {
			f.AgentLabel = r.Name
		}
		if f.TeamID == nil {
			f.TeamID = r.TeamID
		}
		f.ReachesProduction, f.Unowned = r.Production, !r.Owned
	}
	return nil
}

func parseOffset(token string) (int, error) {
	if token == "" {
		return 0, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return 0, page.ErrBadToken
	}
	n, err := strconv.Atoi(string(raw))
	if err != nil || n < 0 {
		return 0, page.ErrBadToken
	}
	return n, nil
}

func offsetToken(n int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(n)))
}

// List returns one page of what the caller may read, most urgent first.
func (s *Service) List(ctx context.Context, f domain.Filter, size int32, token string) (Listing, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Listing{}, err
	}
	if !c.CanAnywhere(td.PermPostureRead) {
		return Listing{}, td.ErrPermissionDenied(td.PermPostureRead)
	}
	if err := s.entitled(ctx, billing.Entitlements.PostureFindings, ErrEdition); err != nil {
		return Listing{}, err
	}
	e, err := s.Ents.Current(ctx)
	if err != nil {
		return Listing{}, err
	}
	offset, err := parseOffset(token)
	if err != nil {
		return Listing{}, err
	}
	v, now, err := s.viewerOf(ctx, c)
	if err != nil {
		return Listing{}, err
	}
	fs, statuses, err := s.collect(ctx, v, f)
	if err != nil {
		return Listing{}, err
	}
	ranked := domain.Rank(fs, now)
	if !e.PostureRemediation() {
		for i := range ranked {
			ranked[i].Fix = ranked[i].Fix.WithoutRemediation()
		}
	}
	out := Listing{Restricted: !v.Posture.Org, Sources: statuses, Total: len(ranked), AsOf: now}
	if size <= 0 {
		size = defaultPageSize
	}
	end := min(offset+int(size), len(ranked))
	if offset < end {
		out.Findings = ranked[offset:end]
	}
	if end < len(ranked) {
		out.Next = offsetToken(end)
	}
	return out, nil
}
