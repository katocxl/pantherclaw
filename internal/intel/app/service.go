// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app serves shared threat-intel indicators (G0 M38 D1103..D1105;
// FD13, FQ38-2; HR-817..822): an org's consume mode and share switch, its
// matches and contributions, the STIX export, the feed import and fetch,
// and the matching that discovery and drift call.
//
// Consume and share are off by default (HR-820). Consuming needs the
// Business edition or above; contributing works on every edition. A match
// holds a call for a person or only alerts, and never refuses (HR-819).
// Only hashes enter or leave (HR-818).
package app

import (
	"context"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	bdomain "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/intel/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/protect"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors.
var (
	ErrMode    = pcerr.New(pcerr.InvalidArgument, "INTEL_MODE_INVALID", "the consume mode is not OFF, HOLD or ALERT_ONLY")
	ErrEdition = pcerr.New(pcerr.FailedPrecondition, "INTEL_EDITION",
		"consuming shared indicators needs the Business edition or above")
	errEditionUnknown = pcerr.New(pcerr.Unavailable, "EDITION_UNKNOWN", "the edition could not be read")
	ErrShareOff       = pcerr.New(pcerr.FailedPrecondition, "INTEL_SHARE_OFF", "the org's share switch is off")
	ErrHuman          = pcerr.New(pcerr.PermissionDenied, "INTEL_HUMAN_ONLY", "only a person may contribute an indicator")
	ErrSource         = pcerr.New(pcerr.FailedPrecondition, "INTEL_SOURCE_NOT_CONFIRMED",
		"the source is not a confirmed finding of that kind: a quarantined server, package or tool, or a flagged description")
	ErrSourceMissing = pcerr.New(pcerr.NotFound, "INTEL_SOURCE_NOT_FOUND", "the source was not found")
	ErrSeverity      = pcerr.New(pcerr.InvalidArgument, "INTEL_SEVERITY_INVALID", "the severity is not LOW, MEDIUM or HIGH")
	ErrTechnique     = pcerr.New(pcerr.InvalidArgument, "INTEL_TECHNIQUE_INVALID",
		"a technique is not an ATT&CK or ATLAS id, or there are more than 16")
	ErrPage = pcerr.New(pcerr.InvalidArgument, "INTEL_PAGE_INVALID", "the page token is not a match id")
)

// Editions reports the current edition (billing.Service).
type Editions interface {
	Current(ctx context.Context) (bdomain.Entitlements, error)
}

// Service serves an org's intel settings, matches and contributions.
type Service struct {
	Pool *db.Pool
	// Ents gates consuming; nil allows none of it.
	Ents Editions
	// Now is the clock of the STIX export; nil is time.Now.
	Now func() time.Time
	// Protect holds a loosening of the consume mode for a second person
	// (RegisterProtect, D1104a); nil refuses it.
	Protect *protect.Gate
}

// Settings are an org's choices; no row is OFF and not shared.
type Settings struct {
	Consume   domain.Mode
	Share     bool
	UpdatedBy string
	UpdatedAt time.Time
}

// Feed is the deployment's current feed.
type Feed struct {
	Version    uint64
	KID        string
	Issued     time.Time
	Expires    time.Time
	Indicators int32
}

// Overview is GetIntelSettings' answer.
type Overview struct {
	Settings         Settings
	Feed             *Feed
	ConsumeAvailable bool
}

func caller(ctx context.Context, p td.Permission) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return tenancy.Caller{}, err
	}
	return c, c.Require(p, td.OrgPath(c.Org))
}

// ReadSettings reads an org's settings in tx; no row is OFF.
func ReadSettings(ctx context.Context, q *dbq.Queries, org ids.OrgID) (Settings, error) {
	row, err := q.GetIntelSettings(ctx, org)
	if db.IsNoRows(err) {
		return Settings{Consume: domain.ModeOff}, nil
	} else if err != nil {
		return Settings{}, err
	}
	m := domain.Mode(row.Consume)
	if !m.Valid() {
		m = domain.ModeOff
	}
	return Settings{Consume: m, Share: row.Share, UpdatedBy: row.UpdatedBy, UpdatedAt: row.UpdatedAt}, nil
}

// consumeAvailable reports whether the edition allows consuming.
func (s *Service) consumeAvailable(ctx context.Context) (bool, error) {
	if s.Ents == nil {
		return false, nil
	}
	e, err := s.Ents.Current(ctx)
	if err != nil {
		return false, errEditionUnknown
	}
	return e.IntelConsume(), nil
}

// Get returns the org's settings and the deployment's current feed.
func (s *Service) Get(ctx context.Context) (Overview, error) {
	c, err := caller(ctx, td.PermIntelRead)
	if err != nil {
		return Overview{}, err
	}
	var out Overview
	if out.ConsumeAvailable, err = s.consumeAvailable(ctx); err != nil {
		return Overview{}, err
	}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if out.Settings, err = ReadSettings(ctx, q, c.Org); err != nil {
			return err
		}
		st, err := q.GetIntelState(ctx)
		if db.IsNoRows(err) {
			return nil
		} else if err != nil {
			return err
		}
		n, err := q.CountIntelIndicators(ctx)
		if err != nil {
			return err
		}
		out.Feed = &Feed{
			Version: uint64(st.FeedVersion), KID: st.Kid, Issued: st.IssuedAt, Expires: st.ExpiresAt, Indicators: n, //nolint:gosec // G115: the column is >= 1
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// Match is one recorded match.
type Match = dbq.ListIntelMatchesRow

// ListMatches pages the org's matches, newest first.
func (s *Service) ListMatches(ctx context.Context, size int32, token string) ([]Match, string, error) {
	c, err := caller(ctx, td.PermIntelRead)
	if err != nil {
		return nil, "", err
	}
	var before *ids.UUID
	if token != "" {
		id, err := ids.ParseUUID(token)
		if err != nil {
			return nil, "", ErrPage
		}
		before = &id
	}
	if size <= 0 || size > 200 {
		size = 50
	}
	var rows []Match
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err = dbq.New(tx).ListIntelMatches(ctx, c.Org, before, size)
		return err
	}, db.ReadOnly())
	if err != nil {
		return nil, "", err
	}
	next := ""
	if int32(len(rows)) == size { //nolint:gosec // G115: at most 200 rows
		next = rows[len(rows)-1].ID.String()
	}
	return rows, next, nil
}

// Contribution is one contributed indicator.
type Contribution struct {
	ID         ids.UUID
	Kind       domain.Kind
	SHA256     string
	Shingles   []string
	Severity   domain.Severity
	Techniques []string
	CreatedDay string
	State      string
}

func dayOf(d pgtype.Date) string {
	if !d.Valid {
		return ""
	}
	return d.Time.Format(time.DateOnly)
}

// ListContributions lists the org's contributions, newest first.
func (s *Service) ListContributions(ctx context.Context) ([]Contribution, error) {
	c, err := caller(ctx, td.PermIntelRead)
	if err != nil {
		return nil, err
	}
	var out []Contribution
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListIntelContributions(ctx, c.Org)
		if err != nil {
			return err
		}
		out = make([]Contribution, 0, len(rows))
		for _, r := range rows {
			out = append(out, Contribution{
				ID: r.ID, Kind: domain.Kind(r.Kind), SHA256: deref(r.Sha256), Shingles: r.Shingles,
				Severity: domain.Severity(r.Severity), Techniques: r.Techniques, CreatedDay: dayOf(r.CreatedDay), State: r.State,
			})
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// Indicators reads the current indicators in tx.
func Indicators(ctx context.Context, q *dbq.Queries) ([]domain.Indicator, error) {
	rows, err := q.ListIntelIndicators(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Indicator, 0, len(rows))
	for _, r := range rows {
		out = append(out, domain.Indicator{
			ID: r.ID, Kind: domain.Kind(r.Kind), SHA256: deref(r.Sha256), Shingles: r.Shingles,
			Severity: domain.Severity(r.Severity), Techniques: r.Techniques, FirstSeen: dayOf(r.FirstSeen), Summary: r.Summary,
		})
	}
	return out, nil
}

// ExportSTIX returns the current indicators as a STIX 2.1 bundle.
func (s *Service) ExportSTIX(ctx context.Context) ([]byte, error) {
	c, err := caller(ctx, td.PermIntelRead)
	if err != nil {
		return nil, err
	}
	var in []domain.Indicator
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		in, err = Indicators(ctx, dbq.New(tx))
		return err
	}, db.ReadOnly())
	if err != nil {
		return nil, err
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	return domain.STIX(in, now())
}

// validTechniques checks a contribution's techniques.
func validTechniques(in []string) bool {
	return len(in) <= domain.MaxTechniques && !slices.ContainsFunc(in, func(t string) bool { return !domain.ValidTechnique(t) })
}
