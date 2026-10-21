// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package billing manages the installed licence and the entitlements the
// server enforces (BUILD_GUIDE §8 M1 billing part 1).
//
// Licensing never stops the server and never switches enforcement off: an
// invalid licence means Community limits, an expired one keeps its limits
// for the grace period (see billing/domain). Installs and rejections are
// platform-audit events.
package billing

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/billing/licence"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Service reads and installs licences.
type Service struct {
	pool  *db.Pool
	roots licence.Roots
	clock clock.Clock
	log   *slog.Logger
	orgs  OrgSource
}

// New returns a Service verifying against roots (normally
// licence.EmbeddedRoots()).
func New(pool *db.Pool, roots licence.Roots, clk clock.Clock, log *slog.Logger) *Service {
	return &Service{pool: pool, roots: roots, clock: clk, log: log}
}

// Install verifies doc and makes it the installed licence. Installing the
// licence that is already installed changes nothing. An invalid document is
// recorded as rejected (the server then runs with Community limits), an
// audit event is written, and the verification error is returned.
func (s *Service) Install(ctx context.Context, doc []byte, actor evdomain.Actor) (domain.Entitlements, error) {
	claims, verr := licence.Verify(doc, s.roots)
	err := s.pool.InTenantTx(ctx, ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		cur, err := q.GetLicenceState(ctx)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if verr != nil {
			reason := "LICENCE_INVALID"
			if err := q.PutLicenceState(ctx, dbq.PutLicenceStateParams{RejectedReason: &reason, UpdatedBy: actorString(actor)}); err != nil {
				return err
			}
			_, err := audit.Record(ctx, tx, audit.Event{
				Name: "licence.rejected", Actor: actor, Outcome: audit.Denied, ReasonCode: reason,
			})
			return err
		}
		if cur.Document != nil && bytes.Equal([]byte(*cur.Document), doc) {
			return nil // already installed
		}
		text := string(doc)
		if err := q.PutLicenceState(ctx, dbq.PutLicenceStateParams{Document: &text, LicenceID: &claims.LicenceID, UpdatedBy: actorString(actor)}); err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "licence.installed", Actor: actor, Outcome: audit.Success,
			Object: &audit.Object{Type: "licence", ID: claims.LicenceID},
			Details: map[string]string{
				"edition": string(claims.Edition), "customer_id": claims.CustomerID,
				"expires_at": claims.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
			},
		})
		return err
	})
	if err != nil {
		return domain.Entitlements{}, fmt.Errorf("billing: install licence: %w", err)
	}
	if verr != nil {
		s.log.WarnContext(ctx, "licence.rejected", slog.String("reason_code", "LICENCE_INVALID"))
		return domain.Invalid("verification failed"), verr
	}
	return s.evaluate(ctx, claims), nil
}

// OrgSource resolves the entitlements of the org a context is for (G0 UI
// D9, internal/entitlements). ok is false when the context names no org.
type OrgSource interface {
	OrgEntitlements(ctx context.Context) (e domain.Entitlements, ok bool, err error)
}

// UseOrgEntitlements makes Current per org: every gate and limit that reads
// Current gets the entitlements of the org its context is for, and the
// licence's otherwise. Call it once at start-up, before serving.
func (s *Service) UseOrgEntitlements(src OrgSource) { s.orgs = src }

// Current returns the entitlements in force now for the org ctx is for
// (when UseOrgEntitlements was called), else the installed licence's.
func (s *Service) Current(ctx context.Context) (domain.Entitlements, error) {
	if s.orgs != nil {
		if e, ok, err := s.orgs.OrgEntitlements(ctx); err != nil || ok {
			return e, err
		}
	}
	return s.Licence(ctx)
}

// Licence returns the installed licence's entitlements, whatever org ctx is
// for.
func (s *Service) Licence(ctx context.Context) (domain.Entitlements, error) {
	var st dbq.GetLicenceStateRow
	err := s.pool.InTenantTx(ctx, ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		st, err = dbq.New(tx).GetLicenceState(ctx)
		return err
	}, db.ReadOnly())
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return domain.CommunityEntitlements(), nil
	case err != nil:
		return domain.Entitlements{}, fmt.Errorf("billing: read licence: %w", err)
	case st.RejectedReason != nil:
		return domain.Invalid("rejected at install"), nil
	case st.Document == nil:
		return domain.CommunityEntitlements(), nil
	}
	// Re-verify: the embedded roots may differ from the build that installed it.
	claims, verr := licence.Verify([]byte(*st.Document), s.roots)
	if verr != nil {
		s.log.WarnContext(ctx, "licence.invalid", slog.String("reason_code", "LICENCE_INVALID"))
		return domain.Invalid("installed licence no longer verifies"), nil //nolint:nilerr // an unverifiable licence means Community limits, not a failure
	}
	return s.evaluate(ctx, claims), nil
}

func (s *Service) evaluate(ctx context.Context, c domain.Claims) domain.Entitlements {
	e := domain.Evaluate(c, s.clock.Now())
	if e.Warning != "" {
		s.log.WarnContext(ctx, "licence.warning", slog.String("status", string(e.Status)), slog.String("detail", e.Warning))
	}
	return e
}

func actorString(a evdomain.Actor) string { return a.Type + ":" + a.ID }
