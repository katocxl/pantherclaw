// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Gateway fleet policy (G0 M18 D151, HR-470). Each org may set an advisory
// minimum gateway version and how long a gateway may go without a status
// report before it is alerted as silent. The minimum version is flagged
// and alerted, never enforced: gateways report their version themselves,
// so refusing on it would be no boundary and could only cause outages.
const (
	// DefaultSilenceAfter is the silence threshold of an org without a policy.
	DefaultSilenceAfter = 300 * time.Second
	// MinSilenceAfter and MaxSilenceAfter bound the threshold (00216).
	MinSilenceAfter = 120 * time.Second
	MaxSilenceAfter = 86400 * time.Second
)

// FleetPolicy is one org's gateway fleet policy.
type FleetPolicy struct {
	// MinimumVersion is the advisory minimum; the zero Version means none.
	MinimumVersion Version
	SilenceAfter   time.Duration
	// UpdatedBy and UpdatedAt are empty for the default policy.
	UpdatedBy string
	UpdatedAt time.Time
}

// DefaultFleetPolicy is the policy of an org that never set one.
func DefaultFleetPolicy() FleetPolicy { return FleetPolicy{SilenceAfter: DefaultSilenceAfter} }

func fleetPolicyFromRow(r dbq.PcGatewayFleetPolicy) FleetPolicy {
	p := FleetPolicy{
		SilenceAfter: time.Duration(r.SilenceAfterSeconds) * time.Second,
		UpdatedBy:    r.UpdatedBy, UpdatedAt: r.UpdatedAt,
	}
	if r.MinimumVersion != nil {
		// Only parseable versions are stored (SetFleetPolicy); an
		// unparseable one would read as no minimum.
		p.MinimumVersion, _ = ParseVersion(*r.MinimumVersion)
	}
	return p
}

// FleetPolicy returns org's fleet policy, or the default when it set none.
// It checks no caller permission: it is the read other services use (the
// silence sweep, M19's upgrade roll-out); people use GetFleetPolicy.
func (s *Service) FleetPolicy(ctx context.Context, org ids.OrgID) (FleetPolicy, error) {
	var out FleetPolicy
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = fleetPolicy(ctx, dbq.New(tx), org)
		return err
	})
	return out, err
}

func fleetPolicy(ctx context.Context, q *dbq.Queries, org ids.OrgID) (FleetPolicy, error) {
	r, err := q.GetGatewayFleetPolicy(ctx, org)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultFleetPolicy(), nil
	} else if err != nil {
		return FleetPolicy{}, err
	}
	return fleetPolicyFromRow(r), nil
}
