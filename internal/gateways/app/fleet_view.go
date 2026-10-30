// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"strconv"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The fleet use cases (G0 M18 D151, D161): reading and setting the fleet
// policy (the permission CreateGateway uses), the fleet view (gateway
// read), and the silence and version alerts (fleet_sweep.go). Per org only.
// The fleet view needs Team; setting the policy and the alerts need
// Enterprise; reading the policy works in every edition.

// Errors.
var (
	ErrFleetViewEdition   = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "the gateway fleet view needs the Team edition")
	ErrFleetPolicyEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "the gateway fleet policy needs the Enterprise edition")
	ErrMinimumVersion     = pcerr.New(pcerr.InvalidArgument, "INVALID_MINIMUM_VERSION",
		"the minimum version must be vMAJOR.MINOR.PATCH with an optional -prerelease")
	ErrSilenceAfter = pcerr.New(pcerr.InvalidArgument, "INVALID_SILENCE_AFTER",
		"the silence threshold must be a whole number of seconds between 120 and 86400")
)

// Editions reports the licence's entitlements for the org a context is for.
type Editions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// Notifier enqueues a notification in the caller's transaction.
type Notifier interface {
	Enqueue(ctx context.Context, tx db.TenantTx, m napp.Message) (napp.Enqueued, error)
}

// Fleet serves the fleet use cases over the gateway use cases.
type Fleet struct {
	s        *Service
	pool     *db.Pool
	clk      clock.Clock
	editions Editions
	notify   Notifier
}

// NewFleet returns the fleet use cases. Without editions every gated use
// is refused; without a notifier the sweep records alerts but sends none.
func NewFleet(s *Service, editions Editions, notify Notifier) *Fleet {
	return &Fleet{s: s, pool: s.pool, clk: s.clk, editions: editions, notify: notify}
}

func (f *Fleet) entitled(ctx context.Context, gate func(billing.Entitlements) bool, refusal error) error {
	if f.editions == nil {
		return refusal
	}
	e, err := f.editions.Current(ctx)
	if err != nil {
		return err
	}
	if !gate(e) {
		return refusal
	}
	return nil
}

// GetFleetPolicy returns the caller's org's fleet policy (gateway.manage),
// in every edition.
func (f *Fleet) GetFleetPolicy(ctx context.Context) (FleetPolicy, error) {
	c, err := f.s.manager(ctx, td.PermGatewayManage)
	if err != nil {
		return FleetPolicy{}, err
	}
	return f.s.FleetPolicy(ctx, c.Org)
}

// SetFleetPolicy sets the caller's org's fleet policy (gateway.manage). An
// empty minimum clears it; a zero silenceAfter is the default. Setting a
// minimum or changing the threshold needs Enterprise; clearing the minimum
// with the threshold default or unchanged works in every edition, so an
// org that left Enterprise can still remove its policy (D167). The minimum
// is stored normalized and stays advisory (HR-470).
func (f *Fleet) SetFleetPolicy(ctx context.Context, minimum string, silenceAfter time.Duration) (FleetPolicy, error) {
	c, err := f.s.manager(ctx, td.PermGatewayManage)
	if err != nil {
		return FleetPolicy{}, err
	}
	var minText *string
	if minimum != "" {
		v, ok := ParseVersion(minimum)
		if !ok || len(v.String()) > maxVersionLen {
			return FleetPolicy{}, ErrMinimumVersion
		}
		s := v.String()
		minText = &s
	}
	if silenceAfter == 0 {
		silenceAfter = DefaultSilenceAfter
	}
	if silenceAfter < MinSilenceAfter || silenceAfter > MaxSilenceAfter || silenceAfter%time.Second != 0 {
		return FleetPolicy{}, ErrSilenceAfter
	}
	cur, err := f.s.FleetPolicy(ctx, c.Org)
	if err != nil {
		return FleetPolicy{}, err
	}
	if clearing := minText == nil && (silenceAfter == DefaultSilenceAfter || silenceAfter == cur.SilenceAfter); !clearing {
		if err := f.entitled(ctx, billing.Entitlements.FleetPolicy, ErrFleetPolicyEdition); err != nil {
			return FleetPolicy{}, err
		}
	}
	var out FleetPolicy
	err = f.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		r, err := dbq.New(tx).UpsertGatewayFleetPolicy(ctx, dbq.UpsertGatewayFleetPolicyParams{
			OrgID: c.Org, MinimumVersion: minText, SilenceAfterSeconds: int32(silenceAfter / time.Second), //nolint:gosec // G115: 120..86400, checked above
			UpdatedBy: c.Principal.String(), UpdatedAt: f.clk.Now(),
		})
		if err != nil {
			return err
		}
		out = fleetPolicyFromRow(r)
		details := map[string]string{"silence_after_seconds": strconv.Itoa(int(r.SilenceAfterSeconds)), "minimum_version": "none"}
		if minText != nil {
			details["minimum_version"] = *minText
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "gateway.fleet_policy_set", Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "gateway_fleet_policy", ID: c.Org.String()}, Details: details,
		})
		return err
	})
	return out, err
}

// Compliance is how a replica's reported version meets the minimum.
type Compliance int

// Compliance values.
const (
	// NoMinimum: the org set no minimum version.
	NoMinimum Compliance = iota
	// VersionCompliant: the version is at or above the minimum.
	VersionCompliant
	// BelowMinimum: the version is below the minimum.
	BelowMinimum
	// VersionUnknown: the version does not parse, so it never complies.
	VersionUnknown
)

// compliance classifies reported against minimum (HR-470).
func compliance(reported, minimum Version) Compliance {
	switch {
	case !minimum.Known():
		return NoMinimum
	case !reported.Known():
		return VersionUnknown
	case Compliant(reported, minimum):
		return VersionCompliant
	default:
		return BelowMinimum
	}
}

// FleetReplica is one replica in the fleet view.
type FleetReplica struct {
	Replica dbq.PcGatewayReplica
	// Version is the parsed reported version; unknown when it does not parse.
	Version    Version
	Compliance Compliance
	// ConfigLag is how many config versions the replica serves behind the
	// gateway's current one (0 when current).
	ConfigLag int64
}

// FleetGateway is one gateway in the fleet view.
type FleetGateway struct {
	Gateway   dbq.PcGateway
	Replicas  []FleetReplica
	Connected bool
	// SilentSince is set while the sweep holds the gateway silent: the
	// time of its last report before the silence.
	SilentSince *time.Time
	// BelowMinimum is set when some replica's version misses the minimum.
	BelowMinimum bool
}

// FleetView is a page of the fleet view.
type FleetView struct {
	Policy   FleetPolicy
	Gateways []FleetGateway
	Next     string
}

// ListFleet pages through the org's active gateways with their replicas'
// versions, compliance and config lag (gateway.read, Team).
func (f *Fleet) ListFleet(ctx context.Context, size int32, token string) (FleetView, error) {
	c, err := f.s.manager(ctx, td.PermGatewayRead)
	if err != nil {
		return FleetView{}, err
	}
	if err := f.entitled(ctx, billing.Entitlements.FleetView, ErrFleetViewEdition); err != nil {
		return FleetView{}, err
	}
	pr, err := page.Parse(size, token)
	if err != nil {
		return FleetView{}, err
	}
	var out FleetView
	err = f.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		if out.Policy, err = fleetPolicy(ctx, q, c.Org); err != nil {
			return err
		}
		rows, err := q.ListGateways(ctx, dbq.ListGatewaysParams{OrgID: c.Org, AfterID: pr.After, MaxRows: pr.Limit()})
		if err != nil {
			return err
		}
		rows, out.Next = page.Finish(pr, rows, func(g dbq.PcGateway) ids.UUID { return g.ID })
		gws := make([]ids.UUID, 0, len(rows))
		for _, g := range rows {
			gws = append(gws, g.ID)
		}
		st, err := f.s.statuses(ctx, q, c.Org, gws)
		if err != nil {
			return err
		}
		alerts, err := alertStates(ctx, q, c.Org, gws)
		if err != nil {
			return err
		}
		for _, g := range rows {
			fg := FleetGateway{Gateway: g, Connected: st[g.ID].Connected}
			if a, ok := alerts[g.ID]; ok {
				fg.SilentSince = a.SilentSince
			}
			for _, r := range st[g.ID].Replicas {
				v, _ := ParseVersion(r.Version)
				fr := FleetReplica{
					Replica: r, Version: v, Compliance: compliance(v, out.Policy.MinimumVersion),
					ConfigLag: max(g.ConfigVersion-r.ConfigVersion, 0),
				}
				fg.BelowMinimum = fg.BelowMinimum || fr.Compliance == BelowMinimum || fr.Compliance == VersionUnknown
				fg.Replicas = append(fg.Replicas, fr)
			}
			out.Gateways = append(out.Gateways, fg)
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

func alertStates(ctx context.Context, q *dbq.Queries, org ids.OrgID, gws []ids.UUID) (map[ids.UUID]dbq.PcGatewayAlertState, error) {
	out := make(map[ids.UUID]dbq.PcGatewayAlertState, len(gws))
	if len(gws) == 0 {
		return out, nil
	}
	rows, err := q.ListGatewayAlertStates(ctx, org, gws)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.GatewayID] = r
	}
	return out, nil
}
