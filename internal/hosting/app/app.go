// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app holds the use cases of PantherClaw-hosted gateways (G0 M19
// D203, ADR-0041, HR-499..503).
//
// Three kinds of caller use it. People of an org (gateway.manage, human
// only) request one hosted gateway and deprovision it; the provisioner, a
// worker job, creates the org's gateway and a single-use enrollment token
// and places it on a host; and the host agent of a shared host, over its
// own host certificate (no org, purpose "hosting", HR-500), fetches what it
// runs, pulls each token once and reports. The host agent never calls an
// org RPC: its certificate never parses as a gateway identity.
package app

import (
	"context"
	"strconv"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	gwapp "github.com/katocxl/pantherclaw/internal/gateways/app"
	"github.com/katocxl/pantherclaw/internal/gateways/ca"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/hosting/domain"
	"github.com/katocxl/pantherclaw/internal/hosting/profile"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Lister purposes of migration 00229.
const (
	listDue      db.ListerPurpose = "hosting_due"
	listAssigned db.ListerPurpose = "hosting_assigned"
)

// Entitlements reads the edition (Team and above, D203).
type Entitlements interface {
	Current(context.Context) (billing.Entitlements, error)
}

// Service serves the hosted gateway use cases.
type Service struct {
	pool *db.Pool
	ca   *ca.Authority
	env  *pccrypto.Envelope
	ents Entitlements
	clk  clock.Clock
	// gatewayAPIURL is the server's gateway listener, told to hosted
	// gateways with their token.
	gatewayAPIURL string
	// fleet reads an org's fleet policy, whose minimum version is the target
	// of its hosted gateway's upgrades (nil: none, as on the worker).
	fleet FleetPolicies
}

// FleetPolicies reads an org's fleet policy (M18's gateways Service).
type FleetPolicies interface {
	FleetPolicy(ctx context.Context, org ids.OrgID) (gwapp.FleetPolicy, error)
}

// WithFleet sets the fleet policy read upgrades roll toward.
func (s *Service) WithFleet(f FleetPolicies) *Service { s.fleet = f; return s }

// New returns the hosted gateway use cases.
func New(pool *db.Pool, authority *ca.Authority, env *pccrypto.Envelope, ents Entitlements, gatewayAPIURL string, clk clock.Clock) *Service {
	if clk == nil {
		clk = clock.System{}
	}
	return &Service{pool: pool, ca: authority, env: env, ents: ents, clk: clk, gatewayAPIURL: gatewayAPIURL}
}

func (s *Service) manager(ctx context.Context, p td.Permission) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	return c, c.Require(p, td.OrgPath(c.Org))
}

func record(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, name string, hosted ids.UUID, details map[string]string) error {
	if details == nil {
		details = map[string]string{}
	}
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: actor, Outcome: audit.Success, Object: &audit.Object{Type: "hosted_gateway", ID: hosted.String()}, Details: details,
	})
	return err
}

// systemActor records what the provisioner does.
var systemActor = evdomain.Actor{Type: "system", ID: "hosting"}

func hostActor(h ids.UUID) evdomain.Actor {
	return evdomain.Actor{Type: "hosting_host", ID: h.String()}
}

// Request asks for the org's hosted gateway (gateway.manage, Team and
// above): one per org (HR-499), with a slug that names it as
// <slug>.gw.<domain> and resources within the plan's quota. The
// provisioner picks it up.
func (s *Service) Request(ctx context.Context, slug string, asked profile.Limits) (dbq.PcHostedGateway, error) {
	c, err := s.manager(ctx, td.PermGatewayManage)
	if err != nil {
		return dbq.PcHostedGateway{}, err
	}
	if !domain.ValidSlug(slug) {
		return dbq.PcHostedGateway{}, domain.ErrSlug
	}
	if s.ents == nil {
		return dbq.PcHostedGateway{}, domain.ErrEdition
	}
	e, err := s.ents.Current(ctx)
	if err != nil {
		return dbq.PcHostedGateway{}, domain.ErrEdition
	}
	l, err := domain.Fit(e, asked)
	if err != nil {
		return dbq.PcHostedGateway{}, err
	}
	if err := s.pool.InGlobalTx(ctx, db.GlobalHosting, func(ctx context.Context, tx db.GlobalTx) error {
		held, err := dbq.New(tx).HostingSlugHeld(ctx, slug)
		if err == nil && held {
			return domain.ErrSlugTaken
		}
		return err
	}); err != nil {
		return dbq.PcHostedGateway{}, err
	}
	var out dbq.PcHostedGateway
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := q.LiveHostedGateway(ctx, c.Org); err == nil {
			return domain.ErrOneOnly
		} else if !db.IsNoRows(err) {
			return err
		}
		h, err := q.InsertHostedGateway(ctx, dbq.InsertHostedGatewayParams{
			OrgID: c.Org, ID: ids.NewV7(), Slug: slug, MilliCpus: int32(l.MilliCPUs), MemoryMib: int32(l.MemoryMiB), Pids: int32(l.PIDs), //nolint:gosec // G115: within the profile's ceilings (domain.Fit)
			CreatedBy: c.Principal.String(),
		})
		if db.IsUniqueViolation(err) {
			return domain.ErrOneOnly
		} else if err != nil {
			return err
		}
		out = h
		return record(ctx, tx, c.Actor(), "hosted_gateway.requested", h.ID, map[string]string{
			"slug": slug, "milli_cpus": strconv.Itoa(l.MilliCPUs), "memory_mib": strconv.Itoa(l.MemoryMiB), "pids": strconv.Itoa(l.PIDs),
		})
	})
	return out, err
}

// Get returns one of the org's hosted gateways (gateway.read).
func (s *Service) Get(ctx context.Context, id ids.UUID) (dbq.PcHostedGateway, error) {
	c, err := s.manager(ctx, td.PermGatewayRead)
	if err != nil {
		return dbq.PcHostedGateway{}, err
	}
	var out dbq.PcHostedGateway
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = dbq.New(tx).GetHostedGateway(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return domain.ErrNotFound
		}
		return err
	})
	return out, err
}

// List pages through the org's hosted gateway records (gateway.read).
func (s *Service) List(ctx context.Context, size int32, token string) ([]dbq.PcHostedGateway, string, error) {
	c, err := s.manager(ctx, td.PermGatewayRead)
	if err != nil {
		return nil, "", err
	}
	pr, err := page.Parse(size, token)
	if err != nil {
		return nil, "", err
	}
	var (
		rows []dbq.PcHostedGateway
		next string
	)
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err = dbq.New(tx).ListHostedGateways(ctx, c.Org, pr.After, pr.Limit())
		if err != nil {
			return err
		}
		rows, next = page.Finish(pr, rows, func(h dbq.PcHostedGateway) ids.UUID { return h.ID })
		return nil
	})
	return rows, next, err
}

// Deprovision stops the org's hosted gateway (gateway.manage). In one
// transaction it first raises the org's containment epoch and revokes the
// gateway with every certificate and broker key it holds, so its next call
// and every permit it holds fail, and only then marks the record for its
// host agent to stop the process (HR-503).
func (s *Service) Deprovision(ctx context.Context, id ids.UUID, reason string) (dbq.PcHostedGateway, error) {
	c, err := s.manager(ctx, td.PermGatewayManage)
	if err != nil {
		return dbq.PcHostedGateway{}, err
	}
	var out dbq.PcHostedGateway
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		h, err := q.LockHostedGateway(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return domain.ErrNotFound
		} else if err != nil {
			return err
		}
		revoked, err := revokeFirst(ctx, q, c.Org, h, c.Principal.String(), reason)
		if err != nil {
			return err
		}
		out, err = q.StartDeprovisionHostedGateway(ctx, c.Org, id)
		if db.IsNoRows(err) {
			out = h // already deprovisioning or done: nothing more
			return nil
		} else if err != nil {
			return err
		}
		return record(ctx, tx, c.Actor(), "hosted_gateway.deprovisioned", id, map[string]string{
			"state": out.State, "gateway_revoked": strconv.FormatBool(revoked),
		})
	})
	return out, err
}

// revokeFirst raises the containment epoch first in the transaction
// (HR-002) and revokes the hosted gateway's gateway, its certificates and
// broker keys (HR-503). A record not yet provisioned has none.
func revokeFirst(ctx context.Context, q *dbq.Queries, org ids.OrgID, h dbq.PcHostedGateway, by, reason string) (bool, error) {
	if h.GatewayID == nil {
		return false, nil
	}
	if err := q.InsertContainment(ctx, org); err != nil {
		return false, err
	}
	if _, err := q.BumpEpoch(ctx, org); err != nil {
		return false, err
	}
	if reason == "" {
		reason = "hosted gateway deprovisioned"
	}
	if _, err := q.RevokeGateway(ctx, dbq.RevokeGatewayParams{RevokedBy: by, Reason: reason, OrgID: org, ID: *h.GatewayID}); err != nil && !db.IsNoRows(err) {
		return false, err // NoRows: already revoked
	}
	if _, err := q.RevokeGatewayCerts(ctx, "hosted_gateway_deprovisioned", org, *h.GatewayID); err != nil {
		return false, err
	}
	if _, err := q.RetireBrokerKeys(ctx, org, *h.GatewayID); err != nil {
		return false, err
	}
	return true, nil
}

// IsHosted reports whether PantherClaw hosts a gateway: a hosted gateway
// record names it (migration 00229), whatever its state, so that a gateway
// once hosted never takes connectors (HR-084). It runs in the caller's
// tenant transaction.
func IsHosted(ctx context.Context, q *dbq.Queries, org ids.OrgID, gateway ids.UUID) (bool, error) {
	return q.IsHostedGateway(ctx, org, gateway)
}
