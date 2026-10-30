// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app holds the gateway use cases (G0 M6, HR-180..182): gateway
// records, single-use enrollment tokens, certificates from the internal CA
// and broker keys.
//
// Two kinds of caller use it. People (gateway.manage is human only) create
// gateways, mint enrollment tokens and revoke; gateways enroll with a token
// and, over mTLS, renew their certificate and register their broker key.
// Authenticate is what the gateway listener runs on every call (HR-181).
package app

import (
	"context"
	"strconv"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/connections/ports"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gateways/ca"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Limits (G0 M6 design decision 1).
const (
	// EnrollmentTTL is how long an enrollment token works.
	EnrollmentTTL = 15 * time.Minute
	// SupersededGrace is how long a certificate replaced by a renewal is
	// still accepted, so calls in flight finish.
	SupersededGrace = 10 * time.Minute
)

// Errors.
var (
	ErrGatewayNotFound = pcerr.New(pcerr.NotFound, "GATEWAY_NOT_FOUND", "gateway not found")
	ErrCertNotFound    = pcerr.New(pcerr.NotFound, "GATEWAY_CERTIFICATE_NOT_FOUND", "gateway certificate not found")
	ErrGatewayRevoked  = pcerr.New(pcerr.FailedPrecondition, "GATEWAY_REVOKED", "the gateway is revoked")
	ErrNameTaken       = pcerr.New(pcerr.AlreadyExists, "GATEWAY_NAME_TAKEN", "an active gateway already has this name")
	// ErrEnrollment is the one answer to every failed enrollment, so that a
	// caller learns nothing about which check failed.
	ErrEnrollment = pcerr.New(pcerr.Unauthenticated, "GATEWAY_ENROLLMENT_REFUSED", "gateway enrollment refused")
	// ErrGatewayCredentials is the one answer to every failed mTLS
	// authentication (HR-181).
	ErrGatewayCredentials = pcerr.New(pcerr.Unauthenticated, "GATEWAY_CREDENTIALS", "gateway credentials required")
)

// Service serves the gateway use cases.
type Service struct {
	pool          *db.Pool
	ca            *ca.Authority
	clk           clock.Clock
	gatewayAPIURL string
	auth          authCache
	// hosted are the PantherClaw-hosted gateways (hosting.go).
	hosted map[ids.UUID]bool
	// kinds load the M14 kinds' configurations (kinds_m14.go).
	kinds *ports.KindConfigs
}

// New returns the gateway use cases. gatewayAPIURL is the URL of the
// server's gateway listener, told to gateways at enrollment.
func New(pool *db.Pool, authority *ca.Authority, gatewayAPIURL string, clk clock.Clock) *Service {
	if clk == nil {
		clk = clock.System{}
	}
	return &Service{pool: pool, ca: authority, clk: clk, gatewayAPIURL: gatewayAPIURL, auth: newAuthCache()}
}

// CA returns the internal certificate authority.
func (s *Service) CA() *ca.Authority { return s.ca }

func (s *Service) manager(ctx context.Context, p td.Permission) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	return c, c.Require(p, td.OrgPath(c.Org))
}

func record(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, name string, gateway ids.UUID, details map[string]string) error {
	if details == nil {
		details = map[string]string{}
	}
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: actor, Outcome: audit.Success, Object: &audit.Object{Type: "gateway", ID: gateway.String()}, Details: details,
	})
	return err
}

// systemActor records events no person or gateway caused.
var systemActor = evdomain.Actor{Type: "system", ID: "gateways"}

func gatewayActor(id ca.Identity) evdomain.Actor {
	return evdomain.Actor{Type: "gateway", ID: id.Gateway.String()}
}

// CreateGateway adds a gateway record (gateway.manage, human only).
func (s *Service) CreateGateway(ctx context.Context, name string) (dbq.PcGateway, error) {
	c, err := s.manager(ctx, td.PermGatewayManage)
	if err != nil {
		return dbq.PcGateway{}, err
	}
	var out dbq.PcGateway
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		g, err := dbq.New(tx).InsertGateway(ctx, dbq.InsertGatewayParams{OrgID: c.Org, ID: ids.NewV7(), Name: name, CreatedBy: c.Principal.String()})
		if db.IsUniqueViolation(err) {
			return ErrNameTaken
		} else if err != nil {
			return err
		}
		out = g
		return record(ctx, tx, c.Actor(), "gateway.created", g.ID, map[string]string{"name": name})
	})
	return out, err
}

// ErrGatewayHosted: PantherClaw runs this gateway, and only its provisioner
// mints its enrollment tokens.
var ErrGatewayHosted = pcerr.New(pcerr.FailedPrecondition, "GATEWAY_HOSTED", "this gateway is PantherClaw-hosted and cannot be enrolled by hand")

// EnrollmentToken is a minted token; Secret is shown once.
type EnrollmentToken struct {
	Secret        credential.Token
	ExpiresAt     time.Time
	CAFingerprint string
	GatewayAPIURL string
}

// CreateEnrollmentToken mints a single-use pcg_ token for an active
// gateway, stored only as SHA-256 (HR-180).
func (s *Service) CreateEnrollmentToken(ctx context.Context, gateway ids.UUID) (EnrollmentToken, error) {
	c, err := s.manager(ctx, td.PermGatewayManage)
	if err != nil {
		return EnrollmentToken{}, err
	}
	var out EnrollmentToken
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		g, err := q.LockGateway(ctx, c.Org, gateway)
		if db.IsNoRows(err) {
			return ErrGatewayNotFound
		} else if err != nil {
			return err
		}
		if g.State != "ACTIVE" {
			return ErrGatewayRevoked
		}
		// Only the provisioner enrolls a hosted gateway (G0 M19 D219).
		if hosted, err := q.IsHostedGateway(ctx, c.Org, g.ID); err != nil {
			return err
		} else if hosted {
			return ErrGatewayHosted
		}
		tok, err := credential.New(credential.GatewayEnrollmentToken, "", c.Org)
		if err != nil {
			return err
		}
		r, err := q.InsertGatewayEnrollmentToken(ctx, dbq.InsertGatewayEnrollmentTokenParams{
			OrgID: c.Org, ID: ids.NewV7(), GatewayID: g.ID, TokenHash: tok.Hash(), CreatedBy: c.Principal.String(),
			TtlMinutes: int32(EnrollmentTTL / time.Minute),
		})
		if err != nil {
			return err
		}
		out = EnrollmentToken{Secret: tok, ExpiresAt: r.ExpiresAt, CAFingerprint: ca.Fingerprint(s.ca.Certificate()), GatewayAPIURL: s.gatewayAPIURL}
		return record(ctx, tx, c.Actor(), "gateway.enrollment_issued", g.ID, map[string]string{"enrollment_id": r.ID.String()})
	})
	return out, err
}

// ListGateways pages through the org's gateways (gateway.read), with what
// their replicas reported (G0 M15 D10), keyed by gateway.
func (s *Service) ListGateways(ctx context.Context, size int32, token string, includeRevoked bool,
) ([]dbq.PcGateway, map[ids.UUID]GatewayStatus, string, error) {
	c, err := s.manager(ctx, td.PermGatewayRead)
	if err != nil {
		return nil, nil, "", err
	}
	pr, err := page.Parse(size, token)
	if err != nil {
		return nil, nil, "", err
	}
	var (
		rows     []dbq.PcGateway
		statuses map[ids.UUID]GatewayStatus
		next     string
	)
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if rows, err = q.ListGateways(ctx, dbq.ListGatewaysParams{OrgID: c.Org, IncludeRevoked: includeRevoked, AfterID: pr.After, MaxRows: pr.Limit()}); err != nil {
			return err
		}
		rows, next = page.Finish(pr, rows, func(g dbq.PcGateway) ids.UUID { return g.ID })
		gws := make([]ids.UUID, 0, len(rows))
		for _, g := range rows {
			gws = append(gws, g.ID)
		}
		statuses, err = s.statuses(ctx, q, c.Org, gws)
		return err
	})
	if err != nil {
		return nil, nil, "", err
	}
	return rows, statuses, next, nil
}

// GatewayDetail is a gateway with its certificates and broker keys.
type GatewayDetail struct {
	Gateway      dbq.PcGateway
	Certificates []dbq.PcGatewayCert
	BrokerKeys   []dbq.PcBrokerKey
	// Status is what its replicas reported (G0 M15 D10).
	Status GatewayStatus
}

// GetGateway returns one gateway (gateway.read); another org's is NotFound.
func (s *Service) GetGateway(ctx context.Context, id ids.UUID) (GatewayDetail, error) {
	c, err := s.manager(ctx, td.PermGatewayRead)
	if err != nil {
		return GatewayDetail{}, err
	}
	var out GatewayDetail
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		g, err := q.GetGateway(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrGatewayNotFound
		} else if err != nil {
			return err
		}
		out.Gateway = g
		if out.Certificates, err = q.ListGatewayCerts(ctx, c.Org, id); err != nil {
			return err
		}
		if out.BrokerKeys, err = q.ListBrokerKeys(ctx, c.Org, id); err != nil {
			return err
		}
		st, err := s.statuses(ctx, q, c.Org, []ids.UUID{id})
		out.Status = st[id]
		return err
	})
	return out, err
}

// RevokeGateway revokes a gateway and every certificate it holds, retires
// its broker keys, whose private key may have left with it, so nothing is
// sealed to them again (HR-182), and raises the containment epoch so that
// its outstanding permits fail BeginDispatch (HR-002). Its next call is
// refused (HR-181).
func (s *Service) RevokeGateway(ctx context.Context, id ids.UUID, reason string) (dbq.PcGateway, error) {
	c, err := s.manager(ctx, td.PermGatewayManage)
	if err != nil {
		return dbq.PcGateway{}, err
	}
	var out dbq.PcGateway
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := bumpEpoch(ctx, q, c.Org); err != nil {
			return err
		}
		g, err := q.RevokeGateway(ctx, dbq.RevokeGatewayParams{RevokedBy: c.Principal.String(), Reason: reason, OrgID: c.Org, ID: id})
		if db.IsNoRows(err) {
			if _, gerr := q.GetGateway(ctx, c.Org, id); db.IsNoRows(gerr) {
				return ErrGatewayNotFound
			}
			return ErrGatewayRevoked
		} else if err != nil {
			return err
		}
		n, err := q.RevokeGatewayCerts(ctx, "gateway_revoked", c.Org, id)
		if err != nil {
			return err
		}
		keys, err := q.RetireBrokerKeys(ctx, c.Org, id)
		if err != nil {
			return err
		}
		out = g
		return record(ctx, tx, c.Actor(), "gateway.revoked", id, map[string]string{
			"certificates": strconv.FormatInt(n, 10), "broker_keys": strconv.FormatInt(keys, 10),
		})
	})
	if err == nil {
		s.auth.forgetGateway(id)
	}
	return out, err
}

// RevokeCertificate revokes one certificate of a gateway (one replica).
func (s *Service) RevokeCertificate(ctx context.Context, gateway, cert ids.UUID) error {
	c, err := s.manager(ctx, td.PermGatewayManage)
	if err != nil {
		return err
	}
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		n, err := q.RevokeGatewayCert(ctx, dbq.RevokeGatewayCertParams{Reason: "revoked", OrgID: c.Org, GatewayID: gateway, ID: cert})
		if err != nil {
			return err
		}
		if n == 0 {
			r, err := q.LockGatewayCert(ctx, c.Org, cert)
			if db.IsNoRows(err) || (err == nil && r.GatewayID != gateway) {
				return ErrCertNotFound
			}
			return err // already revoked: nothing to do
		}
		if err := bumpEpoch(ctx, q, c.Org); err != nil {
			return err
		}
		return record(ctx, tx, c.Actor(), "gateway.certificate_revoked", gateway, map[string]string{"certificate_id": cert.String()})
	})
	if err == nil {
		s.auth.forget(cert)
	}
	return err
}

// bumpEpoch raises the org's containment epoch first in its transaction
// (HR-002), creating the row on first use.
func bumpEpoch(ctx context.Context, q *dbq.Queries, org ids.OrgID) error {
	if err := q.InsertContainment(ctx, org); err != nil {
		return err
	}
	_, err := q.BumpEpoch(ctx, org)
	return err
}
