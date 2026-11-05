// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/payments/anchors"
	"github.com/katocxl/pantherclaw/internal/payments/ap2"
	"github.com/katocxl/pantherclaw/internal/payments/caps"
	"github.com/katocxl/pantherclaw/internal/payments/caps/caprpc"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	apsim "github.com/katocxl/pantherclaw/internal/sim/agentpay"
)

// The M39 agent payment actions wiring (G0 M39 D1124, D1124a..D1124d):
// merchant caps are activated through the policy gate's change requests
// (kind PAYMENT_CAP, confirmed by two distinct people with security keys),
// so the caps service registers its apply callback on the server's change
// requests before anything is served; PaymentCapService is served; and
// the Authority verifies payment mandates itself (mandateVerifier).

// paymentCaps are the merchant cap services per server (by pool), built on
// the policy gate's change requests.
var paymentCaps = struct {
	sync.Mutex
	by map[*db.Pool]*caps.Service
}{by: map[*db.Pool]*caps.Service{}}

func init() {
	policyGateExtensions = append(policyGateExtensions, func(d apiDeps, v *policyapp.Versions) {
		svc := &caps.Service{Pool: d.pool, Changes: v.Changes}
		if d.billing != nil {
			svc.Editions = d.billing
		}
		v.Changes.Register(policyapp.ChangePaymentCap, svc.Apply)
		paymentCaps.Lock()
		defer paymentCaps.Unlock()
		paymentCaps.by[d.pool] = svc
	})
}

// paymentCapsOf is the server's merchant cap service, or nil before the
// policy gate is registered (no cap can then be proposed: fail closed).
func paymentCapsOf(pool *db.Pool) *caps.Service {
	paymentCaps.Lock()
	defer paymentCaps.Unlock()
	return paymentCaps.by[pool]
}

// registerM39Pay serves PaymentCapService once the policy gate built the
// caps service; without it nothing is served (fail closed).
func registerM39Pay(rs *connect.Server, d apiDeps) {
	svc := paymentCapsOf(d.pool)
	if svc == nil {
		return
	}
	pantherclawv1connect.RegisterPaymentCapServiceHandler(rs, caprpc.New(svc))
}

// validateAgentPay checks the development-only agent payments settings.
func (c *Config) validateAgentPay() []error {
	if !c.Dev.AgentPaySimRoots {
		return nil
	}
	if err := c.localOnly(); err != nil {
		return []error{fmt.Errorf("dev.agentpay_sim_roots is development-only: %w", err)}
	}
	return nil
}

// Circuits opens a connection's circuit for a reason (capp.Service).
type paymentCircuits interface {
	OpenCircuitFor(ctx context.Context, org ids.OrgID, gateway, id ids.UUID, reason string) (bool, error)
}

// mandateVerifier implements pipeline.PaymentVerifier on the server (G0 M39
// D1124d): the org's ACTIVE anchors (anchors.Service.ForOrg) pinned to the
// connection's merchant audience (ap2.WithAudiences), keys fetched by the
// server's KeySource. A live anchor quarantines the connection with reason
// payments_live_refused. It audits payments.mandate_verified and
// payments.mandate_refused with digests and reason codes only.
type mandateVerifier struct {
	pool    *db.Pool
	anchors *anchors.Service
	log     *slog.Logger

	mu       sync.Mutex
	circuits paymentCircuits
}

// mandateVerifiers are the verifiers per server (by pool), so the
// connections service built later can be bound (bindPaymentCircuits).
var mandateVerifiers = struct {
	sync.Mutex
	by map[*db.Pool]*mandateVerifier
}{by: map[*db.Pool]*mandateVerifier{}}

// newMandateVerifier builds the server's verifier; nil without a pool or a
// public URL (then no payment can be decided: CANNOT_AUTHORIZE).
func newMandateVerifier(cfg *Config, pool *db.Pool, log *slog.Logger) pipeline.PaymentVerifier {
	if pool == nil {
		return nil
	}
	kc := anchors.KeyConfig{}
	if cfg.Dev.AgentPaySimRoots {
		roots, err := apsim.DevRoots()
		if err != nil {
			return nil
		}
		kc.RootCAs = roots // development only (validateAgentPay)
	}
	svc, err := anchors.New(pool, anchors.Config{PublicURL: cfg.Auth.PublicURL, Keys: kc}, clock.System{}, log)
	if err != nil {
		return nil
	}
	if log == nil {
		log = pclog.Discard()
	}
	v := &mandateVerifier{pool: pool, anchors: svc, log: log}
	mandateVerifiers.Lock()
	defer mandateVerifiers.Unlock()
	mandateVerifiers.by[pool] = v
	return v
}

// bindPaymentCircuits gives the pool's verifier the connections service
// that quarantines a connection whose payment left the sandbox.
func bindPaymentCircuits(pool *db.Pool, c paymentCircuits) {
	mandateVerifiers.Lock()
	v := mandateVerifiers.by[pool]
	mandateVerifiers.Unlock()
	if v != nil && c != nil {
		v.mu.Lock()
		v.circuits = c
		v.mu.Unlock()
	}
}

// VerifyMandate implements pipeline.PaymentVerifier.
func (v *mandateVerifier) VerifyMandate(ctx context.Context, org ids.OrgID, connection ids.UUID, raw string, want pipeline.PaymentWant) (ap2.Verified, error) {
	var conn dbq.PcConnection
	var audience string
	err := v.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		if conn, err = q.GetConnection(ctx, org, connection); err != nil {
			return err
		}
		audience, err = q.ConnectionMerchantAudience(ctx, org, connection)
		if db.IsNoRows(err) {
			audience, err = "", nil // no audience: every mandate is refused
		}
		return err
	}, db.ReadOnly())
	if err != nil {
		return ap2.Verified{}, err
	}
	// The merchant endpoint is a sandbox endpoint too (D1124c).
	if conn.BaseUrl == nil || anchors.CheckURL(*conn.BaseUrl) != nil {
		v.quarantine(ctx, org, conn, "endpoint")
		v.refused(ctx, org, connection, pipeline.ReasonPaymentsLiveRefused, "")
		return ap2.Verified{}, ap2.ErrLiveRefused
	}
	resolver, err := v.anchors.ForOrg(ctx, org)
	if err != nil {
		return ap2.Verified{}, err
	}
	got, err := ap2.Verify(ctx, raw, ap2.WithAudiences(resolver, audience), clock.System{}.Now())
	switch {
	case errors.Is(err, ap2.ErrLiveRefused):
		v.quarantine(ctx, org, conn, "mandate")
		v.refused(ctx, org, connection, pipeline.ReasonPaymentsLiveRefused, "")
		return ap2.Verified{}, err
	case errors.Is(err, ap2.ErrInvalid):
		v.log.InfoContext(ctx, "payments.mandate_invalid", slog.String("connection_id", connection.String()), pclog.Err(err))
		v.refused(ctx, org, connection, pipeline.ReasonMandateInvalid, "")
		return ap2.Verified{}, ap2.ErrInvalid
	case err != nil:
		return ap2.Verified{}, err
	}
	if got.AmountMinor != want.AmountMinor || got.Currency != want.Currency || got.Merchant != want.Merchant {
		v.refused(ctx, org, connection, pipeline.ReasonMandateMismatch, got.MandateDigest, "merchant", got.Merchant, "currency", got.Currency)
		return got, nil // the payment step refuses it (MANDATE_MISMATCH)
	}
	v.record(ctx, org, connection, auditkind.PaymentsMandateVerified, audit.Success, "", map[string]string{
		"mandate_digest": got.MandateDigest, "merchant": got.Merchant, "currency": got.Currency,
		"amount_minor": strconv.FormatInt(got.AmountMinor, 10), "version": got.Version,
	})
	return got, nil
}

// quarantine opens the connection's circuit (payments_live_refused).
func (v *mandateVerifier) quarantine(ctx context.Context, org ids.OrgID, conn dbq.PcConnection, where string) {
	v.mu.Lock()
	c := v.circuits
	v.mu.Unlock()
	v.log.WarnContext(ctx, "security.payments_live_refused", slog.String("connection_id", conn.ID.String()), slog.String("seen_in", where))
	if c == nil {
		return
	}
	if _, err := c.OpenCircuitFor(ctx, org, conn.GatewayID, conn.ID, capp.QuarantinePaymentsLive); err != nil {
		v.log.WarnContext(ctx, "payments.quarantine_failed", slog.String("connection_id", conn.ID.String()), pclog.Err(err))
	}
}

// refused audits payments.mandate_refused with the reason and, for a
// mismatch, the digest and the mandate's merchant and currency.
func (v *mandateVerifier) refused(ctx context.Context, org ids.OrgID, connection ids.UUID, reason, digest string, kv ...string) {
	d := map[string]string{"reason": reason}
	if digest != "" {
		d["mandate_digest"] = digest
	}
	for i := 0; i+1 < len(kv); i += 2 {
		d[kv[i]] = kv[i+1]
	}
	v.record(ctx, org, connection, auditkind.PaymentsMandateRefused, audit.Denied, reason, d)
}

func (v *mandateVerifier) record(ctx context.Context, org ids.OrgID, connection ids.UUID, name string, outcome audit.Outcome, reason string, details map[string]string) {
	err := v.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := audit.Record(ctx, tx, audit.Event{
			Name: name, Actor: evdomain.Actor{Type: "system", ID: "authority"}, Outcome: outcome, ReasonCode: reason,
			Object: &audit.Object{Type: "connection", ID: connection.String()}, Details: details,
		})
		return err
	})
	if err != nil {
		v.log.WarnContext(ctx, "payments.audit_failed", slog.String("event", name), pclog.Err(err))
	}
}
