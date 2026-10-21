// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app holds the PAP/1 workload identity use cases (Badge; PAP-1
// §3–§4, ADR-0013, G0 M3): enrollment tokens, enrollment, admission by the
// owner (HR-094), workload tokens, server nonces and the proof replay store
// (HR-090, HR-091).
//
// Two kinds of caller use it. People and services (authenticated by the
// tenancy interceptor) mint enrollment tokens and decide admissions;
// workloads (authenticated by a PAP/1 proof, pap.Checked) enroll and get
// tokens. A workload request always consumes its proof first, in its own
// committed transaction: the nonce must be live by the database clock, then
// (jkt, jti) is inserted, and a replay finds the row already there.
package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/netip"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// Errors returned to people and services.
var (
	ErrAgentNotFound    = pcerr.New(pcerr.NotFound, "AGENT_NOT_FOUND", "agent not found")
	ErrInstanceNotFound = pcerr.New(pcerr.NotFound, "INSTANCE_NOT_FOUND", "instance not found")
	ErrNotOwner         = pcerr.New(pcerr.PermissionDenied, "NOT_AGENT_OWNER",
		"only the agent's owner or backup owner may do this")
	ErrAgentUnusable = pcerr.New(pcerr.FailedPrecondition, "AGENT_STATE",
		"the agent must be claimed and neither suspended nor retired")
	ErrFingerprint  = pcerr.New(pcerr.FailedPrecondition, "FINGERPRINT_MISMATCH", "the fingerprint does not match the instance's key")
	ErrInstanceGone = pcerr.New(pcerr.FailedPrecondition, "INSTANCE_STATE",
		"the instance is no longer waiting for this decision (decided, revoked or expired)")
	ErrKeyEnrolled = pcerr.New(pcerr.AlreadyExists, "KEY_ENROLLED", "this key is already enrolled in the org")
)

// KeySource gives the workload-token signer and verifier (keys.Registry).
type KeySource interface {
	Signer(keys.Purpose) (*jws.Signer, error)
	Verifier(keys.Purpose, string) (*jws.Verifier, error)
}

// Service serves the identity use cases.
type Service struct {
	pool   *db.Pool
	keys   KeySource
	issuer string
	clk    clock.Clock
	att    Attestors
	floods floods
}

// New returns the identity use cases. issuer is the server's public URL,
// the iss of every workload token.
func New(pool *db.Pool, ks KeySource, issuer string, clk clock.Clock) *Service {
	return &Service{pool: pool, keys: ks, issuer: issuer, clk: clk}
}

// TokenVerifier returns the verifier for workload tokens (PAP-1 §4 step 1).
func (s *Service) TokenVerifier() (*jws.Verifier, error) {
	return s.keys.Verifier(keys.PurposeWorkloadTokens, pap.TokenType)
}

// Issuer returns the workload-token issuer.
func (s *Service) Issuer() string { return s.issuer }

// Nonce returns org's current nonce, creating the nonce of the current
// minute (database clock) on first use (HR-091).
func (s *Service) Nonce(ctx context.Context, org ids.OrgID) (string, error) {
	n, _, err := s.NonceExpiry(ctx, org)
	return n, err
}

// NonceExpiry returns org's current nonce and when it stops being
// accepted: 6 minutes after the start of its minute.
func (s *Service) NonceExpiry(ctx context.Context, org ids.OrgID) (string, time.Time, error) {
	var out string
	var minute int64
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := orgActive(ctx, q, org); err != nil {
			return err
		}
		var err error
		if minute, err = q.CurrentMinute(ctx); err != nil {
			return err
		}
		if out, err = q.GetNonceForMinute(ctx, org, minute); err == nil {
			return nil
		} else if !db.IsNoRows(err) {
			return err
		}
		var b [32]byte
		if _, err := rand.Read(b[:]); err != nil {
			return err
		}
		if err := q.InsertNonce(ctx, org, minute, base64.RawURLEncoding.EncodeToString(b[:])); err != nil {
			return err
		}
		out, err = q.GetNonceForMinute(ctx, org, minute)
		return err
	})
	return out, time.Unix((minute+6)*60, 0), err
}

// Consume records a verified proof (PAP-1 §4 steps 5–6): its nonce must be
// one of org's live nonces, then (jkt, jti) is inserted in the nonce's
// slot. It commits on its own, so a later failure of the request cannot
// make the proof reusable (HR-090, HR-091).
func (s *Service) Consume(ctx context.Context, org ids.OrgID, c pap.Checked) error {
	return s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := orgActive(ctx, q, org); err != nil {
			return err
		}
		minute, err := q.LiveNonceMinute(ctx, org, c.Nonce())
		if db.IsNoRows(err) {
			return pap.Err(pap.CodeUseNonce)
		} else if err != nil {
			return err
		}
		n, err := q.InsertProofJTI(ctx, dbq.InsertProofJTIParams{
			OrgID: org, Slot: pap.Slot(minute), Jkt: c.JKT(), Jti: c.JTI(), NonceMinute: minute,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return pap.Err(pap.CodeProofReplay)
		}
		return nil
	})
}

// network returns the network an address belongs to for HR-092: its /24
// (IPv4) or /56 (IPv6); "" when unknown.
func network(addr string) string {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		if ap, err2 := netip.ParseAddrPort(addr); err2 == nil {
			a = ap.Addr()
		} else {
			return ""
		}
	}
	a = a.Unmap()
	bits := 56
	if a.Is4() {
		bits = 24
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return ""
	}
	return p.String()
}

func instanceActor(id ids.UUID) evdomain.Actor {
	return evdomain.Actor{Type: "instance", ID: id.String()}
}

// recordAs audits an event in tx.
func recordAs(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, name, objType string, obj ids.UUID, details map[string]string) error {
	if details == nil {
		details = map[string]string{}
	}
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: actor, Outcome: audit.Success, Object: &audit.Object{Type: objType, ID: obj.String()}, Details: details,
	})
	return err
}

// callerRecord audits an event made by a person or service.
func callerRecord(ctx context.Context, tx db.TenantTx, c tenancy.Caller, name string, obj ids.UUID, details map[string]string) error {
	if details == nil {
		details = map[string]string{}
	}
	if c.Credential != "" {
		details["via"] = string(c.Credential)
	}
	return recordAs(ctx, tx, c.Actor(), name, "instance", obj, details)
}

// usableAgent loads and locks an agent that can hold instances.
func usableAgent(ctx context.Context, q *dbq.Queries, org ids.OrgID, agent ids.UUID) (dbq.PcAgent, error) {
	a, err := q.LockAgent(ctx, org, agent)
	if db.IsNoRows(err) {
		return a, ErrAgentNotFound
	} else if err != nil {
		return a, err
	}
	if !agentUsable(a) {
		return a, ErrAgentUnusable
	}
	return a, nil
}

// orgActive refuses every workload request of an org that is not ACTIVE:
// a DELETED org (D22) fails closed on the workload path as on every other
// (HR-392). Every workload request takes a nonce and has its proof
// consumed, so the check sits in both, before anything is written.
func orgActive(ctx context.Context, q *dbq.Queries, org ids.OrgID) error {
	state, err := q.OrgState(ctx, org)
	switch {
	case db.IsNoRows(err), err == nil && state != "ACTIVE":
		return pap.Err(pap.CodeInvalidToken)
	case err != nil:
		return err
	}
	return nil
}
