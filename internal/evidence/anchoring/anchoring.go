// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package anchoring runs the anchored global root of the evidence ledger
// (G0 M7 design decision 12, HR-195, PAP-1 §9.4). Every anchoring period
// (evidence.anchoring.interval, an hour by default) it:
//
//  1. lists the active orgs through the audited cross-org lister (purpose
//     "orgs") and reads each one's latest checkpoint in its own tenant
//     transaction;
//  2. draws a fresh 32-byte nonce per org and computes its blinded leaf
//     SHA-256(0x00 ‖ "pantherclaw.anchor-leaf.v1" ‖ nonce ‖
//     SHA-256(checkpoint note)), so a quiet org's leaf still changes and no
//     leaf shows which org it belongs to or whether it was active;
//  3. builds the global tree over the leaves ordered by their own value,
//     signs the anchor statement with the anchors key (ECDSA P-256) and
//     stores the anchor (pc.anchors: blinded leaves and the root only) and
//     each org's leaf, nonce and checkpoint (its anchor_leaves row);
//  4. enters the statement in the configured Rekor v2 log as a
//     hashedrekord v0.0.2 entry and checks the returned inclusion proof and
//     log checkpoint against the configured key and origin, then has the
//     configured RFC 3161 authority timestamp the signature and checks the
//     token against the configured chain. Only then is the anchor
//     ANCHORED; any failure leaves it FAILED, retried with backoff, logged
//     as evidence.anchor_failed and recorded in the platform audit.
//
// Nothing here is on the authorization path: the job runs in the worker,
// reads checkpoints and writes only anchors, anchor leaves and the
// platform audit, so a slow or failing log or authority never delays or
// changes a decision (design decision 20). Rekor and timestamp responses
// are never logged; logs carry ids, codes and digests.
package anchoring

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/anchor"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/merkle"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Defaults and limits.
const (
	// DefaultInterval is evidence.anchoring.interval's default.
	DefaultInterval = time.Hour
	// MaxAttempts bounds the attempts to log and timestamp one anchor; the
	// next period's anchor covers the orgs again anyway.
	MaxAttempts = 8
	// MaxOrgs bounds the orgs of one anchor (one cross-org listing).
	MaxOrgs = 10_000
	// firstBackoff doubles after every failed attempt, up to maxBackoff.
	firstBackoff = time.Minute
	maxBackoff   = 30 * time.Minute
	// maxDuePerTick bounds the anchors one tick logs and timestamps.
	maxDuePerTick = 4
	// rekorTimeout allows for Rekor v2 answering once a checkpoint covers
	// the entry.
	rekorTimeout = 90 * time.Second
	tsaTimeout   = 30 * time.Second
)

// Failure codes: anchors.error_code and the evidence.anchor_failed event.
const (
	// CodeKeyUnavailable: the anchors key that signed the statement is no
	// longer in the registry (revoked).
	CodeKeyUnavailable = "KEY_UNAVAILABLE"
	// CodeRekorFailed: the log could not be reached or refused the entry.
	CodeRekorFailed = "REKOR_FAILED"
	// CodeRekorInvalid: the log's answer does not verify (inclusion proof,
	// checkpoint signature or origin, or another entry).
	CodeRekorInvalid = "REKOR_INVALID"
	// CodeTimestampFailed: the authority could not be reached or refused.
	CodeTimestampFailed = "TIMESTAMP_FAILED"
	// CodeTimestampInvalid: the token does not verify against the chain,
	// does not cover the signature or answers another nonce, or predates
	// the anchoring period.
	CodeTimestampInvalid = "TIMESTAMP_INVALID"
)

// Actor records anchor failures in the platform audit.
var Actor = domain.Actor{Type: "system", ID: "evidence-anchoring"}

// ErrNoSigner reports a missing active anchors key.
var ErrNoSigner = errors.New("anchoring: no active anchors key")

// Service anchors the orgs' checkpoints.
type Service struct {
	Pool *db.Pool
	Keys *keys.Registry
	// LogOrigin is evidence.log_origin, the statement's origin.
	LogOrigin string
	// Interval is the anchoring period (evidence.anchoring.interval).
	Interval time.Duration
	Rekor    *anchor.RekorClient
	TSA      *anchor.TSAClient
	// Clock defaults to the system clock.
	Clock clock.Clock
	Log   *slog.Logger
	// MaxOrgs caps the orgs listed (0: MaxOrgs).
	MaxOrgs int
}

func (s *Service) now() time.Time {
	if s.Clock == nil {
		return time.Now().UTC()
	}
	return s.Clock.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Log == nil {
		return pclog.Discard()
	}
	return s.Log
}

func (s *Service) interval() time.Duration {
	if s.Interval <= 0 {
		return DefaultInterval
	}
	return s.Interval
}

// Period returns the start of the anchoring period that contains t.
func (s *Service) Period(t time.Time) time.Time { return t.UTC().Truncate(s.interval()) }

// orgLeaf is one org's part of an anchor.
type orgLeaf struct {
	org   ids.OrgID
	size  int64
	nonce anchor.Nonce
	leaf  merkle.Hash
}

// Created is the anchor Create stored.
type Created struct {
	ID     ids.UUID
	Period time.Time
	Leaves int
	// Exists: an anchor for the period was already stored.
	Exists bool
}

// Create builds, signs and stores the anchor of period over every active
// org's latest checkpoint. It stores nothing when no org has a checkpoint,
// and nothing new when the period already has an anchor.
func (s *Service) Create(ctx context.Context, period time.Time) (Created, error) {
	period = period.UTC().Truncate(time.Second)
	out := Created{Period: period}
	if exists, err := s.exists(ctx, period); err != nil || exists {
		out.Exists = exists
		return out, err
	}
	limit := s.MaxOrgs
	if limit <= 0 || limit > MaxOrgs {
		limit = MaxOrgs
	}
	refs, err := s.Pool.CrossOrgList(ctx, db.ListActiveOrgs, limit)
	if err != nil {
		return out, err
	}
	if len(refs) == limit {
		s.log().WarnContext(ctx, "evidence.anchor_orgs_capped", slog.Int("orgs", limit))
	}
	var parts []orgLeaf
	for _, r := range refs {
		var note []byte
		var size int64
		err := s.Pool.InTenantTx(ctx, r.Org, func(ctx context.Context, tx db.TenantTx) error {
			c, err := dbq.New(tx).LatestCheckpoint(ctx, r.Org)
			if err != nil {
				return err
			}
			note, size = c.Note, c.TreeSize
			return nil
		}, db.ReadOnly())
		if db.IsNoRows(err) {
			continue
		} else if err != nil {
			return out, fmt.Errorf("anchoring: org %s: %w", r.Org, err)
		}
		nonce, err := anchor.NewNonce()
		if err != nil {
			return out, err
		}
		parts = append(parts, orgLeaf{org: r.Org, size: size, nonce: nonce, leaf: anchor.Leaf(nonce, note)})
	}
	if len(parts) == 0 {
		return out, nil
	}
	leaves := make([]merkle.Hash, len(parts))
	for i, p := range parts {
		leaves[i] = p.leaf
	}
	tree, err := anchor.NewTree(leaves) //nolint:contextcheck // an in-memory tree: no I/O to cancel
	if err != nil {
		return out, err
	}
	key, err := s.signer()
	if err != nil {
		return out, err
	}
	signed, err := anchor.SignStatement(key.Private.Reveal(), anchor.Statement{
		Origin: s.LogOrigin, Period: period, Size: tree.Size(), Root: tree.Root(),
	})
	if err != nil {
		return out, err
	}
	ordered := tree.Leaves()
	flat := make([]byte, 0, len(ordered)*merkle.HashSize)
	for _, l := range ordered {
		flat = append(flat, l[:]...)
	}
	root := tree.Root()
	id := ids.NewV7()
	var inserted int64
	err = s.Pool.InGlobalTx(ctx, db.GlobalAnchors, func(ctx context.Context, tx db.GlobalTx) error {
		inserted, err = dbq.New(tx).InsertAnchor(ctx, dbq.InsertAnchorParams{
			ID: id, Period: period, Leaves: flat, Root: root[:], Statement: signed.Statement, Signature: signed.Signature, Kid: key.KID,
		})
		return err
	})
	if err != nil {
		return out, fmt.Errorf("anchoring: store anchor: %w", err)
	}
	if inserted == 0 {
		out.Exists = true
		return out, nil
	}
	out.ID, out.Leaves = id, len(ordered)
	var errs []error
	for _, p := range parts {
		index := leafIndex(ordered, p.leaf)
		err := s.Pool.InTenantTx(ctx, p.org, func(ctx context.Context, tx db.TenantTx) error {
			return dbq.New(tx).InsertAnchorLeaf(ctx, dbq.InsertAnchorLeafParams{
				OrgID: p.org, AnchorID: id, LeafIndex: int32(index), Nonce: p.nonce[:], CheckpointSize: p.size, //nolint:gosec // G115: < MaxLeaves
			})
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("anchoring: org %s's leaf: %w", p.org, err))
		}
	}
	s.log().InfoContext(ctx, "evidence.anchor_created", slog.String("anchor", id.String()),
		slog.Time("period", period), slog.Int("leaves", len(ordered)), slog.String("root", hex.EncodeToString(root[:])))
	return out, errors.Join(errs...)
}

func leafIndex(ordered []merkle.Hash, leaf merkle.Hash) int {
	for i, l := range ordered {
		if l.Equal(leaf) {
			return i
		}
	}
	return -1
}

func (s *Service) exists(ctx context.Context, period time.Time) (bool, error) {
	var n int
	err := s.Pool.InGlobalTx(ctx, db.GlobalAnchors, func(ctx context.Context, tx db.GlobalTx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM pc.anchors WHERE period = $1", period).Scan(&n)
	}, db.ReadOnly())
	return n > 0, err
}

// signer returns the active anchors key.
func (s *Service) signer() (keys.AltKey, error) {
	ks := s.Keys.AltKeys(keys.PurposeAnchors)
	if len(ks) == 0 || ks[0].State != keys.StateActive {
		return keys.AltKey{}, ErrNoSigner
	}
	return ks[0], nil
}

// publicKey returns the PKIX DER of the anchors key kid, active or retiring.
func (s *Service) publicKey(kid string) ([]byte, bool) {
	for _, k := range s.Keys.AltKeys(keys.PurposeAnchors) {
		if k.KID == kid {
			return k.Public, true
		}
	}
	return nil, false
}

// Result is what Submit did.
type Result struct {
	State string
	Code  string
}

// Submit logs and timestamps the stored anchor id, checks both responses
// and records the outcome: ANCHORED, or FAILED with the next attempt's
// time. A failure is an outcome, not an error: errors are only storage
// failures.
func (s *Service) Submit(ctx context.Context, id ids.UUID) (Result, error) {
	var a dbq.PcAnchor
	err := s.Pool.InGlobalTx(ctx, db.GlobalAnchors, func(ctx context.Context, tx db.GlobalTx) error {
		var err error
		a, err = dbq.New(tx).GetAnchor(ctx, id)
		return err
	}, db.ReadOnly())
	if err != nil {
		return Result{}, fmt.Errorf("anchoring: anchor %s: %w", id, err)
	}
	if a.State == "ANCHORED" || a.Attempts >= MaxAttempts {
		return Result{State: a.State, Code: deref(a.ErrorCode)}, nil
	}
	public, ok := s.publicKey(a.Kid)
	if !ok {
		return s.fail(ctx, a, CodeKeyUnavailable, nil)
	}
	h := anchor.HashedRekord{Digest: sha256.Sum256(a.Statement), Signature: a.Signature, PublicKey: public}
	entry := a.RekorEntry
	if entry == nil {
		rctx, cancel := context.WithTimeout(ctx, rekorTimeout)
		_, raw, err := s.Rekor.Submit(rctx, h)
		cancel()
		if err != nil {
			return s.fail(ctx, a, rekorCode(err), err)
		}
		entry = raw
		if err := s.Pool.InGlobalTx(ctx, db.GlobalAnchors, func(ctx context.Context, tx db.GlobalTx) error {
			_, err := dbq.New(tx).KeepAnchorRekorEntry(ctx, raw, a.ID)
			return err
		}); err != nil {
			return Result{}, fmt.Errorf("anchoring: keep the log entry: %w", err)
		}
	} else if err := s.verifyEntry(entry, h); err != nil {
		return s.fail(ctx, a, CodeRekorInvalid, err)
	}
	tctx, cancel := context.WithTimeout(ctx, tsaTimeout)
	token, ts, err := s.TSA.Timestamp(tctx, a.Signature)
	cancel()
	if err != nil {
		return s.fail(ctx, a, timestampCode(err), err)
	}
	if ts.Time.Before(a.Period) {
		return s.fail(ctx, a, CodeTimestampInvalid, errors.New("the timestamp predates the anchoring period"))
	}
	err = s.Pool.InGlobalTx(ctx, db.GlobalAnchors, func(ctx context.Context, tx db.GlobalTx) error {
		return expectOne(dbq.New(tx).MarkAnchorAnchored(ctx, dbq.MarkAnchorAnchoredParams{
			RekorEntry: entry, TimestampToken: token, ID: a.ID, Attempts: a.Attempts,
		}))
	})
	if err != nil {
		return Result{}, fmt.Errorf("anchoring: mark anchored: %w", err)
	}
	s.log().InfoContext(ctx, "evidence.anchored", slog.String("anchor", a.ID.String()), slog.Int("attempt", int(a.Attempts)+1),
		slog.String("statement_sha256", hex.EncodeToString(h.Digest[:])))
	return Result{State: "ANCHORED"}, nil
}

// verifyEntry checks a kept log entry again before it counts.
func (s *Service) verifyEntry(raw []byte, h anchor.HashedRekord) error {
	e, err := anchor.ParseEntry(raw)
	if err != nil {
		return err
	}
	body, err := h.CanonicalBody()
	if err != nil {
		return err
	}
	_, err = anchor.VerifyEntry(e, s.Rekor.Log, body)
	return err
}

func rekorCode(err error) string {
	if errors.Is(err, anchor.ErrInvalidEntry) || errors.Is(err, anchor.ErrInvalidStatement) {
		return CodeRekorInvalid
	}
	return CodeRekorFailed
}

func timestampCode(err error) string {
	if errors.Is(err, anchor.ErrInvalidTimestamp) {
		return CodeTimestampInvalid
	}
	return CodeTimestampFailed
}

// Backoff is the wait after the attempt-th failed attempt (from 1).
func Backoff(attempt int) time.Duration {
	d := firstBackoff
	for i := 1; i < attempt && d < maxBackoff; i++ {
		d *= 2
	}
	return min(d, maxBackoff)
}

// fail records a failed attempt: FAILED, the code, the next attempt's time;
// logs evidence.anchor_failed (ids and codes only, never a response) and
// records it in the platform audit.
func (s *Service) fail(ctx context.Context, a dbq.PcAnchor, code string, cause error) (Result, error) {
	attempt := int(a.Attempts) + 1
	next := s.now().Add(Backoff(attempt))
	err := s.Pool.InGlobalTx(ctx, db.GlobalAnchors, func(ctx context.Context, tx db.GlobalTx) error {
		return expectOne(dbq.New(tx).MarkAnchorFailed(ctx, dbq.MarkAnchorFailedParams{
			ErrorCode: code, NextAt: next, ID: a.ID, Attempts: a.Attempts,
		}))
	})
	if err != nil {
		return Result{}, fmt.Errorf("anchoring: mark failed: %w", err)
	}
	attrs := []any{
		slog.String("anchor", a.ID.String()), slog.String("code", code), slog.Int("attempt", attempt),
		slog.Bool("final", attempt >= MaxAttempts),
	}
	if attempt < MaxAttempts {
		attrs = append(attrs, slog.Time("next_attempt", next))
	}
	if cause != nil {
		attrs = append(attrs, slog.String("cause", causeKind(cause)))
	}
	s.log().WarnContext(ctx, "evidence.anchor_failed", attrs...)
	err = s.Pool.InTenantTx(ctx, ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
		_, err := audit.Record(ctx, tx, audit.Event{
			Name: "evidence.anchor_failed", Actor: Actor, Outcome: audit.Failure,
			Object:  &audit.Object{Type: "anchor", ID: a.ID.String()},
			Details: map[string]string{"code": code, "attempt": fmt.Sprint(attempt), "period": a.Period.UTC().Format(time.RFC3339)},
		})
		return err
	})
	if err != nil {
		return Result{}, fmt.Errorf("anchoring: audit the failure: %w", err)
	}
	return Result{State: "FAILED", Code: code}, nil
}

// causeKind names the kind of a failure without any response content.
func causeKind(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, anchor.ErrInvalidEntry):
		return "invalid log entry"
	case errors.Is(err, anchor.ErrInvalidStatement):
		return "invalid statement"
	case errors.Is(err, anchor.ErrInvalidTimestamp):
		return "invalid timestamp"
	case errors.Is(err, ErrHostNotAllowed):
		return "host not configured"
	default:
		return "request failed"
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// expectOne checks a conditional transition (HR-004): no row is a lost
// race, which callers never take for success.
func expectOne(n int64, err error) error {
	switch {
	case err != nil:
		return err
	case n != 1:
		return db.ErrLostRace
	}
	return nil
}

// Tick creates the current period's anchor when it has none, then logs and
// timestamps the anchors that are due (new ones, and failed ones whose
// backoff is over).
func (s *Service) Tick(ctx context.Context) error {
	if _, err := s.Create(ctx, s.Period(s.now())); err != nil {
		s.log().ErrorContext(ctx, "evidence.anchor_create_failed", slog.String("error", err.Error()))
	}
	var due []ids.UUID
	err := s.Pool.InGlobalTx(ctx, db.GlobalAnchors, func(ctx context.Context, tx db.GlobalTx) error {
		var err error
		due, err = dbq.New(tx).AnchorsDue(ctx, MaxAttempts, maxDuePerTick)
		return err
	}, db.ReadOnly())
	if err != nil {
		return fmt.Errorf("anchoring: due anchors: %w", err)
	}
	for _, id := range due {
		if _, err := s.Submit(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

// Leaves splits an anchor's stored leaves.
func Leaves(flat []byte) ([][]byte, error) {
	if len(flat) == 0 || len(flat)%merkle.HashSize != 0 {
		return nil, errors.New("anchoring: malformed leaves")
	}
	out := make([][]byte, 0, len(flat)/merkle.HashSize)
	for c := range slices.Chunk(flat, merkle.HashSize) {
		out = append(out, bytes.Clone(c))
	}
	return out, nil
}
