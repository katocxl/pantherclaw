// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/detection/rules"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/reflex/alerts"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
)

// Entitlements reads the server's current edition.
type Entitlements interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// Engine evaluates the built-in pack and an org's published custom rules
// over the org's feed.
type Engine struct {
	Pool *db.Pool
	// Builtin is the verified built-in pack's rules; PackErr is why the
	// pack did not load (detections stay off, D12).
	Builtin     []*Compiled
	PackVersion string
	PackErr     error
	// Env compiles custom rules.
	Env    *celenv.Env
	Raiser *alerts.Raiser
	Sink   *failures.Sink
	Ents   Entitlements
	Log    *slog.Logger
	// Batch is the most events one run reads (≤ feed.MaxBatch).
	Batch int
	Now   func() time.Time
	// State builds the working memory of a transaction (tests lower caps).
	State func(tx db.TenantTx) *PG
}

// Failure kinds the engine reports (F641).
const (
	FailurePackIntegrity   = "detection.pack_integrity"
	FailureOverflow        = "detection.overflow"
	FailureRuleDisabled    = "detection.rule_disabled"
	FailureCustomIntegrity = "detection.custom_rule_integrity"
	FailureEditionLapsed   = "detection.edition_lapsed"
)

// RunResult is what one run did.
type RunResult struct {
	Events, Signals int
	From, To        int64
}

// ErrCursorMoved reports a run that lost the compare-and-set: another run
// evaluated the same entries first, and this one rolled back.
var ErrCursorMoved = errors.New("detection: cursor moved")

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Engine) log() *slog.Logger {
	if e.Log != nil {
		return e.Log
	}
	return pclog.Discard()
}

// Process evaluates the next batch of org's feed in one transaction:
// signals, rule state and the cursor commit together or not at all
// (HR-240).
func (e *Engine) Process(ctx context.Context, org ids.OrgID) (RunResult, error) {
	batch := e.Batch
	if batch <= 0 || batch > feed.MaxBatch {
		batch = feed.MaxBatch
	}
	ents := billing.CommunityEntitlements()
	if e.Ents != nil {
		if cur, err := e.Ents.Current(ctx); err == nil {
			ents = cur
		}
	}
	var res RunResult
	err := e.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		res = RunResult{}
		q := dbq.New(tx)
		if e.PackErr != nil || e.Builtin == nil {
			// Detection stays off; the server still serves decisions.
			return e.report(ctx, tx, reflexdomain.Failure{
				Org: org, Kind: FailurePackIntegrity, DedupeKey: FailurePackIntegrity,
				Summary:  "The built-in detection pack failed its integrity check, so detections are off.",
				NextStep: "Reinstall the release binary; the pack ships inside it and is checked at startup.",
			})
		}
		cursor, err := q.EnsureDetectionCursor(ctx, org)
		if err != nil {
			return err
		}
		events, err := feed.Reader{}.After(ctx, tx, cursor, batch)
		if err != nil || len(events) == 0 {
			return err
		}
		res.From, res.To = cursor, events[len(events)-1].Seq
		set, err := e.ruleSet(ctx, tx, q, ents)
		if err != nil {
			return err
		}
		st := e.state(tx)
		errs := map[string]int{}
		lastErr := map[string]string{}
		for _, ev := range events {
			if reflexdomain.ReflexKind(ev.Kind) {
				continue
			}
			res.Events++
			for _, c := range set {
				id := c.Rule.ID
				if errs[id] >= MaxConsecutiveErrors {
					continue
				}
				r, err := Evaluate(ctx, st, c, ev)
				if err != nil {
					if !errors.Is(err, celenv.ErrEval) {
						return err
					}
					errs[id]++
					lastErr[id] = truncate(err.Error(), 512)
					continue
				}
				errs[id] = 0
				if r.Overflow {
					if err := e.overflow(ctx, tx, q, c); err != nil {
						return err
					}
				}
				if r.Fired == nil {
					continue
				}
				if _, err := e.Raiser.RaiseTx(ctx, tx, Signal(c, ev, *r.Fired)); err != nil {
					return fmt.Errorf("detection: %s: %w", id, err)
				}
				res.Signals++
			}
		}
		if err := e.saveErrors(ctx, tx, q, set, errs, lastErr); err != nil {
			return err
		}
		if err := st.Prune(ctx, e.now()); err != nil {
			return err
		}
		n, err := q.AdvanceDetectionCursor(ctx, res.To, org, cursor)
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrCursorMoved
		}
		return nil
	})
	return res, err
}

func (e *Engine) state(tx db.TenantTx) *PG {
	if e.State != nil {
		return e.State(tx)
	}
	return NewPG(tx)
}

func (e *Engine) report(ctx context.Context, tx db.TenantTx, f reflexdomain.Failure) error {
	if e.Sink == nil {
		return nil
	}
	_, _, err := e.Sink.ReportTx(ctx, tx, f)
	return err
}

// ruleSet is the rules that run for the org now: the built-in rules of the
// edition and the published custom rules whose stored digest equals the
// ledger-recorded one (HR-241), minus the auto-disabled ones.
func (e *Engine) ruleSet(ctx context.Context, tx db.TenantTx, q *dbq.Queries, ents billing.Entitlements) ([]*Compiled, error) {
	states, err := q.DetectionRuleStates(ctx, tx.OrgID())
	if err != nil {
		return nil, err
	}
	disabled := map[string]bool{}
	for _, s := range states {
		if s.DisabledAt != nil {
			disabled[s.RuleID] = true
		}
	}
	var out []*Compiled
	for _, c := range e.Builtin {
		if disabled[c.Rule.ID] || (c.Rule.Edition == rules.EditionBusiness && !ents.AdvancedDetections()) {
			continue
		}
		out = append(out, c)
	}
	if e.Env == nil || !ents.CustomDetections() {
		return out, nil
	}
	custom, err := q.PublishedCustomRules(ctx, tx.OrgID())
	if err != nil {
		return nil, err
	}
	for _, r := range custom {
		if disabled[r.RuleID] {
			continue
		}
		c, err := CustomRule(e.Env, r.Content, r.ContentDigest, r.LedgerDigest)
		if err != nil {
			if err := e.report(ctx, tx, reflexdomain.Failure{
				Org: tx.OrgID(), Kind: FailureCustomIntegrity, DedupeKey: FailureCustomIntegrity + ":" + r.ID.String(),
				Scope:    []reflexdomain.Subject{{Type: reflexdomain.SubjectResource, ID: "detection_rule:" + r.RuleID}},
				Summary:  "Custom detection rule " + r.RuleID + " does not match its published digest, so it does not run.",
				NextStep: "Publish the rule again from its reviewed source.",
			}); err != nil {
				return nil, err
			}
			continue
		}
		out = append(out, c)
	}
	return out, nil
}

// ErrDigestMismatch reports a custom rule whose stored content does not
// match the digest its publication recorded (HR-241).
var ErrDigestMismatch = errors.New("detection: custom rule digest mismatch")

// CustomRule parses and compiles a published custom rule after checking
// that its content, its stored digest and the ledger-recorded digest agree.
func CustomRule(env *celenv.Env, content string, stored []byte, ledger string) (*Compiled, error) {
	sum := sha256.Sum256([]byte(content))
	if !bytes.Equal(sum[:], stored) || hex.EncodeToString(sum[:]) != ledger {
		return nil, ErrDigestMismatch
	}
	r, err := rules.Parse([]byte(content))
	if err != nil {
		return nil, err
	}
	if r.Builtin() {
		return nil, fmt.Errorf("%w: a custom rule id starts with org.", rules.ErrInvalid)
	}
	return Compile(env, r, hex.EncodeToString(sum[:]), "")
}

func (e *Engine) overflow(ctx context.Context, tx db.TenantTx, q *dbq.Queries, c *Compiled) error {
	day := pgtype.Date{Time: e.now().UTC().Truncate(24 * time.Hour), Valid: true}
	n, err := q.MarkDetectionOverflow(ctx, tx.OrgID(), c.Rule.ID, day)
	if err != nil || n == 0 {
		return err
	}
	return e.report(ctx, tx, reflexdomain.Failure{
		Org: tx.OrgID(), Kind: FailureOverflow, DedupeKey: FailureOverflow + ":" + c.Rule.ID,
		Scope:    []reflexdomain.Subject{{Type: reflexdomain.SubjectResource, ID: "detection_rule:" + c.Rule.ID}},
		Summary:  "Detection rule " + c.Rule.ID + " reached its cardinality cap; new keys count into one overflow group.",
		NextStep: "Find what is creating so many distinct keys (it may be flooding on purpose) and narrow the rule.",
	})
}

func (e *Engine) saveErrors(ctx context.Context, tx db.TenantTx, q *dbq.Queries, set []*Compiled, errs map[string]int,
	last map[string]string,
) error {
	for _, c := range set {
		id := c.Rule.ID
		n, touched := errs[id]
		if !touched {
			continue
		}
		var le *string
		if s, ok := last[id]; ok {
			le = &s
		}
		if err := q.SetDetectionRuleErrors(ctx, dbq.SetDetectionRuleErrorsParams{
			OrgID: tx.OrgID(), RuleID: id, ConsecutiveErrors: int32(n), LastError: le, //nolint:gosec // G115: ≤ 500
		}); err != nil {
			return err
		}
		if n < MaxConsecutiveErrors {
			continue
		}
		reason := fmt.Sprintf("%d evaluation errors in a row", n)
		k, err := q.DisableDetectionRule(ctx, &reason, tx.OrgID(), id)
		if err != nil {
			return err
		}
		if k == 0 {
			continue
		}
		e.log().WarnContext(ctx, "detection.rule_disabled", slog.String("org", tx.OrgID().String()), slog.String("rule", id))
		if err := e.report(ctx, tx, reflexdomain.Failure{
			Org: tx.OrgID(), Kind: FailureRuleDisabled, DedupeKey: FailureRuleDisabled + ":" + id,
			Scope:    []reflexdomain.Subject{{Type: reflexdomain.SubjectResource, ID: "detection_rule:" + id}},
			Summary:  "Detection rule " + id + " was disabled after " + reason + ".",
			NextStep: "Fix or replace the rule, then enable it again.",
		}); err != nil {
			return err
		}
	}
	return nil
}
