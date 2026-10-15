// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package engine_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/detection/engine"
	"github.com/katocxl/pantherclaw/internal/detection/pack"
	"github.com/katocxl/pantherclaw/internal/detection/rules"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/reflex/alerts"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
)

type ents struct{ e billing.Edition }

func (x ents) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: x.e}, nil
}

type fixture struct {
	p   *db.Pool
	org ids.OrgID
	env *celenv.Env
	e   *engine.Engine
}

func newFixture(t *testing.T, edition billing.Edition) *fixture {
	t.Helper()
	d := dbtest.New(t)
	env, err := engine.NewEnv(celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	p, err := pack.Load(env)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{p: d.AppPool(t), org: ids.New[ids.Org](), env: env}
	f.e = &engine.Engine{
		Pool: f.p, Builtin: p.Rules, PackVersion: p.Version, Env: env, Raiser: &alerts.Raiser{}, Sink: &failures.Sink{},
		Ents: ents{edition},
	}
	f.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'detect')", f.org)
	// Detection starts at the feed's head (D59 M4): start it before the
	// test writes anything.
	if _, err := f.e.Process(context.Background(), f.org); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (f *fixture) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

// audit appends n audit events and waits until they are chained.
func (f *fixture) audit(t *testing.T, name string, n int, details func(i int) map[string]string) {
	t.Helper()
	ctx := context.Background()
	if err := f.p.InTenantTx(ctx, f.org, func(ctx context.Context, tx db.TenantTx) error {
		for i := range n {
			var d map[string]string
			if details != nil {
				d = details(i)
			}
			if _, err := audit.Record(ctx, tx, audit.Event{
				Name: name, Actor: evdomain.Actor{Type: "user", ID: "u1"}, Outcome: audit.Success, Details: d,
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f.chain(t)
}

func (f *fixture) chain(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for {
		if _, err := ledger.ChainAll(context.Background(), f.p, f.org, 1000); err != nil {
			t.Fatal(err)
		}
		if f.count(t, `SELECT count(*) FROM pc.ledger_entries e WHERE org_id = $1
			AND NOT EXISTS (SELECT 1 FROM pc.ledger_chain c WHERE c.org_id = e.org_id AND c.entry_id = e.id)`, f.org) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("entries not chained within a minute")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (f *fixture) drain(t *testing.T) int {
	t.Helper()
	total := 0
	for range 50 {
		r, err := f.e.Process(context.Background(), f.org)
		if err != nil {
			t.Fatal(err)
		}
		total += r.Signals
		if r.Events == 0 && r.To == r.From {
			return total
		}
	}
	t.Fatal("feed did not drain")
	return total
}

// TestHR240_EachEntryEvaluatedOnceWithCompareAndSet: concurrent runs over
// the same org raise each detection once, and the cursor ends at the head;
// the engine's own reflex.* entries are never evaluated (no feedback loop).
func TestHR240_EachEntryEvaluatedOnceWithCompareAndSet(t *testing.T) {
	f := newFixture(t, billing.Community)
	f.audit(t, "security.kill_switch_engaged", 3, nil)
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.e.Process(context.Background(), f.org)
			if err != nil && !errors.Is(err, engine.ErrCursorMoved) && !db.IsUniqueViolation(err) {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	f.drain(t)
	// Three kill switch events count into one INCIDENT alert, once each.
	if n := f.count(t, `SELECT coalesce(sum(count), 0) FROM pc.alerts WHERE org_id = $1
		AND rule_id = 'pc.containment.kill_switch_engaged'`, f.org); n != 3 {
		t.Errorf("kill switch signals counted %d times, want 3", n)
	}
	f.chain(t)
	f.drain(t)
	if n := f.count(t, `SELECT coalesce(sum(count), 0) FROM pc.alerts WHERE org_id = $1`, f.org); n != 3 {
		t.Errorf("after the engine read its own entries: %d signals, want 3", n)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.detection_cursors c JOIN pc.ledger_heads h ON h.org_id = c.org_id
		WHERE c.org_id = $1 AND c.seq = h.seq`, f.org); n != 1 {
		t.Error("cursor is not at the chain head")
	}
}

// TestT105_OverflowFloodingStillAlertsAndReportsOnce: flooding a window
// rule with distinct keys past its cap counts the rest into the overflow
// group, which still fires, and reports one owned failure per day.
func TestT105_OverflowFloodingStillAlertsAndReportsOnce(t *testing.T) {
	f := newFixture(t, billing.Business)
	f.e.State = func(tx db.TenantTx) *engine.PG {
		s := engine.NewPG(tx)
		s.MaxGroups = 3
		return s
	}
	env := f.env
	r, err := rules.Parse([]byte(`id: pc.test.flood
version: "1"
title: Flood
description: Counts per agent.
severity: LOW
attention: ALERT
basis: INFERRED
edition: community
on: [audit.test.flood]
window: {duration: 1h, group_by: [subjects.agent], count: 3}
tests: []
`))
	if err != nil {
		t.Fatal(err)
	}
	c, err := engine.Compile(env, r, "d", "1")
	if err != nil {
		t.Fatal(err)
	}
	f.e.Builtin = []*engine.Compiled{c}
	f.audit(t, "test.flood", 20, func(i int) map[string]string {
		return map[string]string{"agent": fmt.Sprintf("01930000-0000-7000-8000-%012d", i)}
	})
	f.drain(t)
	if n := f.count(t, `SELECT count(*) FROM pc.alerts WHERE org_id = $1 AND rule_id = 'pc.test.flood'`, f.org); n != 1 {
		t.Errorf("overflow alerts %d, want 1", n)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.operational_failures WHERE org_id = $1 AND kind = 'detection.overflow'`, f.org); n != 1 {
		t.Errorf("overflow failures %d, want 1", n)
	}
	if n := f.count(t, `SELECT count(DISTINCT group_key) FROM pc.detection_window_buckets WHERE org_id = $1`, f.org); n != 4 {
		t.Errorf("groups kept %d, want 3 + overflow", n)
	}
}

// TestT105_ErroringRuleIsDisabledWithAFailure: ten evaluation errors in a
// row disable the rule and report an owned failure; other rules go on.
func TestT105_ErroringRuleIsDisabledWithAFailure(t *testing.T) {
	f := newFixture(t, billing.Community)
	r, err := rules.Parse([]byte(`id: pc.test.broken
version: "1"
title: Broken
description: Reads an attribute that is never there.
severity: LOW
attention: ALERT
basis: INFERRED
edition: community
on: [audit.security.kill_switch_engaged]
match: event.attrs["missing"] == "x"
tests: []
`))
	if err != nil {
		t.Fatal(err)
	}
	c, err := engine.Compile(f.env, r, "d", "1")
	if err != nil {
		t.Fatal(err)
	}
	f.e.Builtin = append(f.e.Builtin, c)
	// Small batches: the errors run across several (D59 M3).
	f.e.Batch = 3
	f.audit(t, "security.kill_switch_engaged", 12, nil)
	f.drain(t)
	if n := f.count(t, `SELECT count(*) FROM pc.detection_rule_state WHERE org_id = $1 AND rule_id = 'pc.test.broken'
		AND disabled_at IS NOT NULL`, f.org); n != 1 {
		t.Error("the broken rule was not disabled")
	}
	if n := f.count(t, `SELECT count(*) FROM pc.operational_failures WHERE org_id = $1 AND kind = 'detection.rule_disabled'`, f.org); n != 1 {
		t.Error("no failure for the disabled rule")
	}
	if n := f.count(t, `SELECT coalesce(sum(count), 0) FROM pc.alerts WHERE org_id = $1 AND rule_id = 'pc.containment.kill_switch_engaged'`, f.org); n != 12 {
		t.Errorf("the other rules raised %d, want 12", n)
	}
}

// TestHR241_PackMismatchTurnsDetectionsOff: without a verified pack the
// engine evaluates nothing, leaves the cursor and reports a failure.
func TestHR241_PackMismatchTurnsDetectionsOff(t *testing.T) {
	f := newFixture(t, billing.Community)
	f.e.Builtin, f.e.PackErr = nil, pack.ErrIntegrity
	f.audit(t, "security.kill_switch_engaged", 1, nil)
	if _, err := f.e.Process(context.Background(), f.org); err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.alerts WHERE org_id = $1`, f.org); n != 0 {
		t.Errorf("%d alerts with detections off", n)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.operational_failures WHERE org_id = $1 AND kind = 'detection.pack_integrity'`, f.org); n != 1 {
		t.Error("no pack integrity failure")
	}
}

// TestHR241_CustomRuleRunsOnlyWithItsLedgerDigest: a published custom rule
// whose stored content no longer matches the digest its publication
// recorded is skipped with a failure.
func TestHR241_CustomRuleRunsOnlyWithItsLedgerDigest(t *testing.T) {
	src := "id: org.kill\nversion: \"1\"\ntitle: Kill\ndescription: Custom.\nseverity: LOW\nattention: ALERT\n" +
		"basis: OBSERVED\nedition: business\non: [audit.security.kill_switch_engaged]\ntests: []\n"
	sum := sha256.Sum256([]byte(src))
	env, _ := engine.NewEnv(celenv.DefaultLimits)
	if _, err := engine.CustomRule(env, src, engine.Recorded{Stored: sum[:], Published: sum[:], LedgerPresent: true, Ledger: hex.EncodeToString(sum[:])}); err != nil {
		t.Fatalf("matching digests: %v", err)
	}
	other := sha256.Sum256([]byte("tampered"))
	if _, err := engine.CustomRule(env, src, engine.Recorded{Stored: sum[:], Published: sum[:], LedgerPresent: true, Ledger: hex.EncodeToString(other[:])}); !errors.Is(err, engine.ErrDigestMismatch) {
		t.Errorf("ledger digest differs: %v", err)
	}
	if _, err := engine.CustomRule(env, src+"#", engine.Recorded{Stored: sum[:], Published: sum[:], LedgerPresent: true, Ledger: hex.EncodeToString(sum[:])}); !errors.Is(err, engine.ErrDigestMismatch) {
		t.Errorf("content changed: %v", err)
	}
}

// TestHR037_VariantShoppingIsDetectedInEveryEdition: the approvals'
// security.variant_suspected entry raises the variant-shopping alert in
// Community too: a hardening rule is never edition-gated (D5).
func TestHR037_VariantShoppingIsDetectedInEveryEdition(t *testing.T) {
	f := newFixture(t, billing.Community)
	f.audit(t, "security.variant_suspected", 1, func(int) map[string]string {
		return map[string]string{"operation": "payments.refund.create", "agent": "01930000-0000-7000-8000-0000000000a1"}
	})
	f.drain(t)
	if n := f.count(t, `SELECT count(*) FROM pc.alerts WHERE org_id = $1 AND rule_id = 'pc.approvals.variant_shopping'
		AND state = 'OPEN' AND basis = 'OBSERVED'`, f.org); n != 1 {
		t.Errorf("variant shopping alerts %d, want 1", n)
	}
	// Business rules stay off in Community.
	if n := f.count(t, `SELECT count(*) FROM pc.alerts WHERE org_id = $1 AND rule_id LIKE 'pc.probing.%'`, f.org); n != 0 {
		t.Errorf("%d business alerts in Community", n)
	}
}

// TestT105_MalformedEntryNeverStallsTheCursor: an entry of a known kind
// whose body does not parse passes through as kind and actor only; the
// cursor moves past it and later entries are evaluated.
func TestT105_MalformedEntryNeverStallsTheCursor(t *testing.T) {
	f := newFixture(t, billing.Community)
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := ledger.Append(ctx, tx, "receipt.decision", evdomain.Actor{Type: "gateway", ID: "g"}, []byte(`{"txn":5}`))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	f.chain(t)
	f.audit(t, "security.kill_switch_engaged", 1, nil)
	f.drain(t)
	if n := f.count(t, `SELECT count(*) FROM pc.alerts WHERE org_id = $1 AND rule_id = 'pc.containment.kill_switch_engaged'`, f.org); n != 1 {
		t.Errorf("entries after the malformed one were not evaluated (%d alerts)", n)
	}
}

// TestT105_NoHistoryReplayOnFirstRun: an org's first detection run starts
// at the feed's head; entries written before it are not evaluated (D59 M4).
func TestT105_NoHistoryReplayOnFirstRun(t *testing.T) {
	d := dbtest.New(t)
	env, _ := engine.NewEnv(celenv.DefaultLimits)
	p, err := pack.Load(env)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{p: d.AppPool(t), org: ids.New[ids.Org](), env: env}
	f.e = &engine.Engine{Pool: f.p, Builtin: p.Rules, PackVersion: p.Version, Env: env, Raiser: &alerts.Raiser{}, Sink: &failures.Sink{}}
	f.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'history')", f.org)
	f.audit(t, "security.kill_switch_engaged", 2, nil)
	f.drain(t)
	if n := f.count(t, "SELECT count(*) FROM pc.alerts WHERE org_id = $1", f.org); n != 0 {
		t.Errorf("%d alerts from history", n)
	}
	f.audit(t, "security.kill_switch_engaged", 1, nil)
	f.drain(t)
	if n := f.count(t, "SELECT coalesce(sum(count), 0) FROM pc.alerts WHERE org_id = $1", f.org); n != 1 {
		t.Errorf("new entries raised %d, want 1", n)
	}
}
