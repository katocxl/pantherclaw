// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package alerts_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/reflex/alerts"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
)

type fixture struct {
	p   *db.Pool
	org ids.OrgID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	d := dbtest.New(t)
	f := &fixture{p: d.AppPool(t), org: ids.New[ids.Org]()}
	f.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'reflex')", f.org)
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

func (f *fixture) signal(attention reflexdomain.Attention) reflexdomain.Signal {
	return reflexdomain.Signal{
		Org: f.org, Source: reflexdomain.SourceDetection, RuleID: "pc.tools.drift", RuleVersion: "1",
		RuleDigest: strings.Repeat("ab", 32), PackVersion: "1", Title: "Tool definition drifted",
		Severity: reflexdomain.SeverityHigh, Attention: attention, Basis: reflexdomain.BasisRuleMatch,
		Subjects:   []reflexdomain.Subject{{Type: reflexdomain.SubjectConnection, ID: "c1"}},
		Evidence:   []reflexdomain.EvidenceRef{{Kind: reflexdomain.EvidenceLedger, ID: ids.NewV7()}},
		OccurredAt: time.Now(), Facts: map[string]string{"package": "p"}, GroupKey: "connection:c1",
	}
}

func (f *fixture) raise(t *testing.T, r *alerts.Raiser, s reflexdomain.Signal) (alerts.Raised, error) {
	t.Helper()
	var res alerts.Raised
	err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		res, err = r.RaiseTx(ctx, tx, s)
		return err
	})
	return res, err
}

// TestHR243_RepeatsAddEvidenceNotRows: a repeat signal counts into the
// open alert and appends its evidence; the alert records the rule digest,
// pack version and basis; evidence and events are append-only.
func TestHR243_RepeatsAddEvidenceNotRows(t *testing.T) {
	f := newFixture(t)
	r := &alerts.Raiser{}
	first, err := f.raise(t, r, f.signal(reflexdomain.AttentionAlert))
	if err != nil || !first.New || first.State != alerts.StateOpen {
		t.Fatalf("first: %+v %v", first, err)
	}
	again, err := f.raise(t, r, f.signal(reflexdomain.AttentionAlert))
	if err != nil || again.New || again.Alert != first.Alert || again.Count != 2 {
		t.Fatalf("repeat: %+v %v", again, err)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.alert_evidence WHERE org_id = $1 AND alert_id = $2", f.org, first.Alert); n != 2 {
		t.Errorf("evidence rows %d, want 2", n)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.alerts WHERE org_id = $1 AND rule_digest = $2 AND pack_version = '1'
		AND basis = 'RULE_MATCH'`, f.org, strings.Repeat("ab", 32)); n != 1 {
		t.Errorf("alerts with digest, pack and basis: %d", n)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'reflex.alert'", f.org); n != 1 {
		t.Errorf("reflex.alert entries %d, want 1", n)
	}
	for _, sql := range []string{
		"UPDATE pc.alert_evidence SET ref_id = ref_id WHERE org_id = $1",
		"DELETE FROM pc.alert_evidence WHERE org_id = $1",
		"UPDATE pc.alert_events SET note = 'x' WHERE org_id = $1",
		"DELETE FROM pc.alert_events WHERE org_id = $1",
		"UPDATE pc.alerts SET rule_digest = 'x' WHERE org_id = $1",
		"DELETE FROM pc.alerts WHERE org_id = $1",
	} {
		err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql, f.org)
			return err
		})
		if !db.IsPermissionDenied(err) {
			t.Errorf("%s: %v, want permission denied", sql, err)
		}
	}
}

// TestRaiseByAttention: LIVE writes a reflex.live entry and no alert,
// TELEMETRY writes nothing, and a test signal is capped at ALERT.
func TestRaiseByAttention(t *testing.T) {
	f := newFixture(t)
	r := &alerts.Raiser{}
	if res, err := f.raise(t, r, f.signal(reflexdomain.AttentionLive)); err != nil || !res.Alert.IsZero() {
		t.Fatalf("live: %+v %v", res, err)
	}
	if res, err := f.raise(t, r, f.signal(reflexdomain.AttentionTelemetry)); err != nil || !res.Alert.IsZero() {
		t.Fatalf("telemetry: %+v %v", res, err)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.alerts WHERE org_id = $1", f.org); n != 0 {
		t.Errorf("alerts %d, want 0", n)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'reflex.live'", f.org); n != 1 {
		t.Errorf("live entries %d, want 1", n)
	}
	s := f.signal(reflexdomain.AttentionPage)
	s.Test = true
	res, err := f.raise(t, r, s)
	if err != nil || res.Attention != reflexdomain.AttentionAlert {
		t.Fatalf("test page: %+v %v", res, err)
	}
	s = f.signal(reflexdomain.AttentionAlert)
	s.Facts = map[string]string{"api_token": "x"}
	if _, err := f.raise(t, r, s); !errors.Is(err, reflexdomain.ErrInvalidSignal) {
		t.Errorf("secret-like fact: %v", err)
	}
}

// TestFailureSinkDedupes: a repeat failure with the same dedupe key counts
// into the open one; once resolved, the next report opens a new one.
func TestFailureSinkDedupes(t *testing.T) {
	f := newFixture(t)
	sink := &failures.Sink{}
	report := func() (ids.UUID, bool) {
		var id ids.UUID
		var isNew bool
		if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			id, isNew, err = sink.ReportTx(ctx, tx, reflexdomain.Failure{
				Org: f.org, Kind: "detection.overflow", Summary: "rule overflowed", NextStep: "narrow the rule",
				DedupeKey: "overflow:pc.probing.denial_burst",
			})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return id, isNew
	}
	a, aNew := report()
	b, bNew := report()
	if !aNew || bNew || a != b {
		t.Fatalf("a %v %v, b %v %v", a, aNew, b, bNew)
	}
	f.exec(t, "UPDATE pc.operational_failures SET state = 'RESOLVED', resolved_at = now(), resolution = 'done' WHERE org_id = $1", f.org)
	c, cNew := report()
	if !cNew || c == a {
		t.Fatalf("after resolve: %v %v", c, cNew)
	}
}

// TestFeedReadsTheChainInOrder: the reader returns chained entries with
// seq > after, ascending, normalized, and Head is the last seq.
func TestFeedReadsTheChainInOrder(t *testing.T) {
	f := newFixture(t)
	r := &alerts.Raiser{}
	for range 3 {
		if _, err := f.raise(t, r, f.signal(reflexdomain.AttentionLive)); err != nil {
			t.Fatal(err)
		}
	}
	// Entries chain once no older transaction is running in the cluster.
	for chained, deadline := 0, time.Now().Add(time.Minute); chained < 3; {
		n, err := ledger.ChainAll(context.Background(), f.p, f.org, 100)
		if err != nil {
			t.Fatal(err)
		}
		if chained += n; chained < 3 {
			if time.Now().After(deadline) {
				t.Fatal("the entries were not chained within a minute")
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	var events []feed.Event
	var head int64
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		if events, err = (feed.Reader{}).After(ctx, tx, 1, 10); err != nil {
			return err
		}
		head, err = (feed.Reader{}).Head(ctx, tx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Seq != 2 || events[1].Seq != 3 || head != 3 {
		t.Fatalf("events %+v head %d", events, head)
	}
	if events[0].Kind != reflexdomain.KindLive || events[0].Org != f.org || len(events[0].Subjects) != 1 {
		t.Errorf("%+v", events[0])
	}
}
