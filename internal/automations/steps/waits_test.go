// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package steps

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// TestHR452_AWaitOnConsequencesPassesOnlyOnConfirmed (G0 M17 D103): a
// wait_effect step with consequences passes only when enough of the run's
// actions have every consequence confirmed by its own evidence. An
// unconfirmed or not verifiable consequence never passes: it keeps the
// step waiting while the run is active and then needs reconciliation;
// so does a consequence still pending at the timeout. Actions whose
// consequences are only pending keep the step waiting, even after the run
// ended, and a min that cannot be reached fails.
//
// Covers: F414
func TestHR452_AWaitOnConsequencesPassesOnlyOnConfirmed(t *testing.T) {
	type counts = dbq.RunDownstreamCountsRow
	for _, c := range []struct {
		name             string
		c                counts
		want             int
		active, timedOut bool
		state            autodomain.StepState
		reason           string
	}{
		{"confirmed", counts{Confirmed: 1}, 1, true, false, autodomain.StepDone, ""},
		{"confirmed, though another is unconfirmed", counts{Confirmed: 2, Unconfirmed: 1}, 2, false, false, autodomain.StepDone, ""},
		{"too few confirmed, run active", counts{Confirmed: 1}, 2, true, false, autodomain.StepWaiting, ""},
		{"pending after the run ended", counts{Pending: 1}, 1, false, false, autodomain.StepWaiting, ""},
		{"unconfirmed, run active", counts{Unconfirmed: 1}, 1, true, false, autodomain.StepWaiting, ""},
		{"unconfirmed after the run ended", counts{Unconfirmed: 1}, 1, false, false, autodomain.StepUnknown, engine.ReasonEffectUnknown},
		{"not verifiable at the timeout", counts{Unconfirmed: 1}, 1, true, true, autodomain.StepUnknown, engine.ReasonEffectUnknown},
		{"pending at the timeout", counts{Pending: 1}, 1, true, true, autodomain.StepUnknown, engine.ReasonEffectUnknown},
		{
			"unconfirmed with one short of min",
			counts{Confirmed: 1, Unconfirmed: 1},
			2, false, false, autodomain.StepUnknown,
			engine.ReasonEffectUnknown,
		},
		{"nothing predicted, run ended", counts{}, 1, false, false, autodomain.StepFailed, ReasonNoEffect},
		{"nothing predicted at the timeout", counts{}, 1, true, true, autodomain.StepFailed, engine.ReasonTimeout},
	} {
		state, reason := downstreamOutcome(c.c, c.want, c.active, c.timedOut)
		if state != c.state || reason != c.reason {
			t.Errorf("%s: %s %q, want %s %q", c.name, state, reason, c.state, c.reason)
		}
		if state == autodomain.StepDone && int(c.c.Confirmed) < c.want {
			t.Errorf("%s: passed with %d confirmed of %d", c.name, c.c.Confirmed, c.want)
		}
	}
}

// countRow is a transaction that answers one count query.
type countRow struct {
	pgx.Tx
	n   int32
	err error
	sql *string
}

func (c countRow) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	*c.sql = sql
	return c
}

func (c countRow) Scan(dest ...any) error {
	if c.err != nil {
		return c.err
	}
	*dest[0].(*int32) = c.n
	return nil
}

// TestAnUnknownIrreversibleOutcomeMakesTheWaitUnknown (G0 M17 D146,
// HR-280): the next wait step of a run with an unknown irreversible
// outcome, a consequence's among them
// (TestAConsequenceWithNoKnownEffectHoldsTheIrreversibleGate has the
// count), ends UNKNOWN for a person to decide, and never retries; a run
// with none goes on, and a failed read is never taken for none.
//
// Covers: F414
func TestAnUnknownIrreversibleOutcomeMakesTheWaitUnknown(t *testing.T) {
	var sql string
	run := ids.NewV7()
	out := map[string]string{"run_state": "ENDED"}
	check := func(n int32, err error) (autodomain.StepResult, bool, error) {
		t.Helper()
		return unknownIrreversible(context.Background(), countRow{n: n, err: err, sql: &sql}, ids.OrgID{}, run, out)
	}
	res, unknown, err := check(2, nil)
	if err != nil || !unknown {
		t.Fatalf("2 unknown: %v %v", unknown, err)
	}
	if !strings.Contains(sql, "RunUnknownIrreversible") {
		t.Fatalf("read with %q", sql)
	}
	if res.State != autodomain.StepUnknown || res.Effect != autodomain.EffectUnknown || res.Reason != engine.ReasonEffectUnknown {
		t.Errorf("2 unknown: %s %s %q", res.State, res.Effect, res.Reason)
	}
	if res.Output[engine.OutputIrreversible] != "true" || res.Output["unknown_irreversible"] != "2" || res.Output["run_state"] != "ENDED" {
		t.Errorf("output: %v", res.Output)
	}
	if len(res.Refs) != 1 || res.Refs[0] != ref(reflexdomain.EvidenceRun, run) {
		t.Errorf("refs: %v", res.Refs)
	}
	if len(out) != 1 {
		t.Errorf("the caller's output changed: %v", out)
	}
	if _, unknown, err := check(0, nil); unknown || err != nil {
		t.Errorf("none unknown: %v %v", unknown, err)
	}
	if _, unknown, err := check(0, errors.New("read failed")); unknown || err == nil {
		t.Errorf("a failed read: %v %v", unknown, err)
	}
}
