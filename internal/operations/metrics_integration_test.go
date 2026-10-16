// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package operations_test

import (
	"context"
	"errors"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/operations"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type edition billing.Edition

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Edition(e)}, nil
}

// TestHR258_MetricsNeverReadAMissingSourceAsZero (D33, F301): a source
// that is not collected reads NOT_COLLECTED and an hour without a sample
// NO_SAMPLE, never 0; collected counts carry their drill-down search; the
// metrics need Team and operations.read across the organization.
func TestHR258_MetricsNeverReadAMissingSourceAsZero(t *testing.T) {
	f := newFx(t)
	run := ids.NewV7()
	f.exec(`INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_user_id, principal_user_id, principal_source, expires_at)
		SELECT $1, $2, $3, environment_id, $4, $4, 'launcher', now() + interval '8 hours' FROM pc.agents WHERE id = $3`,
		f.org, run, f.agentA, f.user)
	for _, d := range []string{"DENY", "DENY", "ALLOW"} {
		f.exec(`INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id, state)
			VALUES ($1, $2, $3, $4, $5, 'payments.refund.create', $6, 'R', 'gw', 'OPEN')`, f.org, ids.NewV7(), run, ids.NewV7(), make([]byte, 32), d)
	}
	// The transactions are this hour's; the collector samples the last full
	// hour, so move them back one.
	f.d.AdminExec(t, `UPDATE pc.transactions SET created_at = date_trunc('hour', now()) - interval '30 minutes' WHERE org_id = $1`, f.org)

	c := &operations.Collector{Pool: f.p, Ents: edition(billing.Team), Failures: &failures.Sink{}}
	n, err := c.Collect(context.Background(), f.org)
	if err != nil || n == 0 {
		t.Fatalf("collect: %d %v", n, err)
	}
	if again, err := c.Collect(context.Background(), f.org); err != nil || again != 0 {
		t.Fatalf("a second collection wrote %d samples: %v", again, err)
	}

	f.s.Ents = edition(billing.Team)
	now := time.Now().UTC().Truncate(time.Hour)
	m, err := f.s.GetMetrics(f.orgWide(), nil, now.Add(-30*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	last := now.Add(-time.Hour)
	point := func(metric string, at time.Time) operations.Point {
		for _, s := range m.Series {
			if s.Metric == metric && s.Dimension == "" {
				for _, p := range s.Points {
					if p.Bucket.Equal(at) {
						return p
					}
				}
			}
		}
		t.Fatalf("no %s point at %s", metric, at)
		return operations.Point{}
	}
	if p := point(operations.MetricDecisionsDenied, last); p.State != operations.Collected || p.Value != 2 || p.Drill == nil || p.Drill.Query == nil {
		t.Fatalf("denied: %+v", p)
	}
	if p := point(operations.MetricAutomationOutcomes, last); p.State != operations.Collected || p.Value != 0 {
		t.Fatalf("automation outcomes: %+v", p)
	}
	if p := point(operations.MetricExposureUsable, last); p.State != operations.NotCollected {
		t.Fatalf("exposure without a snapshot: %+v", p)
	}
	// Collection reaches back 24 hours; the hours before have no sample.
	if p := point(operations.MetricDecisionsDenied, now.Add(-29*time.Hour)); p.State != operations.NoSample || p.Value != 0 {
		t.Fatalf("hour without a sample: %+v", p)
	}

	if _, err := f.s.GetMetrics(f.teamOf(f.teamA), nil, now.Add(-time.Hour), now); !errors.Is(err, operations.ErrMetricsScope) {
		t.Fatalf("team viewer: %v", err)
	}
	f.s.Ents = edition(billing.Community)
	var pe *pcerr.Error
	if _, err := f.s.GetMetrics(f.orgWide(), nil, now.Add(-time.Hour), now); !errors.As(err, &pe) || pe.Reason() != "EDITION_REQUIRED" {
		t.Fatalf("community: %v", err)
	}
	if _, err := f.s.GetMetrics(f.orgWide(), nil, now.Add(-31*24*time.Hour), now); err == nil {
		t.Fatal("a 31-day range was read")
	}
}

// TestHR258_EachMetricNeedsItsSourcePermission (D69 M7): a Viewer holds
// operations.read across the org but neither evidence.read, coverage.read
// nor exposure.read: those metrics read RESTRICTED, with no dimension or
// drill-down, and only the automation metric is shown.
func TestHR258_EachMetricNeedsItsSourcePermission(t *testing.T) {
	f := newFx(t)
	c := &operations.Collector{Pool: f.p, Ents: edition(billing.Team), Failures: &failures.Sink{}}
	if _, err := c.Collect(context.Background(), f.org); err != nil {
		t.Fatal(err)
	}
	f.s.Ents = edition(billing.Team)
	now := time.Now().UTC().Truncate(time.Hour)
	viewer := f.as(td.RoleViewer, td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()})
	m, err := f.s.GetMetrics(viewer, nil, now.Add(-2*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range m.Series {
		want := operations.PointRestricted
		if s.Metric == operations.MetricAutomationOutcomes {
			want = operations.Collected
		}
		if s.Dimension != "" {
			t.Fatalf("%s leaks a dimension %q", s.Metric, s.Dimension)
		}
		last := s.Points[len(s.Points)-1]
		if last.State != want || (want == operations.PointRestricted && last.Drill != nil) {
			t.Fatalf("%s: %+v, want %s", s.Metric, last, want)
		}
	}
}
