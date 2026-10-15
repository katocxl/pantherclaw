// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package operations

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Summary is the freshness-qualified summary (F212, HR-258): counts within
// the viewer's scope, stamped with that scope and the as-of time, and what
// is not known. It never states that there are no issues: an empty count
// is a count within a scope and a time, beside the gaps that could hide
// something.
type Summary struct {
	AsOf time.Time
	// Whole reports that the counts cover the whole organization;
	// otherwise only the agents in the viewer's scope.
	Whole     bool
	Scope     string
	Counts    map[string]int
	Truncated bool
	// Unknown lists what the summary cannot vouch for: telemetry gaps,
	// restricted sources and sources not reported yet.
	Unknown   []string
	Statement string
}

// Summary count keys.
const (
	CountActiveIncidents        = "active_incidents"
	CountOpenAlerts             = "open_alerts"
	CountCritical               = "critical"
	CountProtectionFailures     = "protection_failures"
	CountExpiringDecisions      = "expiring_decisions"
	CountAuthorityExpansion     = "authority_expansion_24h"
	CountTelemetryGaps          = "telemetry_gaps"
	CountUnconfirmedContainment = "unconfirmed_containment"
	CountPostureFindings        = "posture_findings"
)

// GetSummary returns the viewer's summary.
func (s *Service) GetSummary(ctx context.Context) (Summary, error) {
	if _, err := operator(ctx); err != nil {
		return Summary{}, err
	}
	x, err := s.readSources(ctx)
	if err != nil {
		return Summary{}, err
	}
	var out Summary
	err = s.read(ctx, func(ctx context.Context, v *viewer) error {
		q, err := workQueue(ctx, v, x)
		if err != nil {
			return err
		}
		es, err := evidenceStatus(ctx, v, x)
		if err != nil {
			return err
		}
		out = summarize(q, es)
		return nil
	})
	return out, err
}

func summarize(q Queue, es EvidenceStatus) Summary {
	out := Summary{AsOf: q.AsOf, Whole: q.Whole, Truncated: q.Truncated, Counts: map[string]int{
		CountActiveIncidents: 0, CountOpenAlerts: 0, CountCritical: 0, CountProtectionFailures: 0,
		CountExpiringDecisions: 0, CountAuthorityExpansion: 0, CountTelemetryGaps: 0, CountUnconfirmedContainment: 0,
		CountPostureFindings: 0,
	}}
	out.Scope = "what your permissions cover"
	if q.Whole {
		out.Scope = "the whole organization"
	}
	// Counted from every item read, before the queue was cut to its length
	// (D69 M4).
	out.Counts[CountActiveIncidents] = q.Counts[KindIncident]
	out.Counts[CountOpenAlerts] = q.Counts[KindAlert]
	out.Counts[CountProtectionFailures] = q.Counts[KindProtectionFailure]
	out.Counts[CountExpiringDecisions] = q.Counts[KindWaitingDecision]
	out.Counts[CountUnconfirmedContainment] = q.Counts[KindUnconfirmedContainment]
	out.Counts[CountPostureFindings] = q.Counts[KindPostureFinding]
	out.Counts[CountAuthorityExpansion] = q.Counts[KindAuthorityExpansion]
	out.Counts[CountCritical] = q.Critical
	for _, src := range es.Sources {
		label := src.Name
		if label == "" {
			label = src.Kind
		}
		switch {
		case src.Gap():
			out.Counts[CountTelemetryGaps]++
			if src.LastSeen == nil {
				out.Unknown = append(out.Unknown, label+": never seen")
			} else {
				out.Unknown = append(out.Unknown, label+": not seen since "+src.LastSeen.Format(time.RFC3339))
			}
		case src.Freshness == Restricted:
			out.Unknown = append(out.Unknown, label+": outside your permissions")
		case src.Freshness == NotAvailable:
			out.Unknown = append(out.Unknown, label+": not reported yet")
		}
	}
	out.Unknown = append(out.Unknown, q.Pending...)
	if !q.Whole {
		out.Unknown = append(out.Unknown, "agents and kinds outside your permissions are not counted")
	}
	if q.Truncated {
		out.Unknown = append(out.Unknown, "more items exist than were read")
	}
	out.Statement = statement(out)
	return out
}

func statement(s Summary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "As of %s, for %s: %d active incidents, %d unconfirmed containment actions, %d open alerts (%d critical), "+
		"%d protection failures, %d decisions expiring within the hour, %d open posture findings, "+
		"%d authority expansions in the last day.",
		s.AsOf.Format(time.RFC3339), s.Scope, s.Counts[CountActiveIncidents], s.Counts[CountUnconfirmedContainment],
		s.Counts[CountOpenAlerts], s.Counts[CountCritical], s.Counts[CountProtectionFailures],
		s.Counts[CountExpiringDecisions], s.Counts[CountPostureFindings], s.Counts[CountAuthorityExpansion])
	if len(s.Unknown) > 0 {
		b.WriteString(" Not known: " + strings.Join(s.Unknown, "; ") + ".")
	}
	b.WriteString(" These counts cover only what PantherClaw records in this scope; they are not a statement that nothing is wrong.")
	return b.String()
}
