// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package operations

import (
	"context"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Freshness of a telemetry source (F219).
type Freshness string

// Freshness values. STALE and NEVER are gaps; RESTRICTED says the viewer
// may not see the source, NOT_AVAILABLE that this server does not collect
// it yet.
const (
	Fresh        Freshness = "FRESH"
	Stale        Freshness = "STALE"
	Never        Freshness = "NEVER"
	Restricted   Freshness = "RESTRICTED"
	NotAvailable Freshness = "NOT_AVAILABLE"
)

// Source kinds.
const (
	SourceGateway    = "gateway"
	SourceSDK        = "sdk"
	SourceHook       = "hook"
	SourceSandbox    = "sandbox"
	SourceLedger     = "ledger"
	SourceDetections = "detections"
	SourceExport     = "export"
)

// closureKind is the ledger kind of a sandbox closure
// (coverage/app.ClosureLedgerKind).
const closureKind = "sandbox.closure"

// Staleness thresholds per source kind. A gateway renews its 24-hour
// certificate well before expiry, so a gateway neither deciding nor
// renewing for 26 hours is down; the chainer runs every 2 seconds and the
// detection dispatcher every 5.
var staleAfter = map[string]time.Duration{
	SourceGateway:    26 * time.Hour,
	SourceSDK:        24 * time.Hour,
	SourceHook:       24 * time.Hour,
	SourceSandbox:    7 * 24 * time.Hour,
	SourceLedger:     time.Minute,
	SourceDetections: 2 * time.Minute,
}

// SourceStatus is one telemetry source (F219, F640). LastSeen is nil when
// it was never seen; a gap is any source that is STALE or NEVER.
type SourceStatus struct {
	Kind      string
	Name      string
	ID        string
	LastSeen  *time.Time
	Freshness Freshness
	// Lag is how many feed entries detection has yet to read.
	Lag  int64
	Note string
}

// Gap reports whether the source is a gap in the evidence.
func (s SourceStatus) Gap() bool { return s.Freshness == Stale || s.Freshness == Never }

// EvidenceStatus is every source with the time it was read.
type EvidenceStatus struct {
	AsOf    time.Time
	Sources []SourceStatus
}

func freshness(kind string, last *time.Time, now time.Time) Freshness {
	switch {
	case last == nil:
		return Never
	case now.Sub(*last) > staleAfter[kind]:
		return Stale
	default:
		return Fresh
	}
}

// GetEvidenceStatus returns each source's last-seen time and freshness.
// Org-wide sources (gateways, the ledger chain, detections) need
// operations.read at the org and read RESTRICTED otherwise; the SDK and
// hook channels are read over the viewer's agents only.
func (s *Service) GetEvidenceStatus(ctx context.Context) (EvidenceStatus, error) {
	var out EvidenceStatus
	err := s.read(ctx, func(ctx context.Context, v *viewer) error {
		var err error
		out, err = evidenceStatus(ctx, v)
		return err
	})
	return out, err
}

func evidenceStatus(ctx context.Context, v *viewer) (EvidenceStatus, error) {
	now, err := v.q.OpsDBNow(ctx)
	if err != nil {
		return EvidenceStatus{}, err
	}
	now = now.UTC()
	out := EvidenceStatus{AsOf: now}
	add := func(kind, name, id string, last *time.Time) {
		out.Sources = append(out.Sources, SourceStatus{Kind: kind, Name: name, ID: id, LastSeen: last, Freshness: freshness(kind, last, now)})
	}
	org := v.whole(td.PermOperationsRead)
	if org {
		gws, err := v.q.OpsGatewaysLastSeen(ctx, v.c.Org)
		if err != nil {
			return EvidenceStatus{}, err
		}
		for _, g := range gws {
			add(SourceGateway, g.Name, g.ID.String(), never(g.LastSeen))
		}
		chain, err := v.q.OpsChainState(ctx, v.c.Org)
		if err != nil {
			return EvidenceStatus{}, err
		}
		add(SourceLedger, "evidence chain", "", never(chain.LastChained))
		if err := detections(ctx, v, chain.Head, now, &out); err != nil {
			return EvidenceStatus{}, err
		}
		last, err := v.q.OpsLedgerKindLastSeen(ctx, v.c.Org, closureKind)
		if err != nil {
			return EvidenceStatus{}, err
		}
		add(SourceSandbox, "sandbox closures", "", never(last))
	} else {
		for _, k := range []string{SourceGateway, SourceLedger, SourceDetections, SourceSandbox} {
			out.Sources = append(out.Sources, SourceStatus{
				Kind: k, Freshness: Restricted,
				Note: "needs operations.read across the organization",
			})
		}
	}
	sc, err := v.scope(ctx, td.PermOperationsRead)
	if err != nil {
		return EvidenceStatus{}, err
	}
	for _, ch := range []string{SourceSDK, SourceHook} {
		if sc.Restricted {
			out.Sources = append(out.Sources, SourceStatus{Kind: ch, Freshness: Restricted})
			continue
		}
		agents := sc.Agents
		if agents == nil {
			agents = []ids.UUID{}
		}
		last, err := v.q.OpsChannelLastSeen(ctx, dbq.OpsChannelLastSeenParams{
			OrgID: v.c.Org, Channel: ch, AllAgents: sc.All, Agents: agents,
		})
		if err != nil {
			return EvidenceStatus{}, err
		}
		add(ch, ch+" channel", "", never(last))
	}
	out.Sources = append(out.Sources, SourceStatus{
		Kind: SourceExport, Freshness: NotAvailable,
		Note: "export delivery health is reported once SIEM export is configured",
	})
	return out, nil
}

// detections reports the detection engine: when its cursor last moved and
// how far it is behind the feed head.
func detections(ctx context.Context, v *viewer, head int64, now time.Time, out *EvidenceStatus) error {
	cur, err := v.q.OpsDetectionCursor(ctx, v.c.Org)
	switch {
	case db.IsNoRows(err):
		st := SourceStatus{Kind: SourceDetections, Name: "detection engine", Freshness: Never, Lag: head}
		if head == 0 {
			st.Note = "no evidence recorded yet"
		}
		out.Sources = append(out.Sources, st)
		return nil
	case err != nil:
		return err
	}
	last := cur.UpdatedAt.UTC()
	st := SourceStatus{Kind: SourceDetections, Name: "detection engine", LastSeen: &last, Lag: max(head-cur.Seq, 0)}
	// A cursor that is caught up is fresh however long ago it moved; one
	// behind the head and not moving is a gap.
	st.Freshness = Fresh
	if st.Lag > 0 && now.Sub(last) > staleAfter[SourceDetections] {
		st.Freshness = Stale
	}
	out.Sources = append(out.Sources, st)
	return nil
}
