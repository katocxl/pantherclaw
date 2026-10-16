// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/exposure/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// MaxRights caps one snapshot; beyond it the snapshot says it is truncated
// and never counts as complete (posture keeps findings open on it).
const MaxRights = 100000

// batch is how many rights one insert carries.
const batch = 1000

// Snapshot is a materialized computation.
type Snapshot struct {
	ID         ids.UUID
	FeedSeq    int64
	Cause      string
	Rights     int
	Truncated  bool
	Gaps       []string
	Digest     []byte
	ComputedAt time.Time
	// Stale is set when a change was recorded after the computation
	// (F258); ChangedAt is when.
	Stale     bool
	ChangedAt *time.Time
}

// Recomputed is a recomputation's snapshot, what it read and its rights.
type Recomputed struct {
	Snapshot Snapshot
	Loaded   Loaded
	Rights   []domain.Right
}

// Recompute computes the org's reach in tx and stores it as the current
// snapshot. cause is initial, change, manual or schedule; feedSeq is the
// feed position the computation reflects.
func Recompute(ctx context.Context, tx db.TenantTx, cause string, feedSeq int64) (Recomputed, error) {
	l, err := Load(ctx, tx)
	if err != nil {
		return Recomputed{}, err
	}
	res := domain.Compute(l.Inputs)
	rights, truncated := res.Rights, false
	if len(rights) > MaxRights {
		rights, truncated = rights[:MaxRights], true
	}
	gaps := slices.Concat(res.Gaps, l.CeilingGaps)
	if len(gaps) > 64 {
		gaps = append(gaps[:63], "MORE_GAPS")
	}
	if gaps == nil {
		gaps = []string{}
	}
	s := Snapshot{
		ID: ids.NewV7(), FeedSeq: feedSeq, Cause: cause, Rights: len(rights), Truncated: truncated, Gaps: gaps,
		Digest: Digest(rights),
	}
	q := dbq.New(tx)
	s.ComputedAt, err = q.InsertExposureSnapshot(ctx, dbq.InsertExposureSnapshotParams{
		OrgID: tx.OrgID(), ID: s.ID, FeedSeq: feedSeq, Cause: cause, Rights: int32(len(rights)), //nolint:gosec // G115: ≤ MaxRights
		Truncated: truncated, Gaps: gaps, RightsSha256: s.Digest,
	})
	if err != nil {
		return Recomputed{}, err
	}
	for i := 0; i < len(rights); i += batch {
		rows := make([]row, 0, batch)
		for j, r := range rights[i:min(i+batch, len(rights))] {
			rows = append(rows, rowOf(i+j+1, r))
		}
		body, err := json.Marshal(rows)
		if err != nil {
			return Recomputed{}, err
		}
		if err := q.InsertExposureRights(ctx, tx.OrgID(), s.ID, body); err != nil {
			return Recomputed{}, err
		}
	}
	return Recomputed{Snapshot: s, Loaded: l, Rights: rights}, nil
}

// row is one right as InsertExposureRights reads it.
type row struct {
	Seq           int        `json:"seq"`
	View          string     `json:"reach_view"`
	Label         string     `json:"label"`
	Agent         *string    `json:"agent_id"`
	Connection    *string    `json:"connection_id"`
	Grant         *string    `json:"grant_id"`
	Operation     *string    `json:"operation"`
	ResourceGroup string     `json:"resource_group"`
	Verb          string     `json:"verb"`
	Coverage      string     `json:"coverage"`
	Reasons       []string   `json:"reasons"`
	Depth         int        `json:"depth"`
	ExpiresAt     *time.Time `json:"expires_at"`
	ObservedAt    *time.Time `json:"observed_at"`
	Observations  int        `json:"observations"`
	Basis         string     `json:"basis"`
	Irreversible  bool       `json:"irreversible"`
	Automations   []string   `json:"automation_ids"`
}

func rowOf(seq int, r domain.Right) row {
	var op *string
	if r.Operation != "" {
		op = &r.Operation
	}
	reasons := r.Reasons
	if len(reasons) > 16 {
		reasons = reasons[:16]
	}
	if reasons == nil {
		reasons = []string{}
	}
	return row{
		Seq: seq, View: string(r.View), Label: string(r.Label), Agent: str(r.Agent), Connection: str(r.Connection), Grant: str(r.Grant),
		Operation: op, ResourceGroup: r.ResourceGroup, Verb: string(r.Verb), Coverage: string(r.Coverage), Reasons: reasons,
		Depth: r.Depth, ExpiresAt: r.ExpiresAt, ObservedAt: r.ObservedAt, Observations: r.Observations,
		Basis: r.Basis, Irreversible: r.Irreversible, Automations: idStrings(r.Automations),
	}
}

// RightOf converts a stored right back.
func RightOf(x dbq.PcExposureRight) domain.Right {
	r := domain.Right{
		View: domain.View(x.ReachView), Label: domain.Label(x.Label), Agent: x.AgentID, Connection: x.ConnectionID,
		Grant: x.GrantID, ResourceGroup: x.ResourceGroup, Verb: domain.Verb(x.Verb), Coverage: domain.Coverage(x.Coverage),
		Reasons: x.Reasons, Depth: int(x.Depth), ExpiresAt: x.ExpiresAt, ObservedAt: x.ObservedAt,
		Observations: int(x.Observations), Basis: x.Basis, Irreversible: x.Irreversible, Automations: x.AutomationIds,
	}
	if x.Operation != nil {
		r.Operation = *x.Operation
	}
	return r
}

// Digest is the SHA-256 of the rights' keys and labels in order, so two
// computations compare cheaply.
func Digest(rights []domain.Right) []byte {
	h := sha256.New()
	for _, r := range rights {
		h.Write([]byte(r.Key() + "|" + string(r.Label) + "|" + string(r.Coverage) + "|" + strings.Join(r.Reasons, ",") + "\n"))
	}
	return h.Sum(nil)
}

// Viewer decides what the caller may see (D8): agents by the caller's
// permission where each agent lives, and credential rights (no agent)
// only at org scope. It answers from the caller's scope, never from
// whether hidden rows exist.
type Viewer interface {
	Agent(ctx context.Context, agent ids.UUID) (bool, error)
	Org() bool
}

// View is a snapshot's rights the viewer may see.
type View struct {
	Snapshot Snapshot
	Rights   []domain.Right
	// Restricted is set when the viewer's scope is narrower than the org
	// (permission-derived, never from hidden rows).
	Restricted bool
}

// Current reads the current snapshot's rights matching f that the viewer
// may see. Filtering happens row by row before anything is returned or
// counted.
func Current(ctx context.Context, tx db.TenantTx, v Viewer, f domain.Filter) (View, error) {
	q := dbq.New(tx)
	s, err := q.LatestExposureSnapshot(ctx, tx.OrgID())
	if db.IsNoRows(err) {
		return View{}, ErrNoSnapshot
	} else if err != nil {
		return View{}, err
	}
	out := View{Snapshot: Snapshot{
		ID: s.ID, FeedSeq: s.FeedSeq, Cause: s.Cause, Rights: int(s.Rights), Truncated: s.Truncated, Gaps: s.Gaps,
		Digest: s.RightsSha256, ComputedAt: s.ComputedAt, Stale: s.Stale, ChangedAt: s.ChangedAt,
	}, Restricted: !v.Org()}
	if f.Agent != nil {
		if ok, err := v.Agent(ctx, *f.Agent); err != nil || !ok {
			return out, err
		}
	}
	cache := map[ids.UUID]bool{}
	after := int32(0)
	for {
		rows, err := q.ListExposureRights(ctx, dbq.ListExposureRightsParams{
			OrgID: tx.OrgID(), SnapshotID: s.ID, After: after, AgentID: f.Agent, ConnectionID: f.Connection, MaxRows: 5000,
		})
		if err != nil {
			return View{}, err
		}
		for _, x := range rows {
			after = x.Seq
			r := RightOf(x)
			if !f.Match(r) {
				continue
			}
			ok, err := visible(ctx, v, cache, r)
			if err != nil {
				return View{}, err
			}
			if ok {
				out.Rights = append(out.Rights, r)
			}
		}
		if len(rows) < 5000 {
			return out, nil
		}
	}
}

func visible(ctx context.Context, v Viewer, cache map[ids.UUID]bool, r domain.Right) (bool, error) {
	if r.Agent == nil {
		return v.Org(), nil
	}
	if ok, seen := cache[*r.Agent]; seen {
		return ok, nil
	}
	ok, err := v.Agent(ctx, *r.Agent)
	if err != nil {
		return false, err
	}
	cache[*r.Agent] = ok
	return ok, nil
}

// Preview computes before and after a reduction on the org's live inputs
// in tx (F259): grants revoked take every grant delegated from them along.
// Nothing is stored.
func Preview(ctx context.Context, tx db.TenantTx, c domain.Change) (domain.Diff, error) {
	l, err := Load(ctx, tx)
	if err != nil {
		return domain.Diff{}, err
	}
	if c.Descendants == nil {
		c.Descendants = l.Descendants
	}
	return domain.Preview(l.Inputs, c), nil
}

// FilterVisible keeps the rights the viewer may see.
func FilterVisible(ctx context.Context, v Viewer, rights []domain.Right) ([]domain.Right, error) {
	cache := map[ids.UUID]bool{}
	return filterFunc(rights, func(r domain.Right) (bool, error) { return visible(ctx, v, cache, r) })
}

func filterFunc(rights []domain.Right, keep func(domain.Right) (bool, error)) ([]domain.Right, error) {
	out := slices.Grow([]domain.Right(nil), len(rights))
	for _, r := range rights {
		ok, err := keep(r)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, r)
		}
	}
	return out, nil
}

func str(u *ids.UUID) *string {
	if u == nil {
		return nil
	}
	s := u.String()
	return &s
}

// maxRowAutomations is how many automations a stored right names (the
// column's bound); a path that many automations reach is never usual.
const maxRowAutomations = 64

func idStrings(us []ids.UUID) []string {
	out := make([]string, 0, min(len(us), maxRowAutomations))
	for _, u := range us[:min(len(us), maxRowAutomations)] {
		out = append(out, u.String())
	}
	return out
}
