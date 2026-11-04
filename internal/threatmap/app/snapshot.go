// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/tenantctx"
	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
	"github.com/katocxl/pantherclaw/internal/threatmap/domain"
	"github.com/katocxl/pantherclaw/internal/threatmap/mapset"
	"github.com/katocxl/pantherclaw/internal/threatmap/ports"
)

// Snapshot interval bounds (D719): config threat_map.snapshot_interval.
const (
	DefaultSnapshotInterval = time.Hour
	MinSnapshotInterval     = 10 * time.Second
)

// SnapshotActor is the system actor of the snapshot's audit events.
var SnapshotActor = evdomain.Actor{Type: "system", ID: "threatmap-snapshot"}

// Snapshotter takes an org's daily threat map snapshots (D719).
type Snapshotter struct {
	Pool  *db.Pool
	Ents  Entitlements
	Store ports.Store
	// Now overrides the clock; tests set it.
	Now func() time.Time
}

// SnapshotResult says what a run did.
type SnapshotResult struct {
	Scopes, Drops int
	Deleted       int64
}

// Run evaluates every scope of a Business org (the org, and each
// environment with an active agent) in both frameworks, records each lane
// that dropped since the newest stored day as threatmap.lane_lost, stores
// today's row, and deletes days older than the history keeps. An org
// without the history edition is left alone.
func (s *Snapshotter) Run(ctx context.Context, org ids.OrgID) (SnapshotResult, error) {
	var res SnapshotResult
	if s.Ents == nil {
		return res, nil
	}
	e, err := s.Ents.Current(tenantctx.WithOrg(ctx, org))
	if err != nil {
		return res, err
	}
	if !e.ThreatMapHistory() {
		return res, nil
	}
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	err = s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		res = SnapshotResult{}
		rec, err := s.Store.Records(ctx, tx, org, now)
		if err != nil {
			return err
		}
		for _, sc := range scopes(rec.Agents) {
			res.Scopes++
			for _, f := range catalog.Frameworks() {
				n, err := s.snapshot(ctx, tx, org, rec, f, sc, e, now)
				if err != nil {
					return err
				}
				res.Drops += n
			}
		}
		res.Deleted, err = s.Store.DeleteSnapshotsBefore(ctx, tx, org, now.AddDate(0, 0, -HistoryDays))
		return err
	})
	return res, err
}

// scopes are the org and every environment with an active agent, sorted.
func scopes(agents []domain.Agent) []domain.Scope {
	var envs []string
	for _, a := range agents {
		if a.Active && a.EnvironmentID != "" {
			envs = append(envs, a.EnvironmentID)
		}
	}
	slices.Sort(envs)
	out := []domain.Scope{{}}
	for _, e := range slices.Compact(envs) {
		out = append(out, domain.Scope{EnvironmentID: e})
	}
	return out
}

func (s *Snapshotter) snapshot(ctx context.Context, tx db.TenantTx, org ids.OrgID, rec ports.Records, f catalog.Framework,
	sc domain.Scope, e billing.Entitlements, now time.Time,
) (int, error) {
	in, err := inputsFor(ctx, s.Store, tx, org, rec, f, sc, e, now)
	if err != nil {
		return 0, err
	}
	m := domain.Evaluate(catalog.Load(f), mapset.Evaluator(f), in)
	snap := snapshotOf(m)
	before, ok, err := s.Store.LatestSnapshot(ctx, tx, org, sc.Key(), string(f))
	if err != nil {
		return 0, err
	}
	var drops []domain.Drop
	if ok {
		drops = domain.Drops(before.States, snap.States)
	}
	day := now.Format(time.DateOnly)
	for _, d := range drops {
		t, _ := m.Technique(d.TechniqueID)
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: auditkind.ThreatmapLaneLost, Actor: SnapshotActor, Outcome: audit.Success,
			// One lane of one technique on one day: the rule groups by it, so
			// a day's drop raises one alert (D719a).
			Object: &audit.Object{Type: "threat_lane", ID: strings.Join([]string{string(f), sc.Key(), d.TechniqueID, string(d.Lane), day}, ":")},
			Details: map[string]string{
				"framework": string(f), "technique_id": d.TechniqueID, "technique_name": t.Name, "lane": string(d.Lane),
				"from": d.From, "to": d.To, "reasons": reasons(t, d.Lane), "scope_key": sc.Key(), "day": day,
			},
		}); err != nil {
			return 0, fmt.Errorf("threatmap: record lane_lost: %w", err)
		}
	}
	return len(drops), s.Store.SaveSnapshot(ctx, tx, org, sc.Key(), string(f), snap)
}

// reasons are the dropped lane's reasons, comma-separated.
func reasons(t domain.Technique, l domain.Lane) string {
	var rs []domain.Reason
	switch l {
	case domain.LanePrevent:
		rs = t.Prevent.Reasons
	case domain.LaneDetect:
		rs = t.Detect.Reasons
	case domain.LaneRespond:
		rs = t.Respond.Reasons
	case domain.LaneTest:
		rs = t.Test.Reasons
	}
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, string(r))
	}
	return strings.Join(out, ",")
}

// snapshotOf is m's stored form.
func snapshotOf(m domain.Map) ports.Snapshot {
	s := ports.Snapshot{
		Day: m.EvaluatedAt, EvaluatedAt: m.EvaluatedAt, CatalogVersion: m.CatalogVersion, CatalogDigest: m.CatalogDigest,
		MappingDigest: m.MappingDigest, States: m.Codes(), Counts: map[string]ports.TacticCounts{},
	}
	for _, t := range m.Tactics {
		s.Counts[t.ID] = ports.TacticCounts{Evidenced: t.Evidenced, Partial: t.Partial, Gap: t.Gap, Outside: t.Outside}
	}
	return s
}

// SnapshotOrgArgs asks for one org's snapshot. Job args carry ids only
// (HR-056).
type SnapshotOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (SnapshotOrgArgs) Kind() string { return "threatmap.snapshot_org" }

// InsertOpts keeps one queued job per org.
func (SnapshotOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type snapshotWorker struct {
	river.WorkerDefaults[SnapshotOrgArgs]
	s   *Snapshotter
	log *slog.Logger
}

func (w *snapshotWorker) Work(ctx context.Context, job *river.Job[SnapshotOrgArgs]) error {
	res, err := w.s.Run(ctx, job.Args.Org)
	if err == nil && res.Scopes > 0 {
		w.log.InfoContext(ctx, "threatmap.snapshot_taken", slog.String("org", job.Args.Org.String()),
			slog.Int("scopes", res.Scopes), slog.Int("drops", res.Drops))
	}
	return err
}

// SnapshotDispatchArgs fans the snapshot out to every active org.
type SnapshotDispatchArgs struct{}

// Kind implements river.JobArgs.
func (SnapshotDispatchArgs) Kind() string { return "threatmap.snapshot" }

type snapshotDispatcher struct {
	river.WorkerDefaults[SnapshotDispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054) and enqueues one job
// per org.
func (w *snapshotDispatcher) Work(ctx context.Context, _ *river.Job[SnapshotDispatchArgs]) error {
	refs, err := w.pool.CrossOrgListAll(ctx, db.ListActiveOrgs, db.ListerPageSize)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("threatmap snapshot: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: SnapshotOrgArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// RegisterSnapshots adds the snapshot workers to reg and returns the
// schedule: the dispatcher every interval (default an hour, at least
// MinSnapshotInterval).
func RegisterSnapshots(reg *jobs.Registry, s *Snapshotter, interval time.Duration, log *slog.Logger) ([]*river.PeriodicJob, error) {
	if log == nil {
		log = pclog.Discard()
	}
	if interval == 0 {
		interval = DefaultSnapshotInterval
	}
	interval = max(interval, MinSnapshotInterval)
	if err := jobs.Register[SnapshotOrgArgs](reg, &snapshotWorker{s: s, log: log}); err != nil {
		return nil, err
	}
	if err := jobs.Register[SnapshotDispatchArgs](reg, &snapshotDispatcher{pool: s.Pool}); err != nil {
		return nil, err
	}
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(interval),
			func() (river.JobArgs, *river.InsertOpts) { return SnapshotDispatchArgs{}, nil }, nil),
	}, nil
}
