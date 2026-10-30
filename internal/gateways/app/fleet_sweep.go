// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"time"

	"github.com/riverqueue/river"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/tenantctx"
)

// The fleet sweep (G0 M18 D151, HR-470, HR-471). Every SweepInterval it
// fans out to one job per active org; an org entitled to the fleet policy
// (Enterprise) gets, for each active gateway:
//   - one gateway.silent when its last report is older than the org's
//     silence threshold, and one gateway.recovered when it reports again;
//   - one gateway.below_minimum per version below the org's minimum that
//     its live replicas report, an unknown version counting as below.
//
// The alert state (00217) is changed in the same transaction as the
// notifications are enqueued, so a retried sweep sends nothing twice. The
// sweep never refuses or changes what a gateway is served (HR-470).
const (
	SweepInterval = time.Minute
	// sweepBatch is how many gateways one query reads.
	sweepBatch = 500
)

// FleetSweepArgs fans the fleet sweep out to every active org.
type FleetSweepArgs struct{}

// Kind implements river.JobArgs.
func (FleetSweepArgs) Kind() string { return "gateway_fleet.sweep" }

// FleetSweepOrgArgs sweeps one org's fleet.
type FleetSweepOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (FleetSweepOrgArgs) Kind() string { return "gateway_fleet.sweep_org" }

// InsertOpts keeps one queued job per org.
func (FleetSweepOrgArgs) InsertOpts() river.InsertOpts { return uniqueQueued }

// SweepResult counts the alerts one sweep sent.
type SweepResult struct {
	Silent, Recovered, BelowMinimum int
}

// Sweep raises and clears org's silence and version alerts. An org not
// entitled to the fleet policy is skipped.
func (f *Fleet) Sweep(ctx context.Context, org ids.OrgID) (SweepResult, error) {
	var res SweepResult
	if err := f.entitled(tenantctx.WithOrg(ctx, org), billing.Entitlements.FleetPolicy, ErrFleetPolicyEdition); errors.Is(err, ErrFleetPolicyEdition) {
		return res, nil
	} else if err != nil {
		return res, err
	}
	err := f.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.LockGatewayAlertState(ctx, org.UUID()); err != nil {
			return err
		}
		policy, err := fleetPolicy(ctx, q, org)
		if err != nil {
			return err
		}
		now := f.clk.Now()
		var after ids.UUID
		for {
			gws, err := q.ListActiveGatewayIDs(ctx, org, after, sweepBatch)
			if err != nil || len(gws) == 0 {
				return err
			}
			replicas, err := q.ListGatewayReplicas(ctx, org, gws, time.Time{})
			if err != nil {
				return err
			}
			byGateway := make(map[ids.UUID][]dbq.PcGatewayReplica, len(gws))
			for _, r := range replicas {
				byGateway[r.GatewayID] = append(byGateway[r.GatewayID], r)
			}
			alerts, err := alertStates(ctx, q, org, gws)
			if err != nil {
				return err
			}
			for _, gw := range gws {
				st := alerts[gw]
				st.OrgID, st.GatewayID = org, gw
				next, msgs := evaluate(gw, policy, byGateway[gw], st, now)
				if next == st {
					continue
				}
				if err := q.UpsertGatewayAlertState(ctx, dbq.UpsertGatewayAlertStateParams{
					OrgID: org, GatewayID: gw, SilentSince: next.SilentSince, SilentNotifiedAt: next.SilentNotifiedAt,
					BelowMinimumVersion: next.BelowMinimumVersion, BelowMinimumNotifiedAt: next.BelowMinimumNotifiedAt,
				}); err != nil {
					return err
				}
				for _, m := range msgs {
					switch m.Type {
					case "gateway.silent":
						res.Silent++
					case "gateway.recovered":
						res.Recovered++
					case "gateway.below_minimum":
						res.BelowMinimum++
					}
					if f.notify == nil {
						continue
					}
					m.Org = org
					if _, err := f.notify.Enqueue(ctx, tx, m); err != nil {
						return err
					}
				}
			}
			if len(gws) < sweepBatch {
				return nil
			}
			after = gws[len(gws)-1]
		}
	})
	return res, err
}

// evaluate returns a gateway's next alert state and the notifications the
// change sends. Silence is judged on the gateway's last report time, which
// is never pruned (D167): a gateway that never reported is not silent, and
// one silent for longer than the replica retention still is. Versions are
// judged on live replicas only, so a silent gateway keeps its version alert.
func evaluate(gw ids.UUID, p FleetPolicy, replicas []dbq.PcGatewayReplica, st dbq.PcGatewayAlertState, now time.Time,
) (dbq.PcGatewayAlertState, []napp.Message) {
	next := dbq.PcGatewayAlertState{
		OrgID: st.OrgID, GatewayID: gw, LastReportAt: st.LastReportAt, SilentSince: st.SilentSince, SilentNotifiedAt: st.SilentNotifiedAt,
		BelowMinimumVersion: st.BelowMinimumVersion, BelowMinimumNotifiedAt: st.BelowMinimumNotifiedAt,
	}
	var msgs []napp.Message
	id := gw.String()
	var live []dbq.PcGatewayReplica
	for _, r := range replicas {
		if now.Sub(r.LastSeen) < p.SilenceAfter {
			live = append(live, r)
		}
	}
	reported := st.LastReportAt != nil
	silent := reported && now.Sub(*st.LastReportAt) >= p.SilenceAfter
	switch {
	case silent && next.SilentSince == nil:
		since := *st.LastReportAt
		next.SilentSince, next.SilentNotifiedAt = &since, &now
		msgs = append(msgs, napp.Message{
			Type: "gateway.silent", DedupeKey: "gateway.silent:" + id + ":" + strconv.FormatInt(since.UnixMicro(), 10),
			Params: map[string]string{
				"gateway": id, "since": since.UTC().Format(time.RFC3339),
				"threshold": strconv.FormatInt(int64(p.SilenceAfter/time.Second), 10),
			},
		})
	case reported && !silent && next.SilentSince != nil:
		since := *next.SilentSince
		next.SilentSince, next.SilentNotifiedAt = nil, nil
		msgs = append(msgs, napp.Message{
			Type: "gateway.recovered", DedupeKey: "gateway.recovered:" + id + ":" + strconv.FormatInt(since.UnixMicro(), 10),
			Params: map[string]string{"gateway": id, "since": since.UTC().Format(time.RFC3339)},
		})
	}
	if !p.MinimumVersion.Known() {
		next.BelowMinimumVersion, next.BelowMinimumNotifiedAt = nil, nil
		return next, msgs
	}
	if len(live) == 0 {
		return next, msgs
	}
	var worst *Version
	for _, r := range live {
		v, _ := ParseVersion(r.Version)
		if Compliant(v, p.MinimumVersion) {
			continue
		}
		if worst == nil || !v.Known() || (worst.Known() && v.Compare(*worst) < 0) {
			worst = &v
		}
	}
	if worst == nil {
		next.BelowMinimumVersion, next.BelowMinimumNotifiedAt = nil, nil
		return next, msgs
	}
	shown := worst.String()
	if next.BelowMinimumVersion != nil && *next.BelowMinimumVersion == shown {
		return next, msgs
	}
	next.BelowMinimumVersion, next.BelowMinimumNotifiedAt = &shown, &now
	msgs = append(msgs, napp.Message{
		Type: "gateway.below_minimum", DedupeKey: "gateway.below_minimum:" + id + ":" + shown + ":" + strconv.FormatInt(now.UnixMicro(), 10),
		Params: map[string]string{"gateway": id, "version": shown, "minimum": p.MinimumVersion.String()},
	})
	return next, msgs
}

type fleetSweepWorker struct {
	river.WorkerDefaults[FleetSweepArgs]
	pool *db.Pool
}

func (w *fleetSweepWorker) Work(ctx context.Context, _ *river.Job[FleetSweepArgs]) error {
	return fanOut(ctx, w.pool, func(o ids.OrgID) river.JobArgs { return FleetSweepOrgArgs{Org: o} })
}

type fleetSweepOrgWorker struct {
	river.WorkerDefaults[FleetSweepOrgArgs]
	f   *Fleet
	log *slog.Logger
}

func (w *fleetSweepOrgWorker) Work(ctx context.Context, job *river.Job[FleetSweepOrgArgs]) error {
	r, err := w.f.Sweep(ctx, job.Args.Org)
	if r != (SweepResult{}) {
		w.log.InfoContext(ctx, "gateway_fleet.swept", slog.String("org", job.Args.Org.String()),
			slog.Int("silent", r.Silent), slog.Int("recovered", r.Recovered), slog.Int("below_minimum", r.BelowMinimum))
	}
	return err
}

// RegisterJobs adds the fleet sweep workers to reg.
func (f *Fleet) RegisterJobs(reg *jobs.Registry, log *slog.Logger) error {
	if log == nil {
		log = pclog.Discard()
	}
	if err := jobs.Register[FleetSweepArgs](reg, &fleetSweepWorker{pool: f.pool}); err != nil {
		return err
	}
	return jobs.Register[FleetSweepOrgArgs](reg, &fleetSweepOrgWorker{f: f, log: log})
}

// FleetPeriodicJobs returns the fleet sweep schedule.
func FleetPeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(SweepInterval),
			func() (river.JobArgs, *river.InsertOpts) { return FleetSweepArgs{}, nil }, nil),
	}
}
