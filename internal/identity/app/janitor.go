// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// JanitorInterval is how often identity rows are cleaned up.
const JanitorInterval = time.Minute

// Swept counts what one janitor run did for an org.
type Swept struct {
	Proofs, Nonces, Instances, Runs int64
}

// SweepOrg cleans one org (G0 M3 constraints 8 and 17): replay rows whose
// nonce expired more than 60 seconds ago, in the slots that can hold them,
// and old nonces (PAP-1 §4); pending instances past their admission
// deadline become EXPIRED with their ADMISSION entries; runs past their
// expiry are recorded EXPIRED (they already read so).
func SweepOrg(ctx context.Context, pool *db.Pool, org ids.OrgID) (Swept, error) {
	var sw Swept
	err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		minute, err := q.CurrentMinute(ctx)
		if err != nil {
			return err
		}
		// A nonce of minute m expires at m+6 and its rows go from m+7.
		before := minute - 6
		slots := make([]int16, 0, pap.ReplaySlots)
		for i := range int64(pap.ReplaySlots) {
			slots = append(slots, pap.Slot(i))
		}
		if sw.Proofs, err = q.DeleteExpiredProofs(ctx, org, slots, before); err != nil {
			return err
		}
		if sw.Nonces, err = q.DeleteExpiredNonces(ctx, org, before); err != nil {
			return err
		}
		expired, err := q.ExpirePendingInstances(ctx, org)
		if err != nil {
			return err
		}
		for _, in := range expired {
			if _, err := q.CloseSubjectEntry(ctx, dbq.CloseSubjectEntryParams{
				OrgID: org, SubjectType: "instance", SubjectID: in.ID, State: "EXPIRED", Reason: "admission deadline passed",
			}); err != nil {
				return err
			}
			if err := agents.RecordChange(ctx, q, org, in.AgentID, adomain.Change{
				Kind: adomain.ChangeInstanceExpired, Actor: adomain.System, Details: map[string]string{"instance_id": in.ID.String()},
			}); err != nil {
				return err
			}
		}
		sw.Instances = int64(len(expired))
		sw.Runs, err = q.ExpireRuns(ctx, org)
		return err
	})
	return sw, err
}

// JanitorOrgArgs asks for one org to be swept. Job args carry ids only
// (HR-056).
type JanitorOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (JanitorOrgArgs) Kind() string { return "identity.janitor_org" }

// InsertOpts keeps one queued job per org.
func (JanitorOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type janitorOrgWorker struct {
	river.WorkerDefaults[JanitorOrgArgs]
	pool *db.Pool
	log  *slog.Logger
}

func (w *janitorOrgWorker) Work(ctx context.Context, job *river.Job[JanitorOrgArgs]) error {
	sw, err := SweepOrg(ctx, w.pool, job.Args.Org)
	if err == nil && sw.Instances+sw.Runs > 0 {
		w.log.InfoContext(ctx, "identity.janitor", slog.String("org", job.Args.Org.String()),
			slog.Int64("instances_expired", sw.Instances), slog.Int64("runs_expired", sw.Runs))
	}
	return err
}

// JanitorDispatchArgs fans the janitor out to every active org.
type JanitorDispatchArgs struct{}

// Kind implements river.JobArgs.
func (JanitorDispatchArgs) Kind() string { return "identity.janitor_dispatch" }

type janitorDispatchWorker struct {
	river.WorkerDefaults[JanitorDispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054) and enqueues one job
// per org.
func (w *janitorDispatchWorker) Work(ctx context.Context, _ *river.Job[JanitorDispatchArgs]) error {
	refs, err := w.pool.CrossOrgListAll(ctx, db.ListActiveOrgs, db.ListerPageSize)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("identity janitor: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: JanitorOrgArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// RegisterJanitor adds the janitor workers to reg.
func RegisterJanitor(reg *jobs.Registry, pool *db.Pool, log *slog.Logger) error {
	if log == nil {
		log = pclog.Discard()
	}
	if err := jobs.Register[JanitorOrgArgs](reg, &janitorOrgWorker{pool: pool, log: log}); err != nil {
		return err
	}
	return jobs.Register[JanitorDispatchArgs](reg, &janitorDispatchWorker{pool: pool})
}

// JanitorPeriodicJobs returns the janitor schedule.
func JanitorPeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(JanitorInterval),
			func() (river.JobArgs, *river.InsertOpts) { return JanitorDispatchArgs{}, nil }, nil),
	}
}
