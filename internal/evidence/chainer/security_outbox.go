// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package chainer

import (
	"context"
	"log/slog"

	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/evidence/securityevent"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

// SecurityOrgArgs retries one bounded page of unacknowledged events.
type SecurityOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

func (SecurityOrgArgs) Kind() string                 { return "evidence.security_log_org" }
func (SecurityOrgArgs) InsertOpts() river.InsertOpts { return (ChainOrgArgs{}).InsertOpts() }

type SecurityOrgWorker struct {
	river.WorkerDefaults[SecurityOrgArgs]
	Pool *db.Pool
	Log  *slog.Logger
}

func (w *SecurityOrgWorker) Work(ctx context.Context, job *river.Job[SecurityOrgArgs]) error {
	events, err := securityevent.Attempt(ctx, w.Pool, job.Args.Org)
	if err != nil {
		return err
	}
	for _, e := range events {
		securityevent.Emit(ctx, w.Log, e)
	}
	return nil
}

// SecurityDispatchArgs retries independently of new ledger entries; an
// otherwise idle org must not lose the event at the commit-to-log gap.
type SecurityDispatchArgs struct{}

func (SecurityDispatchArgs) Kind() string { return "evidence.security_log_dispatch" }

type SecurityDispatchWorker struct {
	river.WorkerDefaults[SecurityDispatchArgs]
	Pool *db.Pool
	Log  *slog.Logger
}

func (w *SecurityDispatchWorker) Work(ctx context.Context, _ *river.Job[SecurityDispatchArgs]) error {
	// Every org, in pages (D45), one InsertMany per page.
	return w.Pool.CrossOrgPages(ctx, db.ListAllOrgs, db.ListerPageSize, func(page []db.OrgRef) error {
		client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
		if err != nil {
			return err
		}
		params := make([]river.InsertManyParams, 0, len(page))
		for _, ref := range page {
			params = append(params, river.InsertManyParams{Args: SecurityOrgArgs{Org: ref.Org}})
		}
		_, err = client.InsertMany(ctx, params)
		return err
	})
}
