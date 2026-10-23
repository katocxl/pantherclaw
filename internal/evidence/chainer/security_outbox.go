// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package chainer

import (
	"context"
	"errors"
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
	const capOrgs = 10000
	refs, err := w.Pool.CrossOrgList(ctx, db.ListAllOrgs, capOrgs)
	if err != nil {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return err
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, ref := range refs {
		params = append(params, river.InsertManyParams{Args: SecurityOrgArgs{Org: ref.Org}})
	}
	if len(params) > 0 {
		if _, err := client.InsertMany(ctx, params); err != nil {
			return err
		}
	}
	if len(refs) == capOrgs {
		w.Log.ErrorContext(ctx, "security_event.dispatch_capped", slog.Int("org_cap", capOrgs))
		return errors.New("security-event dispatcher reached 10000-org lister cap; paging required")
	}
	return nil
}
