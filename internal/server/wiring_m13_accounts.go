// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"time"

	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/accounts"
	"github.com/katocxl/pantherclaw/internal/datarequests"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

func newAccountDeletion(store *accounts.Store, data *datarequests.Service) *accounts.Deletion {
	d := accounts.NewDeletion(store, data.RecordDeletedAccount, data.RecordAccountDeletionIntent)
	data.ReapplyAccount = d.Reapply
	return d
}

type accountDeletionArgs struct{}

func (accountDeletionArgs) Kind() string { return "accounts.deletion_resume" }

type accountDeletionWorker struct {
	river.WorkerDefaults[accountDeletionArgs]
	d *accounts.Deletion
}

func (w *accountDeletionWorker) Work(ctx context.Context, _ *river.Job[accountDeletionArgs]) error {
	return w.d.ResumePending(ctx)
}

func registerAccountDeletion(reg *jobs.Registry, d *accounts.Deletion) ([]*river.PeriodicJob, error) {
	if err := jobs.Register[accountDeletionArgs](reg, &accountDeletionWorker{d: d}); err != nil {
		return nil, err
	}
	return []*river.PeriodicJob{river.NewPeriodicJob(river.PeriodicInterval(time.Minute), func() (river.JobArgs, *river.InsertOpts) {
		return accountDeletionArgs{}, nil
	}, &river.PeriodicJobOpts{RunOnStart: true})}, nil
}
