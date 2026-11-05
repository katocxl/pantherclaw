// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"slices"
	"strings"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

// Contribution export (G0 M38 D1105; HR-821). The operator collects every
// org's QUEUED contributions into one JSON document for the feed maintainer
// and marks them EXPORTED. The document names no org, account or source and
// no time finer than a day; entries are sorted by their content, so their
// order says nothing about who contributed first.

// ContributionsSpec is the export's spec.
const ContributionsSpec = "pc-intel-contributions/1"

// ExportedIndicator is one contributed indicator as exported.
type ExportedIndicator struct {
	Kind       string   `json:"kind"`
	SHA256     string   `json:"sha256,omitzero"`
	Shingles   []string `json:"shingles,omitzero"`
	Severity   string   `json:"severity"`
	Techniques []string `json:"techniques,omitzero"`
	CreatedDay string   `json:"created_day"`
}

// Contributions is the export document.
type Contributions struct {
	Spec        string              `json:"spec"`
	ExportedDay string              `json:"exported_day"`
	Indicators  []ExportedIndicator `json:"indicators"`
}

// ExportContributions collects every org's queued contributions and marks
// them exported. now gives the export's day.
func ExportContributions(ctx context.Context, pool *db.Pool, now time.Time) ([]byte, error) {
	doc := Contributions{Spec: ContributionsSpec, ExportedDay: now.UTC().Format(time.DateOnly), Indicators: []ExportedIndicator{}}
	err := pool.CrossOrgPages(ctx, db.ListActiveOrgs, 500, func(page []db.OrgRef) error {
		for _, o := range page {
			err := pool.InTenantTx(ctx, o.Org, func(ctx context.Context, tx db.TenantTx) error {
				q := dbq.New(tx)
				rows, err := q.QueuedIntelContributions(ctx, o.Org)
				if err != nil || len(rows) == 0 {
					return err
				}
				done := make([]ids.UUID, 0, len(rows))
				for _, r := range rows {
					doc.Indicators = append(doc.Indicators, ExportedIndicator{
						Kind: r.Kind, SHA256: deref(r.Sha256), Shingles: r.Shingles, Severity: r.Severity,
						Techniques: r.Techniques, CreatedDay: dayOf(r.CreatedDay),
					})
					done = append(done, r.ID)
				}
				return q.MarkIntelContributionsExported(ctx, o.Org, done)
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(doc.Indicators, func(a, b ExportedIndicator) int {
		return strings.Compare(a.Kind+a.SHA256+strings.Join(a.Shingles, ",")+a.CreatedDay, b.Kind+b.SHA256+strings.Join(b.Shingles, ",")+b.CreatedDay)
	})
	return json.Marshal(doc, json.Deterministic(true))
}

// FetchInterval is how often the feed is fetched.
const FetchInterval = 24 * time.Hour

// FetchArgs asks for one fetch. It carries no data (HR-056).
type FetchArgs struct{}

// Kind implements river.JobArgs.
func (FetchArgs) Kind() string { return "intel.feed_fetch" }

// InsertOpts keeps one fetch queued or running at a time.
func (FetchArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type fetchWorker struct {
	river.WorkerDefaults[FetchArgs]
	f *Fetcher
}

func (w *fetchWorker) Timeout(*river.Job[FetchArgs]) time.Duration { return 5 * time.Minute }

func (w *fetchWorker) Work(ctx context.Context, _ *river.Job[FetchArgs]) error { return w.f.Run(ctx) }

// RegisterFetch adds the fetch worker to reg and returns its daily
// schedule, which also runs at start.
func RegisterFetch(reg *jobs.Registry, f *Fetcher) ([]*river.PeriodicJob, error) {
	if err := jobs.Register[FetchArgs](reg, &fetchWorker{f: f}); err != nil {
		return nil, err
	}
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(FetchInterval),
			func() (river.JobArgs, *river.InsertOpts) { return FetchArgs{}, nil },
			&river.PeriodicJobOpts{RunOnStart: true}),
	}, nil
}
