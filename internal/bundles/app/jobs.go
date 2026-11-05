// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	bdomain "github.com/katocxl/pantherclaw/internal/bundles/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Revocation fetching (D1083).
const (
	// FetchInterval is how often each ACTIVE pin's revocations_url is read.
	FetchInterval = 24 * time.Hour
	// MaxFetchBytes bounds one revocations document.
	MaxFetchBytes = 64 << 10
	// maxStatements bounds the statements read from one document.
	maxStatements = 64
)

// FetchOrgArgs asks for one org's revocation URLs to be read. Job args
// carry ids only (HR-056).
type FetchOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (FetchOrgArgs) Kind() string { return "bundles.revocations_fetch_org" }

// InsertOpts keeps one queued job per org, on the notifications queue: a
// slow publisher never holds up other jobs.
func (FetchOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: napp.Queue, UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

// FetchOrg reads each ACTIVE pin's revocations_url (https only, at most
// 64 KiB, no redirects, through the egress client) and applies every
// statement in it that a key pinned for that publisher signed. The
// document holds compact JWS statements, one per line; a line that does
// not verify is skipped and logged, and a publisher that goes silent
// changes nothing (R-91: revocation relies on the org).
func (s *Service) FetchOrg(ctx context.Context, org ids.OrgID) error {
	var pins []dbq.RevocationURLPinsRow
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		pins, err = dbq.New(tx).RevocationURLPins(ctx, org)
		return err
	}, db.ReadOnly())
	if err != nil {
		return err
	}
	for _, p := range pins {
		lines, err := s.fetch(ctx, p.RevocationsUrl)
		if err != nil {
			s.log.WarnContext(ctx, "bundles.revocations_fetch_failed", slog.String("pin", p.ID.String()), pclog.Err(err))
			continue
		}
		for _, l := range lines {
			a, err := s.applyStatement(ctx, org, systemActor, l, bdomain.SourceFetch)
			if err != nil {
				s.log.WarnContext(ctx, "bundles.revocation_skipped", slog.String("pin", p.ID.String()), pclog.Err(err))
				continue
			}
			if !a.AlreadyApplied {
				s.log.InfoContext(ctx, "bundles.revocation_applied", slog.String("pin", p.ID.String()),
					slog.Int("installs", len(a.Installs)), slog.Int("pins", len(a.Pins)))
			}
		}
	}
	return nil
}

// fetch reads one revocations document.
func (s *Service) fetch(ctx context.Context, raw string) ([]string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("bundles: revocations URL refused")
	}
	ctx, cancel := context.WithTimeout(ctx, FetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/jose, text/plain")
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bundles: revocations URL answered %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxFetchBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxFetchBytes {
		return nil, fmt.Errorf("bundles: revocations document exceeds %d bytes", MaxFetchBytes)
	}
	var out []string
	for l := range bytes.Lines(body) {
		if t := string(bytes.TrimSpace(l)); t != "" {
			out = append(out, t)
		}
		if len(out) == maxStatements {
			break
		}
	}
	return out, nil
}

type fetchOrgWorker struct {
	river.WorkerDefaults[FetchOrgArgs]
	svc *Service
}

func (w *fetchOrgWorker) Work(ctx context.Context, job *river.Job[FetchOrgArgs]) error {
	return w.svc.FetchOrg(ctx, job.Args.Org)
}

// Timeout leaves room for every pin's fetch.
func (w *fetchOrgWorker) Timeout(*river.Job[FetchOrgArgs]) time.Duration { return 101 * FetchTimeout }

// FetchDispatchArgs fans the fetch out to every active org.
type FetchDispatchArgs struct{}

// Kind implements river.JobArgs.
func (FetchDispatchArgs) Kind() string { return "bundles.revocations_fetch_dispatch" }

type fetchDispatchWorker struct {
	river.WorkerDefaults[FetchDispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054) and enqueues one job
// per org; an org without revocation URLs exits at once.
func (w *fetchDispatchWorker) Work(ctx context.Context, _ *river.Job[FetchDispatchArgs]) error {
	refs, err := w.pool.CrossOrgListAll(ctx, db.ListActiveOrgs, db.ListerPageSize)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("bundles revocations dispatch: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: FetchOrgArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// RegisterJobs adds the revocation fetch workers to reg and returns its
// schedule: daily (D1083).
func RegisterJobs(reg *jobs.Registry, svc *Service) ([]*river.PeriodicJob, error) {
	if err := jobs.Register[FetchOrgArgs](reg, &fetchOrgWorker{svc: svc}); err != nil {
		return nil, err
	}
	if err := jobs.Register[FetchDispatchArgs](reg, &fetchDispatchWorker{pool: svc.pool}); err != nil {
		return nil, err
	}
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(FetchInterval),
			func() (river.JobArgs, *river.InsertOpts) { return FetchDispatchArgs{}, nil }, nil),
	}, nil
}
