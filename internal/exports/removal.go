// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package exports

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Removal notices (HR-515): when an artifact that was pushed is removed
// here, a signed notice goes next to the object. It says what PantherClaw
// removed and nothing about the copy at the destination, which belongs to
// the customer and which PantherClaw cannot reach.
const (
	// NoticeFormat identifies the notice.
	NoticeFormat = "pantherclaw.removal-notice/v1"
	// NoticeJWSType is the notice's JWS type, signed with the evidence_packs
	// key: `pclaw verify` and any JWKS reader check it like a pack manifest.
	NoticeJWSType = "pap-removal-notice+jwt"
	// NoticeSuffix names the notice next to its object.
	NoticeSuffix = ".removal-notice.jws"
	// NoticeStatement is the fixed sentence every notice carries.
	NoticeStatement = "PantherClaw removed its own copy of this artifact under its retention rules. This notice does not delete the copy at this destination and does not say that copy is gone."
	// SweepInterval is how often every org's receipts are looked at.
	SweepInterval = time.Hour
)

// RemovalNotice is a notice's signed payload.
type RemovalNotice struct {
	Format        string    `json:"format"`
	Org           string    `json:"org"`
	Destination   string    `json:"destination"`
	Receipt       string    `json:"receipt"`
	Class         string    `json:"class"`
	Artifact      string    `json:"artifact,omitzero"`
	FromSeq       int64     `json:"from_seq,omitzero"`
	ToSeq         int64     `json:"to_seq,omitzero"`
	ObjectKey     string    `json:"object_key"`
	SizeBytes     int64     `json:"size_bytes"`
	SHA256        string    `json:"sha256"`
	DeliveredAt   time.Time `json:"delivered_at"`
	RemovedHereAt time.Time `json:"removed_here_at"`
	Statement     string    `json:"statement"`
}

// Sweep is one org's hourly pass: uploads left behind are aborted, streamed
// pushes nobody started end, artifacts gone here get their notices.
func (s *Service) Sweep(ctx context.Context, org ids.OrgID) error {
	var aborts []ids.UUID
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := q.FailUnclaimedExportReceipts(ctx, org, int32(StreamWait/time.Second)); err != nil {
			return err
		}
		stale := int32(staleAfter / time.Second)
		var err error
		if aborts, err = q.ListExportAborts(ctx, org, stale, maxSweepItems); err != nil {
			return err
		}
		if _, err := q.FailStaleExportReceipts(ctx, org, stale); err != nil {
			return err
		}
		removed, err := q.ListExportRemovals(ctx, org, maxSweepItems)
		if err != nil {
			return err
		}
		for _, id := range removed {
			if _, err := q.MarkExportRemovedHere(ctx, org, id); err != nil {
				return err
			}
			if err := s.pushAudit(ctx, tx, Actor, audit.Success, "export.artifact_removed_here", id, nil); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, id := range aborts {
		p, err := s.load(ctx, org, id)
		if err != nil {
			return err
		}
		s.abortUpload(ctx, p)
	}
	var notices []dbq.ListExportNoticesRow
	if err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		notices, err = dbq.New(tx).ListExportNotices(ctx, org, maxSweepItems)
		return err
	}, db.ReadOnly()); err != nil {
		return err
	}
	var errs []error
	for _, n := range notices {
		if err := s.sendNotice(ctx, org, n.ID); err != nil {
			s.log.WarnContext(ctx, "exports.notice_failed", slog.String("receipt", n.ID.String()), pclog.Err(err))
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// sendNotice signs and pushes one notice. A destination that was disabled
// takes nothing any more: its notice is undeliverable, and the receipt
// still says a copy exists there. A paused one waits.
func (s *Service) sendNotice(ctx context.Context, org ids.OrgID, id ids.UUID) error {
	var r dbq.LoadExportNoticeRow
	var t transport
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		r, err = dbq.New(tx).LoadExportNotice(ctx, org, id)
		if err != nil {
			return err
		}
		if r.DestinationState != StateActive {
			return nil
		}
		tg := Target{Kind: r.Kind, URL: r.Url, KeyPrefix: r.KeyPrefix, PathStyle: r.PathStyle, Internal: r.Internal}
		if r.Bucket != nil {
			tg.Bucket = *r.Bucket
		}
		if r.Region != nil {
			tg.Region = *r.Region
		}
		t, err = s.transportOf(ctx, org, r.DestinationID, tg, r.Secret)
		return err
	})
	if err != nil {
		return err
	}
	switch r.DestinationState {
	case StateActive:
	case StateDisabled:
		return s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			q := dbq.New(tx)
			if _, err := q.SetExportNoticeUndeliverable(ctx, org, id); err != nil {
				return err
			}
			return s.pushAudit(ctx, tx, Actor, audit.Failure, "export.removal_notice_undeliverable", id, map[string]string{"destination": r.DestinationID.String()})
		})
	default:
		return nil
	}
	body, err := s.notice(org, id, r)
	if err != nil {
		return err
	}
	key := r.ObjectKey + NoticeSuffix
	if _, err := t.Put(ctx, key, body); err != nil {
		code, _ := failureOf(err)
		if serr := s.pool.InTenantTx(context.WithoutCancel(ctx), org, func(ctx context.Context, tx db.TenantTx) error {
			if _, err := dbq.New(tx).SetExportNoticeFailed(ctx, org, id); err != nil {
				return err
			}
			return s.recordFailure(ctx, tx, org, r.DestinationID, r.Name, code)
		}); serr != nil {
			return errors.Join(err, serr)
		}
		return err
	}
	sum := sha256.Sum256(body)
	return s.pool.InTenantTx(context.WithoutCancel(ctx), org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		n, err := q.SetExportNoticeSent(ctx, dbq.SetExportNoticeSentParams{NoticeKey: &key, NoticeSha256: sum[:], OrgID: org, ID: id})
		if err != nil {
			return err
		}
		if n == 0 {
			return db.ErrLostRace
		}
		return s.pushAudit(ctx, tx, Actor, audit.Success, "export.removal_notice_sent", id, map[string]string{
			"destination": r.DestinationID.String(), "object_key": key, "sha256": hex.EncodeToString(sum[:]),
		})
	})
}

func (s *Service) notice(org ids.OrgID, id ids.UUID, r dbq.LoadExportNoticeRow) ([]byte, error) {
	if s.keys == nil || r.DeliveredAt == nil || r.RemovedHereAt == nil {
		return nil, errors.New("exports: a notice needs a signer and a delivered, removed artifact")
	}
	n := RemovalNotice{
		Format: NoticeFormat, Org: org.String(), Destination: r.DestinationID.String(), Receipt: id.String(), Class: r.Class,
		ObjectKey: r.ObjectKey, SizeBytes: r.SizeBytes, SHA256: hex.EncodeToString(r.Sha256), DeliveredAt: *r.DeliveredAt,
		RemovedHereAt: *r.RemovedHereAt, Statement: NoticeStatement,
	}
	if r.ArtifactID != nil {
		n.Artifact = r.ArtifactID.String()
	}
	n.FromSeq, n.ToSeq = r.FromSeq.Int64, r.ToSeq.Int64
	payload, err := pack.Canonical(n)
	if err != nil {
		return nil, err
	}
	signer, err := s.keys.Signer(keys.PurposeEvidencePacks)
	if err != nil {
		return nil, fmt.Errorf("exports: notice signer: %w", err)
	}
	signed, err := signer.Sign(NoticeJWSType, payload)
	if err != nil {
		return nil, err
	}
	return []byte(signed), nil
}

// SweepArgs asks for every org's sweep.
type SweepArgs struct{}

// Kind implements river.JobArgs.
func (SweepArgs) Kind() string { return "exports.sweep" }

// maxOrgsPerSweep is one lister page.
const maxOrgsPerSweep = 10_000

type sweepWorker struct {
	river.WorkerDefaults[SweepArgs]
	svc *Service
}

// Work sweeps every active org through the audited lister (HR-054); one
// org's failure leaves the others' sweeps to run, and the next run tries it
// again.
func (w *sweepWorker) Work(ctx context.Context, _ *river.Job[SweepArgs]) error {
	failed := 0
	err := w.svc.pool.CrossOrgPages(ctx, db.ListActiveOrgs, maxOrgsPerSweep, func(page []db.OrgRef) error {
		for _, r := range page {
			if err := w.svc.Sweep(ctx, r.Org); err != nil {
				failed++
				w.svc.log.WarnContext(ctx, "exports.sweep_failed", slog.String("org", r.Org.String()), pclog.Err(err))
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if failed > 0 {
		return errors.New("exports: " + strconv.Itoa(failed) + " orgs failed their sweep")
	}
	return nil
}

// Register adds the workers to reg and returns the sweep's schedule.
func Register(reg *jobs.Registry, svc *Service) ([]*river.PeriodicJob, error) {
	if err := jobs.Register[PushArgs](reg, &pushWorker{svc: svc}); err != nil {
		return nil, err
	}
	if err := jobs.Register[SweepArgs](reg, &sweepWorker{svc: svc}); err != nil {
		return nil, err
	}
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(SweepInterval),
			func() (river.JobArgs, *river.InsertOpts) { return SweepArgs{}, nil }, nil),
	}, nil
}
