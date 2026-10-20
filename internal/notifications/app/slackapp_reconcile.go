// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The Slack reconciler (G0 M14 D88). Every minute, for each org, it closes
// the OPEN cards whose request is final however it ended (a decision, an
// expiry, an invalidation, a supersession, a void that ended it), so no
// approvals code has to notify Slack; and it asks Slack again whether each
// active channel is still internal: a channel shared outside the workspace
// returns to PENDING_ACTIVATION and the org's admins are told. Both are
// bounded per run. It runs whatever the edition: closing a card is never a
// new card (only new cards stop after a downgrade).

const (
	// SlackReconcileInterval is how often the reconciler runs.
	SlackReconcileInterval = time.Minute
	// slackReconcileBatch bounds the cards closed and channels checked per
	// org and run.
	slackReconcileBatch = 50
)

// SlackReconciled counts what one run did for one org.
type SlackReconciled struct {
	Closed, Paused int
}

// ReconcileSlack runs the reconciler for one org.
func (s *Service) ReconcileSlack(ctx context.Context, org ids.OrgID) (SlackReconciled, error) {
	var out SlackReconciled
	var cards []dbq.SlackCardsToCloseRow
	var channels []dbq.ActiveSlackAppChannelsRow
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		if cards, err = q.SlackCardsToClose(ctx, org, slackReconcileBatch); err != nil {
			return err
		}
		channels, err = q.ActiveSlackAppChannels(ctx, org, slackReconcileBatch)
		return err
	}, db.ReadOnly())
	if err != nil {
		return out, err
	}
	for _, c := range cards {
		if s.closeSlackCard(ctx, org, c.RequestID, c.ChannelRecordID) {
			out.Closed++
		}
	}
	for _, c := range channels {
		paused, err := s.recheckSlackChannel(ctx, org, c)
		if err != nil {
			return out, err
		}
		if paused {
			out.Paused++
		}
	}
	return out, nil
}

// slackToken opens a slack_app channel's bot token.
func (s *Service) slackToken(ctx context.Context, org ids.OrgID, channel ids.UUID, blob []byte) (string, error) {
	b, err := s.envelope.Decrypt(ctx, s.field(org, channel, secretColumn), SecretPurpose, blob)
	return string(b), err
}

// closeSlackCard updates one card to its request's final state; it reports
// whether Slack took the update.
func (s *Service) closeSlackCard(ctx context.Context, org ids.OrgID, request, channel ids.UUID) bool {
	var cfg dbq.GetSlackAppChannelRow
	var facts dbq.SlackCardFactsRow
	var stored dbq.PcSlackCard
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		if cfg, err = q.GetSlackAppChannel(ctx, org, channel); err != nil {
			return err
		}
		if facts, err = q.SlackCardFacts(ctx, org, request); err != nil {
			return err
		}
		stored, err = q.GetSlackCard(ctx, org, request, channel)
		return err
	}, db.ReadOnly())
	if err != nil || cfg.ChannelState == "DISABLED" || !domain.CardIsClosed(facts.State) {
		return false
	}
	token, err := s.slackToken(ctx, org, channel, cfg.Secret)
	if err != nil {
		return false
	}
	f := domain.CardFacts{
		Level: cfg.DataLevel, Kind: facts.SubjectKind, Consequence: facts.Reversibility, State: facts.State,
		ExpiresAt: facts.DeadlineAt, RequestID: request.String(), Operation: facts.Operation, Agent: facts.AgentName,
		Environment: facts.EnvironmentName,
	}
	out := s.slackRefresh(ctx, org, token, stored, f)
	if !out.ok {
		s.log.WarnContext(ctx, "notifications.slack_card_not_closed", slog.String("org", org.String()),
			slog.String("channel", channel.String()), slog.String("code", out.code))
	}
	return out.ok
}

// recheckSlackChannel asks Slack whether an active channel is still
// internal (conversations.info). A channel now shared outside the
// workspace returns to PENDING_ACTIVATION, audited, and the org's admins
// are told; any other failure is left to delivery health.
func (s *Service) recheckSlackChannel(ctx context.Context, org ids.OrgID, c dbq.ActiveSlackAppChannelsRow) (bool, error) {
	token, err := s.slackToken(ctx, org, c.ChannelRecordID, c.Secret)
	if err != nil {
		s.log.WarnContext(ctx, "notifications.slack_recheck_skipped", slog.String("org", org.String()), pclog.Err(err))
		return false, nil // the delivery path reports an unusable token
	}
	a, out := s.slackCall(ctx, token, "conversations.info", nil, url.Values{"channel": {c.SlackChannel}})
	if !out.ok || !sharedChannel(a, c.SlackChannel) {
		return false, nil
	}
	paused := false
	err = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		n, err := q.MarkSlackSharedExternally(ctx, org, c.ChannelRecordID)
		if err != nil || n == 0 {
			return err
		}
		paused = true
		row, err := q.GetChannel(ctx, org, c.ChannelRecordID)
		if err != nil {
			return err
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "notification.slack_channel_shared", Actor: evdomain.Actor{Type: "system", ID: "slack-reconciler"},
			Outcome: audit.Success, ReasonCode: "SLACK_CHANNEL_SHARED",
			Object:  &audit.Object{Type: "notification_channel", ID: c.ChannelRecordID.String()},
			Details: map[string]string{"slack_channel": c.SlackChannel},
		}); err != nil {
			return err
		}
		admins, err := q.OrgUsersWithRoles(ctx, org, []string{string(td.RoleOrgAdmin)})
		if err != nil {
			return err
		}
		_, err = s.Enqueue(ctx, tx, Message{
			Org: org, Type: "notification.slack_channel_shared", Params: map[string]string{"channel": row.Name},
			Personal: admins, Subject: &Subject{Type: "notification_channel", ID: c.ChannelRecordID},
			DedupeKey: "slack-shared:" + c.ChannelRecordID.String() + ":" + fmt.Sprint(s.clock.Now().Unix()),
		})
		return err
	})
	return paused, err
}

// SlackReconcileOrgArgs runs the reconciler for one org (ids only, HR-056).
type SlackReconcileOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (SlackReconcileOrgArgs) Kind() string { return "notifications.slack_reconcile_org" }

// InsertOpts keeps one queued run per org.
func (SlackReconcileOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: Queue, UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type slackReconcileOrgWorker struct {
	river.WorkerDefaults[SlackReconcileOrgArgs]
	svc *Service
}

func (w *slackReconcileOrgWorker) Work(ctx context.Context, job *river.Job[SlackReconcileOrgArgs]) error {
	r, err := w.svc.ReconcileSlack(ctx, job.Args.Org)
	if err != nil {
		w.svc.log.WarnContext(ctx, "notifications.slack_reconcile_failed", slog.String("org", job.Args.Org.String()), pclog.Err(err))
		return err
	}
	if r.Closed+r.Paused > 0 {
		w.svc.log.InfoContext(ctx, "notifications.slack_reconciled", slog.String("org", job.Args.Org.String()),
			slog.Int("closed", r.Closed), slog.Int("paused", r.Paused))
	}
	return nil
}

// SlackReconcileDispatchArgs fans the reconciler out to every active org.
type SlackReconcileDispatchArgs struct{}

// Kind implements river.JobArgs.
func (SlackReconcileDispatchArgs) Kind() string { return "notifications.slack_reconcile_dispatch" }

type slackReconcileDispatchWorker struct {
	river.WorkerDefaults[SlackReconcileDispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054) and enqueues one run
// per org.
func (w *slackReconcileDispatchWorker) Work(ctx context.Context, _ *river.Job[SlackReconcileDispatchArgs]) error {
	refs, err := w.pool.CrossOrgList(ctx, db.ListActiveOrgs, 10000)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("slack reconciler: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: SlackReconcileOrgArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// registerSlackReconciler adds the reconciler's workers to reg.
func registerSlackReconciler(reg *jobs.Registry, svc *Service) error {
	if err := jobs.Register[SlackReconcileOrgArgs](reg, &slackReconcileOrgWorker{svc: svc}); err != nil {
		return err
	}
	return jobs.Register[SlackReconcileDispatchArgs](reg, &slackReconcileDispatchWorker{pool: svc.pool})
}

// slackReconcilePeriodic schedules the reconciler.
func slackReconcilePeriodic() *river.PeriodicJob {
	return river.NewPeriodicJob(river.PeriodicInterval(SlackReconcileInterval),
		func() (river.JobArgs, *river.InsertOpts) { return SlackReconcileDispatchArgs{}, nil }, nil)
}

// sharedChannel reports whether a conversations.info answer describes the
// channel as shared outside the workspace.
func sharedChannel(a slackAnswer, channel string) bool {
	var ch slackChannel
	if json.Unmarshal(a.Channel, &ch) != nil || ch.ID != channel {
		return false
	}
	return ch.ExtShared || ch.Shared
}
