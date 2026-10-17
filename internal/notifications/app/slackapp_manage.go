// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// slack_app channel administration (G0 M14 D22, HR-315). A slack_app
// channel is created PENDING with its Slack channel, data level and bot
// token; it posts nothing until a person holding notification.manage
// activates it with a fresh security-key step-up, when PantherClaw checks
// the token with auth.test and the channel with conversations.info. Its
// token is replaced only the same way. Neither Slack channel nor data level
// ever change: a different one is a new channel.

// Slack channel states.
const (
	SlackPending = "PENDING"
	SlackActive  = "ACTIVE"
)

// slack_app API errors.
var (
	ErrNotSlackApp        = pcerr.New(pcerr.FailedPrecondition, "NOT_A_SLACK_APP", "only Slack app channels are activated or get a new bot token")
	ErrSlackState         = pcerr.New(pcerr.FailedPrecondition, "SLACK_CHANNEL_STATE", "the Slack app channel is not in a state that allows this")
	ErrSlackTokenRefused  = pcerr.New(pcerr.FailedPrecondition, "SLACK_TOKEN_REFUSED", "Slack refused the bot token")
	ErrSlackChannelRefuse = pcerr.New(pcerr.FailedPrecondition, "SLACK_CHANNEL_REFUSED", "the Slack channel does not exist, is archived, or the bot is not a member")
	ErrSlackShared        = pcerr.New(pcerr.FailedPrecondition, "SLACK_CHANNEL_SHARED", "the Slack channel is shared outside the workspace; approval cards go only to internal channels")
	ErrSlackWorkspace     = pcerr.New(pcerr.FailedPrecondition, "SLACK_WORKSPACE_CHANGED", "the new bot token belongs to a different Slack workspace")
	ErrSlackUnavailable   = pcerr.New(pcerr.Unavailable, "SLACK_UNAVAILABLE", "Slack could not be reached; try again")
)

// SlackAppView is a slack_app channel's configuration, without its token.
type SlackAppView struct {
	ChannelID, DataLevel, TeamID, State string
	ActivatedAt, TokenReplacedAt        *time.Time
}

// checkSlackAppConfig validates a new configuration (D22, D56): Slack
// channel id, data level (unset is MINIMAL) and bot token.
func checkSlackAppConfig(c *domain.SlackAppConfig) error {
	if c.DataLevel == "" {
		c.DataLevel = domain.SlackMinimal
	}
	if !slackChannelPattern.MatchString(c.ChannelID) || !slackTokenPattern.MatchString(c.BotToken) || c.TeamID != "" ||
		(c.DataLevel != domain.SlackMinimal && c.DataLevel != domain.SlackSummary) {
		return domain.ErrInvalid
	}
	return nil
}

// requireSlackApprovals refuses slack_app channels below the Team edition.
func (s *Service) requireSlackApprovals(ctx context.Context) error {
	ok, err := s.slackApprovals(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", errEditionUnreadable, err)
	}
	if !ok {
		return ErrSlackEdition
	}
	return nil
}

func slackAppView(a dbq.PcSlackAppChannel) *SlackAppView {
	return &SlackAppView{
		ChannelID: a.SlackChannel, DataLevel: a.DataLevel, TeamID: deref(a.TeamID), State: a.State,
		ActivatedAt: a.ActivatedAt, TokenReplacedAt: a.TokenReplacedAt,
	}
}

// withSlackApp adds a slack_app channel's configuration to its view.
func (s *Service) withSlackApp(ctx context.Context, q *dbq.Queries, org ids.OrgID, v ChannelView) (ChannelView, error) {
	if v.Kind != domain.KindSlackApp {
		return v, nil
	}
	rows, err := q.ListSlackAppChannels(ctx, org, []ids.UUID{v.ID})
	if err != nil || len(rows) == 0 {
		return v, err
	}
	v.SlackApp = slackAppView(rows[0])
	return v, nil
}

// withSlackApps adds the configurations of a page of channels.
func (s *Service) withSlackApps(ctx context.Context, q *dbq.Queries, org ids.OrgID, vs []ChannelView) error {
	var want []ids.UUID
	for _, v := range vs {
		if v.Kind == domain.KindSlackApp {
			want = append(want, v.ID)
		}
	}
	if len(want) == 0 {
		return nil
	}
	rows, err := q.ListSlackAppChannels(ctx, org, want)
	if err != nil {
		return err
	}
	by := map[ids.UUID]dbq.PcSlackAppChannel{}
	for _, r := range rows {
		by[r.ChannelRecordID] = r
	}
	for i := range vs {
		if r, ok := by[vs[i].ID]; ok {
			vs[i].SlackApp = slackAppView(r)
		}
	}
	return nil
}

// slackCheckError maps a failed Slack check to its API error.
func slackCheckError(err error) error {
	switch {
	case errors.Is(err, ErrSlackToken):
		return ErrSlackTokenRefused
	case errors.Is(err, ErrSlackChannel):
		return ErrSlackChannelRefuse
	case errors.Is(err, ErrSlackExternal):
		return ErrSlackShared
	}
	return ErrSlackUnavailable
}

// ActivateSlackApp activates a PENDING slack_app channel (HR-315): the
// caller is a person holding notification.manage with a fresh step-up of
// their own active key, the edition is Team or above, and Slack confirms
// the stored token and channel. The workspace and bot ids Slack reports
// are recorded; the person and key are audited.
func (s *Service) ActivateSlackApp(ctx context.Context, id ids.UUID, su stepup.StepUp) (ChannelView, error) {
	if err := s.requireSlackApprovals(ctx); err != nil {
		return ChannelView{}, err
	}
	var cfg dbq.GetSlackAppChannelRow
	err := s.inOrg(ctx, td.PermNotificationManage, func(ctx context.Context, c tapp.Caller, q *dbq.Queries, tx db.TenantTx) error {
		if err := stepup.Check(ctx, tx, c, su, s.clock.Now()); err != nil {
			return err
		}
		var err error
		cfg, err = q.GetSlackAppChannel(ctx, c.Org, id)
		if err != nil {
			return notFoundAs(err, ErrNotSlackApp)
		}
		if cfg.State != SlackPending || cfg.ChannelState == "DISABLED" {
			return ErrSlackState
		}
		return nil
	}, db.ReadOnly())
	if err != nil {
		return ChannelView{}, err
	}
	caller, err := tapp.CallerFrom(ctx)
	if err != nil {
		return ChannelView{}, err
	}
	token, err := s.envelope.Decrypt(ctx, s.field(caller.Org, id, secretColumn), SecretPurpose, cfg.Secret)
	if err != nil {
		return ChannelView{}, ErrNoUsableSecret
	}
	// Slack is asked outside any transaction: a slow Slack holds no lock.
	w, err := s.checkSlack(ctx, string(token), cfg.SlackChannel)
	if err != nil {
		return ChannelView{}, slackCheckError(err)
	}
	var out ChannelView
	err = s.inOrg(ctx, td.PermNotificationManage, func(ctx context.Context, c tapp.Caller, q *dbq.Queries, tx db.TenantTx) error {
		if err := stepup.Check(ctx, tx, c, su, s.clock.Now()); err != nil {
			return err
		}
		n, err := q.ActivateSlackAppChannel(ctx, dbq.ActivateSlackAppChannelParams{
			TeamID: &w.TeamID, BotID: &w.BotID, ActivatedBy: &c.Principal.ID, ActivatedCredential: &su.Credential,
			OrgID: c.Org, ChannelRecordID: id,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrSlackState
		}
		row, err := q.GetChannel(ctx, c.Org, id)
		if err != nil {
			return err
		}
		if out, err = s.withSlackApp(ctx, q, c.Org, channelView(row)); err != nil {
			return err
		}
		return s.audit(ctx, tx, c, "notification.slack_app_activated", id, map[string]string{
			"slack_channel": cfg.SlackChannel, "team": w.TeamID, "security_key": su.Credential.String(),
		})
	})
	return out, err
}

// ReplaceSlackToken gives an ACTIVE slack_app channel a new bot token
// (HR-315): the same person, permission, step-up and edition as
// activation, and Slack confirms the new token for the same workspace and
// channel before it is stored. The old token is not kept.
func (s *Service) ReplaceSlackToken(ctx context.Context, id ids.UUID, token string, su stepup.StepUp) (ChannelView, error) {
	if !slackTokenPattern.MatchString(token) {
		return ChannelView{}, ErrInvalidChannel
	}
	if err := s.requireSlackApprovals(ctx); err != nil {
		return ChannelView{}, err
	}
	var cfg dbq.GetSlackAppChannelRow
	err := s.inOrg(ctx, td.PermNotificationManage, func(ctx context.Context, c tapp.Caller, q *dbq.Queries, tx db.TenantTx) error {
		if err := stepup.Check(ctx, tx, c, su, s.clock.Now()); err != nil {
			return err
		}
		var err error
		cfg, err = q.GetSlackAppChannel(ctx, c.Org, id)
		if err != nil {
			return notFoundAs(err, ErrNotSlackApp)
		}
		if cfg.State != SlackActive || cfg.ChannelState == "DISABLED" {
			return ErrSlackState
		}
		return nil
	}, db.ReadOnly())
	if err != nil {
		return ChannelView{}, err
	}
	w, err := s.checkSlack(ctx, token, cfg.SlackChannel)
	if err != nil {
		return ChannelView{}, slackCheckError(err)
	}
	if cfg.TeamID == nil || w.TeamID != *cfg.TeamID {
		return ChannelView{}, ErrSlackWorkspace
	}
	var out ChannelView
	err = s.inOrg(ctx, td.PermNotificationManage, func(ctx context.Context, c tapp.Caller, q *dbq.Queries, tx db.TenantTx) error {
		if err := stepup.Check(ctx, tx, c, su, s.clock.Now()); err != nil {
			return err
		}
		blob, err := s.envelope.Encrypt(ctx, s.field(c.Org, id, secretColumn), SecretPurpose, []byte(token))
		if err != nil {
			return err
		}
		n, err := q.RecordSlackTokenReplaced(ctx, dbq.RecordSlackTokenReplacedParams{
			TokenReplacedBy: &c.Principal.ID, TokenReplacedCredential: &su.Credential, BotID: &w.BotID,
			OrgID: c.Org, ChannelRecordID: id, TeamID: &w.TeamID,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrSlackState
		}
		if n, err = q.SetChannelSecret(ctx, blob, c.Org, id); err != nil {
			return err
		} else if n == 0 {
			return ErrSlackState
		}
		row, err := q.GetChannel(ctx, c.Org, id)
		if err != nil {
			return err
		}
		if out, err = s.withSlackApp(ctx, q, c.Org, channelView(row)); err != nil {
			return err
		}
		return s.audit(ctx, tx, c, "notification.slack_token_replaced", id, map[string]string{"security_key": su.Credential.String()})
	})
	return out, err
}

// SlackConfirmPath is a slack_app channel's activation page.
func SlackConfirmPath(id ids.UUID) string {
	return "/notifications/channels/" + id.String() + "/confirm"
}
