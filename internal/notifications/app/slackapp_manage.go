// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"fmt"
	"strconv"
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

// slack_app channel administration (G0 M14 D22, D66; HR-315). A slack_app
// channel is created PENDING_ACTIVATION with its Slack channel, data level
// and bot token, and gets no deliveries until a person holding
// notification.manage activates it on its page with a fresh security-key
// step-up: the page asks Slack (auth.test, conversations.info), shows the
// workspace, bot and channel found, and activates on confirmation. A new
// bot token comes only through UpdateChannel and puts the channel back to
// PENDING_ACTIVATION until it is confirmed again; no token is typed into a
// web page. Neither Slack channel nor data level ever change.

// Slack channel states.
const (
	SlackPending = "PENDING_ACTIVATION"
	SlackActive  = "ACTIVE"
)

// slack_app API errors.
var (
	ErrNotSlackApp        = pcerr.New(pcerr.FailedPrecondition, "NOT_A_SLACK_APP", "only Slack app channels are activated or take a bot token")
	ErrSlackState         = pcerr.New(pcerr.FailedPrecondition, "SLACK_CHANNEL_STATE", "the Slack app channel is not in a state that allows this")
	ErrSlackTokenRefused  = pcerr.New(pcerr.FailedPrecondition, "SLACK_TOKEN_REFUSED", "Slack refused the bot token")
	ErrSlackChannelRefuse = pcerr.New(pcerr.FailedPrecondition, "SLACK_CHANNEL_REFUSED", "the Slack channel does not exist, is archived, or the bot is not a member")
	ErrSlackShared        = pcerr.New(pcerr.FailedPrecondition, "SLACK_CHANNEL_SHARED", "the Slack channel is shared outside the workspace; approval cards go only to internal channels")
	ErrSlackUnavailable   = pcerr.New(pcerr.Unavailable, "SLACK_UNAVAILABLE", "Slack could not be reached; try again")
	ErrSlackOrgAdmin      = pcerr.New(pcerr.PermissionDenied, "ORG_ADMIN_REQUIRED", "only an Org Admin activates a Slack app channel")
	ErrSlackChanged       = pcerr.New(pcerr.FailedPrecondition, "SLACK_CHANNEL_CHANGED", "the channel changed since the page was shown; reload it and check again")
	ErrSlackWorkspace     = pcerr.New(pcerr.FailedPrecondition, "SLACK_WORKSPACE_CHANGED", "the bot token belongs to another Slack workspace; create a new channel for it")
)

// SlackAppView is a slack_app channel's configuration, without its token.
type SlackAppView struct {
	ChannelID, DataLevel, TeamID, BotID, State string
	ActivatedAt, TokenReplacedAt               *time.Time
	// DirectMessages: the bot also sends approval DMs (G0 M20 D256).
	DirectMessages bool
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
		ChannelID: a.SlackChannel, DataLevel: a.DataLevel, TeamID: deref(a.TeamID), BotID: deref(a.BotID), State: a.State,
		ActivatedAt: a.ActivatedAt, TokenReplacedAt: a.TokenReplacedAt,
		DirectMessages: a.DirectMessages,
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

// SlackPreview is what Slack reports for a PENDING_ACTIVATION channel's
// stored token and Slack channel, shown before a person confirms.
type SlackPreview struct {
	SlackWorkspace
	// Version is the configuration version shown (D88): a confirmation
	// activates only the token and channel that were checked.
	Version string
}

// pendingSlackApp reads a PENDING_ACTIVATION slack_app channel and opens its
// token, for a caller holding notification.manage.
func (s *Service) pendingSlackApp(ctx context.Context, id ids.UUID) (dbq.GetSlackAppChannelRow, string, error) {
	var cfg dbq.GetSlackAppChannelRow
	var org ids.OrgID
	err := s.inOrg(ctx, td.PermNotificationManage, func(ctx context.Context, c tapp.Caller, q *dbq.Queries, _ db.TenantTx) error {
		var err error
		cfg, err = q.GetSlackAppChannel(ctx, c.Org, id)
		if err != nil {
			return notFoundAs(err, ErrNotSlackApp)
		}
		if cfg.State != SlackPending || cfg.ChannelState == "DISABLED" {
			return ErrSlackState
		}
		org = c.Org
		return nil
	}, db.ReadOnly())
	if err != nil {
		return cfg, "", err
	}
	token, err := s.envelope.Decrypt(ctx, s.field(org, id, secretColumn), SecretPurpose, cfg.Secret)
	if err != nil {
		return cfg, "", ErrNoUsableSecret
	}
	return cfg, string(token), nil
}

// PreviewSlackApp asks Slack about a PENDING_ACTIVATION channel's token and
// Slack channel (auth.test, conversations.info) and reports the workspace,
// bot and channel it found (D66). It changes nothing.
func (s *Service) PreviewSlackApp(ctx context.Context, id ids.UUID) (SlackPreview, error) {
	if err := s.requireSlackApprovals(ctx); err != nil {
		return SlackPreview{}, err
	}
	cfg, token, err := s.pendingSlackApp(ctx, id)
	if err != nil {
		return SlackPreview{}, err
	}
	// Slack is asked outside any transaction: a slow Slack holds no lock.
	w, err := s.checkSlack(ctx, token, cfg.SlackChannel)
	if err != nil {
		return SlackPreview{}, slackCheckError(err)
	}
	if cfg.TeamID != nil && w.TeamID != *cfg.TeamID {
		return SlackPreview{}, ErrSlackWorkspace
	}
	return SlackPreview{SlackWorkspace: w, Version: slackVersion(cfg)}, nil
}

// ActivateSlackApp activates a PENDING_ACTIVATION slack_app channel
// (HR-315): the caller is a person holding notification.manage with a
// fresh step-up of their own active key, the edition is Team or above,
// Slack confirms the stored token and an internal channel the bot is in
// again, and the token is still the one checked. The workspace and bot ids
// are recorded; the person and key are audited.
func (s *Service) ActivateSlackApp(ctx context.Context, id ids.UUID, version string, su stepup.StepUp) (ChannelView, error) {
	if err := s.requireSlackApprovals(ctx); err != nil {
		return ChannelView{}, err
	}
	if err := s.inOrg(ctx, td.PermNotificationManage, func(ctx context.Context, c tapp.Caller, _ *dbq.Queries, tx db.TenantTx) error {
		if !orgAdmin(c) {
			return ErrSlackOrgAdmin
		}
		return stepup.Check(ctx, tx, c, su, s.clock.Now())
	}, db.ReadOnly()); err != nil {
		return ChannelView{}, err
	}
	cfg, token, err := s.pendingSlackApp(ctx, id)
	if err != nil {
		return ChannelView{}, err
	}
	if version != slackVersion(cfg) {
		return ChannelView{}, ErrSlackChanged
	}
	w, err := s.checkSlack(ctx, token, cfg.SlackChannel)
	if err != nil {
		return ChannelView{}, slackCheckError(err)
	}
	if cfg.TeamID != nil && w.TeamID != *cfg.TeamID {
		return ChannelView{}, ErrSlackWorkspace
	}
	var out ChannelView
	err = s.inOrg(ctx, td.PermNotificationManage, func(ctx context.Context, c tapp.Caller, q *dbq.Queries, tx db.TenantTx) error {
		if err := stepup.Check(ctx, tx, c, su, s.clock.Now()); err != nil {
			return err
		}
		n, err := q.ActivateSlackAppChannel(ctx, dbq.ActivateSlackAppChannelParams{
			TeamID: &w.TeamID, BotID: &w.BotID, ActivatedBy: &c.Principal.ID, ActivatedCredential: &su.Credential,
			OrgID: c.Org, ChannelRecordID: id, SeenUpdatedAt: cfg.UpdatedAt,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrSlackState // activated, or given a new token, meanwhile
		}
		row, err := q.GetChannel(ctx, c.Org, id)
		if err != nil {
			return err
		}
		if out, err = s.withSlackApp(ctx, q, c.Org, channelView(row)); err != nil {
			return err
		}
		return s.audit(ctx, tx, c, "notification.slack_app_activated", id, map[string]string{
			"slack_channel": cfg.SlackChannel, "team": w.TeamID, "bot": w.BotID, "security_key": su.Credential.String(),
		})
	})
	return out, err
}

// replaceSlackToken stores a slack_app channel's new bot token in tx and
// puts the channel back to PENDING_ACTIVATION (D66): it posts nothing until
// a person confirms the new token on its page.
func (s *Service) replaceSlackToken(ctx context.Context, tx db.TenantTx, q *dbq.Queries, c tapp.Caller, id ids.UUID, token string) error {
	if !slackTokenPattern.MatchString(token) {
		return ErrInvalidChannel
	}
	if _, err := q.GetSlackAppChannel(ctx, c.Org, id); err != nil {
		return notFoundAs(err, ErrNotSlackApp)
	}
	blob, err := s.envelope.Encrypt(ctx, s.field(c.Org, id, secretColumn), SecretPurpose, []byte(token))
	if err != nil {
		return err
	}
	if n, err := q.SetChannelSecret(ctx, blob, c.Org, id); err != nil {
		return err
	} else if n == 0 {
		return ErrSlackState
	}
	if _, err := q.ReturnSlackAppToPending(ctx, ptr(c.Actor().Type+":"+c.Actor().ID), c.Org, id); err != nil {
		return err
	}
	return s.audit(ctx, tx, c, "notification.slack_token_replaced", id, nil)
}

// SlackConfirmPath is a slack_app channel's activation page.
func SlackConfirmPath(id ids.UUID) string {
	return "/notifications/channels/" + id.String() + "/confirm"
}

// slackChannelUpdate applies the slack_app parts of an update in tx: a new bot
// token (D66), and no resuming a channel that waits for activation.
func (s *Service) slackChannelUpdate(ctx context.Context, tx db.TenantTx, q *dbq.Queries, c tapp.Caller, id ids.UUID, u ChannelUpdate) error {
	cfg, err := q.GetSlackAppChannel(ctx, c.Org, id)
	switch {
	case db.IsNoRows(err):
		if u.SlackBotToken != nil {
			return ErrNotSlackApp
		}
		return nil
	case err != nil:
		return err
	case u.Paused != nil && !*u.Paused && (cfg.State != SlackActive || u.SlackBotToken != nil):
		return ErrSlackState // only its page activates it
	case u.SlackBotToken != nil:
		return s.replaceSlackToken(ctx, tx, q, c, id, *u.SlackBotToken)
	}
	return nil
}

// slackVersion is a configuration's version as the confirm page shows it:
// it changes with every token replacement and every return to
// PENDING_ACTIVATION.
func slackVersion(cfg dbq.GetSlackAppChannelRow) string {
	return strconv.FormatInt(cfg.UpdatedAt.UnixMicro(), 10)
}

// orgAdmin reports whether the caller holds Org Admin at org scope (D66:
// only an Org Admin activates a slack_app channel).
func orgAdmin(c tapp.Caller) bool {
	for _, b := range c.Bindings {
		if b.Role == td.RoleOrgAdmin && b.Scope.Type == td.ScopeOrg {
			return true
		}
	}
	return false
}
