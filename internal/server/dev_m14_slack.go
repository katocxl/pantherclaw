// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/katocxl/pantherclaw/internal/keystore"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// devSlackChannelName is the seeded slack_app notification channel.
const devSlackChannelName = "slack-approvals"

// seedSlackChannel seeds a PENDING_ACTIVATION slack_app channel posting approval cards
// to slackChannel with the bot token in tokenFile (G0 M14 D22). DEVELOPMENT
// ONLY. It is not activated: a person activates it on its page with a
// security key, which also runs Slack's checks (HR-315), so point
// dev.slack_api_url at pantherclaw-sim slack first.
func seedSlackChannel(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, slackChannel, tokenFile string, stdout io.Writer) error {
	b, err := os.ReadFile(tokenFile)
	if err != nil {
		return fmt.Errorf("dev seed: --slack-token-file: %w", err)
	}
	kp, err := keys.NewFileProvider(cfg.KEKFiles)
	if err != nil {
		return err
	}
	svc, err := napp.New(pool, nil, pccrypto.NewEnvelope(keystore.NewDEKStore(pool, kp)), napp.Config{PublicURL: cfg.Auth.PublicURL},
		clock.System{}, nil)
	if err != nil {
		return err
	}
	var id ids.UUID
	err = pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		c, err := svc.CreateChannelTx(ctx, tx, napp.NewChannel{
			Org: org, Name: devSlackChannelName, Kind: domain.KindSlackApp, EventTypes: []string{"approval.*", "automation.gate_*"},
			CreatedBy: devSeedActor.Type + ":" + devSeedActor.ID,
			SlackApp:  &domain.SlackAppConfig{ChannelID: slackChannel, BotToken: strings.TrimSpace(string(b))},
		})
		id = c.ID
		return err
	})
	if errors.Is(err, domain.ErrInvalid) {
		return errors.New("dev seed: --slack-channel must be a Slack channel id (C... or G...) and --slack-token-file must hold an xoxb- bot token")
	}
	if err != nil {
		return fmt.Errorf("dev seed: slack channel: %w", err)
	}
	_, _ = fmt.Fprintf(stdout, "seeded slack_app channel %s (%s) to Slack channel %s: waiting for activation; check and activate it with your security key at %s\n",
		devSlackChannelName, id, slackChannel, strings.TrimSuffix(cfg.Auth.PublicURL, "/")+napp.SlackConfirmPath(id)+"?org="+org.String())
	return nil
}
