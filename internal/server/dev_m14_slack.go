// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/keystore"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pcslack "github.com/katocxl/pantherclaw/packages/pc-slack"
)

// devSlackChannelName is the seeded slack_app notification channel.
const devSlackChannelName = "slack-approvals"

// seedSlackChannel seeds a PENDING_ACTIVATION slack_app channel posting approval cards
// to slackChannel with the bot token in tokenFile (G0 M14 D22). DEVELOPMENT
// ONLY. It is not activated: a person activates it on its page with a
// security key, which also runs Slack's checks (HR-315), so point
// dev.slack_api_url at pantherclaw-sim slack first.
func seedSlackChannel(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, slackChannel, tokenFile string, stdout io.Writer) error {
	b, err := os.ReadFile(tokenFile) //nolint:gosec // G304: operator-chosen token path
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

// devSlackConnectionName is the seeded agent-side Slack connection.
const devSlackConnectionName = "slack"

// seedSlackAgentConnection creates the development connection through
// which agents post to Slack with pc.slack (G0 M14 D25): targetURL is the
// Slack Web API base (pantherclaw-sim slack's /api), the bot token is held
// by the gateway (a person seals it with pclaw seal), and the gateway is
// the provider of slack.channel.external, which it reads before each
// decision. DEVELOPMENT ONLY.
func seedSlackAgentConnection(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, gateway ids.UUID, targetURL string) (capp.Connection, error) {
	class := capp.ClassPublic
	if u, err := url.Parse(targetURL); err == nil {
		if a, isIP := httpx.HostAddr(u.Hostname()); isIP && (a.IsPrivate() || a.IsLoopback()) {
			class = capp.ClassInternal
		}
	}
	c, err := capp.New(pool, nil, cfg.Auth.PublicURL, cfg.GatewayAPI.URL).Seed(ctx, org, "dev-seed", capp.CreateInput{
		Name: devSlackConnectionName, Kind: capp.KindHTTP, Package: pcslack.Name, BaseURL: targetURL, Gateway: gateway,
		DestinationClass: class, AccessMode: capp.AccessHeld, DefaultMode: "enforce",
		CredentialHeader: "Authorization", CredentialScheme: "Bearer",
	})
	if err != nil {
		return capp.Connection{}, fmt.Errorf("dev: slack connection: %w", err)
	}
	named, err := packageFacts(pool)(ctx, org, gateway, c.ID)
	if err != nil {
		return capp.Connection{}, fmt.Errorf("dev: slack facts: %w", err)
	}
	var decls []fdomain.Declaration
	for _, name := range slices.Sorted(maps.Keys(named)) {
		for _, subject := range named[name] {
			decls = append(decls, fdomain.Declaration{Name: name, Type: fdomain.TypeObject, SubjectType: subject, MaxLag: time.Minute})
		}
	}
	p := fdomain.Provider{
		ID: ids.NewV7(), Org: org, Name: "slack.gateway", GatewayID: gateway, ConnectionID: c.ID, State: fdomain.ProviderActive, Facts: decls,
	}
	ev := audit.Event{
		Name: "facts.provider_registered", Actor: devSeedActor, Outcome: audit.Success,
		Object:  &audit.Object{Type: "fact_provider", ID: p.ID.String()},
		Details: map[string]string{"gateway": gateway.String(), "connection": c.ID.String(), "facts": strconv.Itoa(len(decls))},
	}
	if err := (&factspg.Store{Pool: pool}).CreateProvider(ctx, org, p, "dev-seed", ev); err != nil {
		return capp.Connection{}, fmt.Errorf("dev: slack facts: %w", err)
	}
	return c, nil
}
