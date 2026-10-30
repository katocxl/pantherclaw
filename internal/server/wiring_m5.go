// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"log/slog"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/keystore"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// m5Services holds the M5 part 1 services shared by the API and worker roles.
type m5Services struct {
	notifications *napp.Service
	webauthn      *authnapp.WebAuthn // nil when security keys are off
	// browser is the browser sign-in the pages use (set by web).
	browser *authnapp.Browser
}

// newM5 builds the notification service (with the SMTP relay and the
// edition source) and, when the public host is a name, WebAuthn.
func newM5(ctx context.Context, cfg *Config, pool *db.Pool, kp keys.KeyProvider, bill *billing.Service, log *slog.Logger) (*m5Services, error) {
	ranges, err := cfg.allowedPrivateRanges()
	if err != nil {
		return nil, err
	}
	insert, err := jobs.NewClient(pool, nil, jobs.Config{Logger: log}) // insert-only: enqueue in the producer's transaction
	if err != nil {
		return nil, err
	}
	envelope := pccrypto.NewEnvelope(keystore.NewDEKStore(pool, kp))
	notif, err := napp.New(pool, insert, envelope, napp.Config{PublicURL: cfg.Auth.PublicURL, AllowedPrivateRanges: ranges},
		clock.System{}, log)
	if err != nil {
		return nil, err
	}
	notif.SetEditions(bill)
	notif.SetWebhookKeys(processWebhookKeys(pool, kp))
	probeM14("m14.notifications", notif)
	if err := cfg.devSlack(notif); err != nil {
		return nil, err
	}
	mailer, err := cfg.mailer()
	if err != nil {
		return nil, err
	}
	if mailer != nil {
		notif.SetMailer(mailer)
	} else {
		log.WarnContext(ctx, "server.email_not_configured", slog.String("note",
			"notifications.smtp.host is empty: email deliveries are skipped"))
	}
	out := &m5Services{notifications: notif}
	rpID := cfg.webAuthnRPID()
	if rpID == "" {
		log.WarnContext(ctx, "server.webauthn_off", slog.String("note",
			"security keys need a domain name: set auth.public_url to e.g. http://localhost:8080 or set webauthn.rp_id"))
		return out, nil
	}
	out.webauthn, err = authnapp.NewWebAuthn(pool, authnapp.WebAuthnConfig{RPID: rpID, RPName: cfg.WebAuthn.RPName, PublicURL: cfg.Auth.PublicURL},
		notif, clock.System{}, log)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// web builds the browser pages: sign-in on the shared callback, the
// account page, and the security-key routes when WebAuthn is on.
func (m *m5Services) web(cfg *Config, pool *db.Pool, idps []authnapp.IdP, limiter *httpx.Limiter, log *slog.Logger) (*webhttp.Handler, error) {
	m.browser = authnapp.NewBrowser(pool, cfg.Auth.PublicURL, idps, clock.System{}, log)
	h, err := webhttp.New(m.browser, cfg.Auth.PublicURL, limiter, log)
	if err != nil {
		return nil, err
	}
	if m.webauthn != nil {
		h.WithKeys(m.webauthn)
	}
	return h, nil
}

// registerWorkers adds the delivery workers and their janitor.
func (m *m5Services) registerWorkers(reg *jobs.Registry) error {
	return napp.RegisterWorkers(reg, m.notifications)
}
