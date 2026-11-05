// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"

	"github.com/katocxl/pantherclaw/internal/notifications/adapters/smtpmail"
	"github.com/katocxl/pantherclaw/internal/platform/config"
)

// WebAuthnConfig configures security keys and passkeys (G0 M5 part 1).
// WebAuthn needs a domain name: the RP id defaults to the host of
// auth.public_url, and when that host is an IP address security keys are
// off (use http://localhost:8080 for local development).
type WebAuthnConfig struct {
	RPID   string `json:"rp_id" env:"PC_WEBAUTHN_RP_ID"`
	RPName string `json:"rp_name" env:"PC_WEBAUTHN_RP_NAME"`
}

// NotificationsConfig configures notification delivery (G0 M5 part 1).
type NotificationsConfig struct {
	// SMTP is the relay for email; without a host, email deliveries are
	// skipped (and shown as such in delivery health).
	SMTP SMTPConfig `json:"smtp"`
	// AllowedPrivateRanges re-allows private webhook destinations for a
	// self-hosted deployment (CIDRs). Operator configuration only: tenants
	// can never reach private networks through a webhook (HR-157).
	AllowedPrivateRanges []string `json:"allowed_private_ranges" env:"PC_NOTIFICATIONS_ALLOWED_PRIVATE_RANGES"`
	// Concurrency is the number of deliveries one worker sends at once.
	Concurrency int `json:"concurrency" env:"PC_NOTIFICATIONS_CONCURRENCY"`
	// WebPushSubject is the VAPID subject (a mailto: or https: URL) Web
	// Push services may contact; empty uses auth.public_url (G0 M36 D1066).
	WebPushSubject string `json:"web_push_subject" env:"PC_NOTIFICATIONS_WEB_PUSH_SUBJECT"`
}

// SMTPConfig is the email relay. The password is read from a file (SB-7).
type SMTPConfig struct {
	Host         string `json:"host" env:"PC_SMTP_HOST"`
	Port         int    `json:"port" env:"PC_SMTP_PORT"`
	TLS          string `json:"tls" env:"PC_SMTP_TLS"`
	From         string `json:"from" env:"PC_SMTP_FROM"`
	Username     string `json:"username" env:"PC_SMTP_USERNAME"`
	PasswordFile string `json:"password_file" env:"PC_SMTP_PASSWORD_FILE"`
}

// webAuthnRPID returns the RP id to use, or "" when security keys are off
// (no rp_id and an IP-address public host).
func (c *Config) webAuthnRPID() string {
	if c.WebAuthn.RPID != "" {
		return c.WebAuthn.RPID
	}
	u, err := url.Parse(c.Auth.PublicURL)
	if err != nil || net.ParseIP(u.Hostname()) != nil {
		return ""
	}
	return u.Hostname()
}

func (c *Config) allowedPrivateRanges() ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(c.Notifications.AllowedPrivateRanges))
	for _, s := range c.Notifications.AllowedPrivateRanges {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("notifications.allowed_private_ranges: %q is not a CIDR", s)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// mailer returns the SMTP mailer, or nil when email is not configured.
func (c *Config) mailer() (*smtpmail.Mailer, error) {
	s := c.Notifications.SMTP
	if s.Host == "" {
		return nil, nil
	}
	cfg := smtpmail.Config{Host: s.Host, Port: s.Port, TLS: s.TLS, From: s.From, Username: s.Username}
	if u, err := url.Parse(c.Auth.PublicURL); err == nil {
		cfg.HeloName = u.Hostname()
	}
	if s.Username != "" {
		if s.PasswordFile == "" {
			return nil, errors.New("notifications.smtp.password_file is required with a username")
		}
		pw, err := config.ReadSecretFile(s.PasswordFile)
		if err != nil {
			return nil, err
		}
		cfg.Password = pw
	}
	return smtpmail.New(cfg)
}

// validateM5 checks the M5 part 1 settings.
func (c *Config) validateM5() []error {
	var errs []error
	if c.Notifications.Concurrency < 1 || c.Notifications.Concurrency > 100 {
		errs = append(errs, errors.New("notifications.concurrency must be 1..100"))
	}
	if _, err := c.allowedPrivateRanges(); err != nil {
		errs = append(errs, err)
	}
	if c.Notifications.SMTP.Host != "" {
		s := c.Notifications.SMTP
		if _, err := smtpmail.New(smtpmail.Config{Host: s.Host, Port: s.Port, TLS: s.TLS, From: s.From, HeloName: "check"}); err != nil {
			errs = append(errs, fmt.Errorf("notifications.%w", err))
		}
		if s.Username != "" && s.PasswordFile == "" {
			errs = append(errs, errors.New("notifications.smtp.password_file is required with a username"))
		}
	}
	if c.WebAuthn.RPID != "" && net.ParseIP(c.WebAuthn.RPID) != nil {
		errs = append(errs, errors.New("webauthn.rp_id must be a domain name, not an IP address"))
	}
	return errs
}
