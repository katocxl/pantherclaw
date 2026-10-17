// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"errors"
	"fmt"
	"net/netip"

	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
)

// Slack approval cards (G0 M14 D22, D23). slack_app channels reach
// https://slack.com/api through the notification service's egress client;
// only a local-only development server may point them at a loopback
// simulator (dev.slack_api_url).

// validateDevSlack checks dev.slack_api_url: loopback, and a local-only
// server.
func (c *Config) validateDevSlack() []error {
	if c.Dev.SlackAPIURL == "" {
		return nil
	}
	var errs []error
	if !loopbackURL(c.Dev.SlackAPIURL) {
		errs = append(errs, errors.New("dev.slack_api_url must be on loopback"))
	}
	if err := c.localOnly(); err != nil {
		errs = append(errs, fmt.Errorf("dev.slack_api_url is development-only: %w", err))
	}
	return errs
}

// devSlack points the notification service at the simulated Slack when
// dev.slack_api_url is set: a client that may reach loopback, for it
// alone.
func (c *Config) devSlack(n *napp.Service) error {
	if c.Dev.SlackAPIURL == "" {
		return nil
	}
	loopback := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	return n.SetSlackAPI(c.Dev.SlackAPIURL, httpx.NewEgressClient(httpx.EgressConfig{Timeout: napp.RequestTimeout, AllowedPrefixes: loopback}))
}
