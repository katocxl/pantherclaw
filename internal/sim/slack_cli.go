// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"slices"
	"strings"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/version"
	"github.com/katocxl/pantherclaw/internal/sim/slack"
)

// Simulated Slack channels: approvals (the bot is a member), external
// (shared with another organization, the bot is a member) and
// outside (the bot is not a member).
const (
	SlackApprovals = "C0APPROVAL1"
	SlackExternal  = "C0EXTERNAL1"
	SlackOutside   = "C0OUTSIDE01"
)

// runSlack serves the simulated Slack Web API (G0 M14 D24).
func runSlack(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("slack", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "127.0.0.1:9095", "listen address (loopback)")
	tokenFile := fs.String("token-file", "", "file holding the only bot token accepted (otherwise any xoxb- token is)")
	extra := fs.String("channels", "", "comma-separated extra channel ids the bot is a member of")
	external := fs.String("external-shared", "", "comma-separated channel ids to mark shared with another organization")
	notIn := fs.String("not-in-channel", "", "comma-separated channel ids the bot is not a member of")
	rate := fs.Int("rate-limit", 0, "answer the first N requests with 429 and Retry-After")
	invalidAuth := fs.Bool("invalid-auth", false, "answer every request invalid_auth (a revoked token)")
	notFound := fs.Bool("channel-not-found", false, "answer every channel method channel_not_found")
	if err := fs.Parse(args); err != nil {
		return err
	}
	channels := []slack.Channel{
		{ID: SlackApprovals, Name: "approvals", Member: true},
		{ID: SlackExternal, Name: "partner-shared", Member: true, ExtShared: true, Shared: true},
		{ID: SlackOutside, Name: "general", Member: false},
	}
	for _, id := range slackList(*extra) {
		channels = append(channels, slack.Channel{ID: id, Name: strings.ToLower(id), Member: true, Private: strings.HasPrefix(id, "G")})
	}
	for i := range channels {
		c := &channels[i]
		if slices.Contains(slackList(*external), c.ID) {
			c.ExtShared, c.Shared = true, true
		}
		if slices.Contains(slackList(*notIn), c.ID) {
			c.Member = false
		}
	}
	var req slack.Require
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return err
		}
		req.Token = strings.TrimSpace(string(b))
		if !strings.HasPrefix(req.Token, "xoxb-") {
			return errors.New("--token-file must hold an xoxb- bot token")
		}
	}
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-sim", Version: version.Get().Version})
	sim := slack.New(channels, slack.Faults{RateLimit: *rate, InvalidAuth: *invalidAuth, ChannelNotFound: *notFound}, log).WithRequire(req)
	return serve(ctx, *addr, sim.Handler(), log, "sim.slack_listening")
}

// slackList splits a comma-separated list, dropping empty items.
func slackList(s string) []string {
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
