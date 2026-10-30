// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"strings"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/version"
	"github.com/katocxl/pantherclaw/internal/sim/teams"
)

// Simulated Teams channels: the team's General channel (the bot is
// installed), a shared channel (a member of another tenant, the bot is
// installed) and one the bot was never added to.
const (
	TeamsGeneral  = teams.TeamID
	TeamsExternal = "19:partnershared000000000000000000@thread.tacv2"
	TeamsOutside  = "19:notinstalled0000000000000000000@thread.tacv2"
)

// TeamsChannels are the simulator's default channels.
func TeamsChannels() []teams.Channel {
	owner := teams.Member{ID: "29:sim-owner", Name: "Owner", TenantID: teams.TenantID, UserRole: "user"}
	partner := teams.Member{ID: "29:sim-partner", Name: "Partner", TenantID: teams.OtherTenantID, UserRole: "user"}
	return []teams.Channel{
		{ID: TeamsGeneral, Name: "General", Installed: true, Members: []teams.Member{owner}},
		{ID: TeamsExternal, Name: "partner-shared", Installed: true, Members: []teams.Member{owner, partner}},
		{ID: TeamsOutside, Name: "not-installed", Installed: false, Members: []teams.Member{owner}},
	}
}

// runTeams serves the simulated Teams bot service (G0 M20 D254).
func runTeams(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("teams", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "127.0.0.1:9098", "listen address (loopback)")
	clientFile := fs.String("client-file", "", "file holding the only accepted client as CLIENT_ID:SECRET (otherwise any client is)")
	rate := fs.Int("rate-limit", 0, "answer the first N Bot Connector requests with 429 and Retry-After")
	invalidClient := fs.Bool("invalid-client", false, "refuse every token request (a deleted client secret)")
	blocked := fs.Bool("blocked", false, "answer every post 403 MessageWritesBlocked")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var req teams.Require
	if *clientFile != "" {
		b, err := os.ReadFile(*clientFile)
		if err != nil {
			return err
		}
		id, secret, ok := strings.Cut(strings.TrimSpace(string(b)), ":")
		if !ok || id == "" || secret == "" {
			return errors.New("--client-file must hold CLIENT_ID:SECRET")
		}
		req = teams.Require{ClientID: id, ClientSecret: secret}
	}
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-sim", Version: version.Get().Version})
	sim := teams.New(TeamsChannels(), teams.Faults{RateLimit: *rate, InvalidClient: *invalidClient, Blocked: *blocked}, log).WithRequire(req)
	return serve(ctx, *addr, sim.Handler(), log, "sim.teams_listening")
}
