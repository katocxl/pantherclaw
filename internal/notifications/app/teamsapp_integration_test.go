// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/sim/teams"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const (
	teamsSecret   = "simulated-teams-client-secret"
	teamsInternal = "19:internalchannel000000000000001@thread.tacv2"
	teamsShared   = "19:sharedchannel00000000000000001@thread.tacv2"
)

type teamsEnv struct {
	*slackEnv
	sim *teams.Server
	url string
}

func newTeamsEnv(t *testing.T) *teamsEnv {
	t.Helper()
	s := newSlackEnv(t, slackToken)
	sim := teams.New([]teams.Channel{
		{ID: teamsInternal, Name: "approvals", Installed: true, Members: []teams.Member{{ID: "29:a", Name: "A", TenantID: teams.TenantID, UserRole: "user"}}},
		{ID: teamsShared, Name: "partners", Installed: true, Members: []teams.Member{
			{ID: "29:a", Name: "A", TenantID: teams.TenantID, UserRole: "user"}, {ID: "29:b", Name: "B", TenantID: teams.OtherTenantID, UserRole: "user"},
		}},
	}, teams.Faults{}, pclog.Discard()).WithRequire(teams.Require{ClientID: teams.AppID, ClientSecret: teamsSecret})
	ts := httptest.NewServer(sim.Handler())
	t.Cleanup(ts.Close)
	if err := s.svc.SetTeamsAPI(ts.URL, ts.Client()); err != nil {
		t.Fatal(err)
	}
	return &teamsEnv{slackEnv: s, sim: sim, url: ts.URL}
}

func (e *teamsEnv) channel(t *testing.T, name, channel string) napp.ChannelView {
	t.Helper()
	c, _, err := e.svc.CreateChannel(e.admin(), napp.ChannelInput{
		Name: name, Kind: domain.KindTeamsApp, EventTypes: []string{"approval.*"},
		TeamsApp: &domain.TeamsAppConfig{
			TenantID: teams.TenantID, TeamID: teams.TeamID, ChannelID: channel, AppID: teams.AppID, ClientSecret: teamsSecret,
			ServiceURL: "https://smba.trafficmanager.net/teams/",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (e *teamsEnv) deliverTeams(t *testing.T) {
	t.Helper()
	var pending []ids.UUID
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := tx.Query(ctx, "SELECT id FROM pc.deliveries WHERE state = 'PENDING' AND kind = 'teams_app' ORDER BY created_at, id")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id ids.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			pending = append(pending, id)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	for _, d := range pending {
		_ = e.svc.Deliver(context.Background(), e.org, d)
	}
}

// TestHR529_TeamsCardsAreLinkOnlyToStandardChannels: a teams_app channel
// is PENDING_ACTIVATION until an Org Admin with a fresh step-up activates
// it; a channel with a member of another tenant is refused and stays
// pending, and gets no card. An active channel gets one Adaptive Card per
// waiting request: the fixed facts and one Action.OpenUrl to the approval
// page, no input, no submit, no bound values (HR-529, HR-313, HR-314).
//
// Covers: F161, PN-017.3
func TestHR529_TeamsCardsAreLinkOnlyToStandardChannels(t *testing.T) {
	e := newTeamsEnv(t)
	shared := e.channel(t, "teams-partners", teamsShared)
	if _, err := e.svc.ActivateTeamsApp(e.admin(), shared.ID, e.fresh()); !errors.Is(err, napp.ErrTeamsShared) {
		t.Fatalf("a shared channel: %v", err)
	}
	if got := e.str(t, "SELECT state || '/' || coalesce(membership_type, '') FROM pc.teams_app_channels WHERE channel_record_id = $1", shared.ID); got != "PENDING_ACTIVATION/shared" {
		t.Fatalf("the shared channel is %s", got)
	}
	internal := e.channel(t, "teams-approvals", teamsInternal)
	if _, err := e.svc.ActivateTeamsApp(e.as(td.KindUser, e.carol, td.RoleViewer), internal.ID, e.fresh()); err == nil {
		t.Fatal("a viewer activated a Teams channel")
	}
	if _, err := e.svc.ActivateTeamsApp(e.admin(), internal.ID, e.fresh()); err != nil {
		t.Fatalf("activate: %v", err)
	}
	request := e.hold(t, 3600e9)
	e.deliverTeams(t)
	e.deliverTeams(t)
	msgs := e.sim.Messages()
	if len(msgs) != 1 || msgs[0].Channel != teamsInternal {
		t.Fatalf("messages %+v", msgs)
	}
	card := string(msgs[0].Attachments)
	if !strings.Contains(card, "Action.OpenUrl") || !strings.Contains(card, "/approvals/"+request.String()) {
		t.Fatalf("the card does not link the request: %s", card)
	}
	for _, no := range []string{"Action.Submit", "Action.Execute", "Input.", "Action.ShowCard"} {
		if strings.Contains(card, no) {
			t.Fatalf("the card has %s: %s", no, card)
		}
	}
	noBoundValues(t, "the Teams card", msgs[0].Text+card)
	if got := e.str(t, "SELECT state FROM pc.teams_cards WHERE request_id = $1", request); got != "POSTED" {
		t.Fatalf("card state %s; deliveries %s", got, e.str(t, "SELECT string_agg(state || ':' || coalesce(last_error, ''), ',') FROM pc.deliveries WHERE kind = 'teams_app'"))
	}
}

// TestHR529_AChannelThatChangedGetsNoCard: the members are read again before
// each card. A guest or a member of another tenant who joined after
// activation stops the card and returns the channel to PENDING_ACTIVATION,
// audited, with the org's admins told; it takes a new activation (D277).
//
// Covers: F161, PN-017.3
func TestHR529_AChannelThatChangedGetsNoCard(t *testing.T) {
	for name, joined := range map[string]teams.Member{
		"a guest":          {ID: "29:g", Name: "G", TenantID: teams.TenantID, UserRole: "guest"},
		"a partner tenant": {ID: "29:b", Name: "B", TenantID: teams.OtherTenantID, UserRole: "user"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newTeamsEnv(t)
			c := e.channel(t, "teams-approvals", teamsInternal)
			if _, err := e.svc.ActivateTeamsApp(e.admin(), c.ID, e.fresh()); err != nil {
				t.Fatal(err)
			}
			home := teams.Member{ID: "29:a", Name: "A", TenantID: teams.TenantID, UserRole: "user"}
			e.sim.SetChannel(teams.Channel{ID: teamsInternal, Name: "approvals", Installed: true, Members: []teams.Member{home, joined}})
			e.hold(t, 3600e9)
			e.deliverTeams(t)
			if msgs := e.sim.Messages(); len(msgs) != 0 {
				t.Fatalf("messages %+v", msgs)
			}
			if got := e.str(t, "SELECT state || '/' || membership_type || '/' || (activated_at IS NULL) || '/' || (shared_at IS NOT NULL) FROM pc.teams_app_channels WHERE channel_record_id = $1", c.ID); got != "PENDING_ACTIVATION/shared/true/true" {
				t.Fatalf("the channel is %s", got)
			}
			if got := e.str(t, "SELECT count(*)::text FROM pc.ledger_entries WHERE kind = 'audit.notification.teams_channel_shared'"); got != "1" {
				t.Fatalf("%s audits", got)
			}
			if got := e.str(t, "SELECT count(*)::text FROM pc.notifications WHERE type = 'notification.teams_channel_shared'"); got != "1" {
				t.Fatalf("%s notices", got)
			}
			// Back to internal, it takes an Org Admin again; then cards go.
			e.sim.SetChannel(teams.Channel{ID: teamsInternal, Name: "approvals", Installed: true, Members: []teams.Member{home}})
			if _, err := e.svc.ActivateTeamsApp(e.admin(), c.ID, e.fresh()); err != nil {
				t.Fatal(err)
			}
			e.hold(t, 3600e9)
			e.deliverTeams(t)
			if msgs := e.sim.Messages(); len(msgs) != 1 {
				t.Fatalf("after activating again: %+v", msgs)
			}
		})
	}
}

// TestHR529_AChannelNotReadIsNotInternal: a member with no role, and a
// channel that lists no one, were not read: neither is activated (D277).
//
// Covers: F161
func TestHR529_AChannelNotReadIsNotInternal(t *testing.T) {
	for name, members := range map[string][]teams.Member{
		"a member with no role": {{ID: "29:a", Name: "A", TenantID: teams.TenantID}},
		"no members":            {},
	} {
		t.Run(name, func(t *testing.T) {
			e := newTeamsEnv(t)
			e.sim.SetChannel(teams.Channel{ID: teamsInternal, Name: "approvals", Installed: true, Members: members})
			c := e.channel(t, "teams-approvals", teamsInternal)
			if _, err := e.svc.ActivateTeamsApp(e.admin(), c.ID, e.fresh()); !errors.Is(err, napp.ErrTeamsUnread) {
				t.Fatalf("activate: %v", err)
			}
			if got := e.str(t, "SELECT state FROM pc.teams_app_channels WHERE channel_record_id = $1", c.ID); got != "PENDING_ACTIVATION" {
				t.Fatalf("the channel is %s", got)
			}
		})
	}
}
