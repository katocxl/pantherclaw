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
