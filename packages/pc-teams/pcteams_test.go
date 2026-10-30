// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pcteams_test

import (
	"context"
	"encoding/json/v2"
	"log/slog"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/consequences"
	credentials "github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/sim/teams"
	pcteams "github.com/katocxl/pantherclaw/packages/pc-teams"
)

var tc = mapping.Context{
	Org: "01920000-0000-7000-8000-000000000001", Env: "01920000-0000-7000-8000-000000000002",
	RunID: "01920000-0000-7000-8000-000000000003", ActionID: "01920000-0000-7000-8000-000000000004",
	AgentInstance: "01920000-0000-7000-8000-000000000005",
}

func decode(t *testing.T) *domain.Package {
	t.Helper()
	p, err := manifest.Decode(pcteams.Package)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != pcteams.Name || p.Version != pcteams.Version {
		t.Fatalf("package %s %s", p.Name, p.Version)
	}
	return p
}

// TestHR524_TheTeamsPostIsBuiltFromTheActionAndPostedWithAMintedToken: the
// one agent-facing operation maps to a channel and tenant; the outbound
// POST /v3/conversations carries exactly the nested channel conversation
// the package fixes (isGroup a boolean, the channel and tenant from the
// target, the text from the action); posted with a token minted from the
// bot's credential, it reaches the simulated channel.
// Covers: HR-524, HR-526
func TestHR524_TheTeamsPostIsBuiltFromTheActionAndPostedWithAMintedToken(t *testing.T) {
	p := decode(t)
	m, err := mapping.New(p, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if tools := m.Tools(); len(tools) != 1 || tools[0].Tool != "teams_post_message" {
		t.Fatalf("agent-facing tools %v (D266: the post only)", tools)
	}
	parsed, err := m.MCP(context.Background(), tc, "teams_post_message",
		[]byte(`{"tenant_id":"`+teams.TenantID+`","channel_id":"`+teams.TeamID+`","text":"Deploy finished"}`))
	if err != nil {
		t.Fatal(err)
	}
	a := parsed.Action
	if a.Operation != "teams.message.post" || a.Target.ID != teams.TeamID || a.Target.Account != teams.TenantID ||
		len(a.Destinations) != 1 || a.Destinations[0].Kind != "external" {
		t.Fatalf("action %s", parsed.Canonical)
	}
	for name, args := range map[string]string{
		"path in channel": `{"tenant_id":"` + teams.TenantID + `","channel_id":"19:a/b@thread.tacv2","text":"x"}`,
		"no tenant":       `{"channel_id":"` + teams.TeamID + `","text":"x"}`,
		"is group":        `{"tenant_id":"` + teams.TenantID + `","channel_id":"` + teams.TeamID + `","text":"x","isGroup":false}`,
		"too long":        `{"tenant_id":"` + teams.TenantID + `","channel_id":"` + teams.TeamID + `","text":"` + strings.Repeat("x", 4001) + `"}`,
	} {
		if _, err := m.MCP(context.Background(), tc, "teams_post_message", []byte(args)); err == nil {
			t.Errorf("%s: mapped", name)
		}
	}

	sim := teams.New([]teams.Channel{{ID: teams.TeamID, Name: "General", Installed: true}}, teams.Faults{}, slog.New(slog.DiscardHandler)).
		WithRequire(teams.Require{ClientID: teams.AppID, ClientSecret: "bot~secret"})
	srv := httptest.NewServer(sim.Handler())
	t.Cleanup(srv.Close)
	d, _ := p.Definition("teams.message.post")
	built, err := egress.Build(srv.URL+"/teams", d, a, "txn")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(built.Body), `"isGroup":true`) {
		t.Fatalf("isGroup is not the JSON boolean true (D272): %s", built.Body)
	}
	var body any
	if err := json.Unmarshal(built.Body, &body); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"isGroup": true, "tenantId": teams.TenantID,
		"channelData": map[string]any{"channel": map[string]any{"id": teams.TeamID}, "tenant": map[string]any{"id": teams.TenantID}},
		"activity":    map[string]any{"type": "message", "text": "Deploy finished"},
	}
	if !reflect.DeepEqual(body, want) || built.URL.Path != "/teams/v3/conversations" {
		t.Fatalf("built %s %s", built.URL, built.Body)
	}
	client, err := egress.NewClient(srv.URL, 5*time.Second, 0, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(srv.URL)
	tok, err := broker.MintClientToken(context.Background(), client, []string{u.Host}, credentials.OAuthClient{
		V: 1, TokenURL: srv.URL + "/" + teams.TenantID + "/oauth2/v2.0/token", ClientID: teams.AppID, Scope: teams.Scope, ClientSecret: []byte("bot~secret"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tok.Clear()
	req, err := client.HTTPRequest(context.Background(), built)
	if err != nil {
		t.Fatal(err)
	}
	if err := tok.Place(req); err != nil {
		t.Fatal(err)
	}
	res, err := client.Do(req)
	if err != nil || res.Status != 201 {
		t.Fatalf("post: %d %v %s", res.Status, err, res.Body)
	}
	if msgs := sim.Messages(); len(msgs) != 1 || msgs[0].Text != "Deploy finished" || msgs[0].Channel != teams.TeamID {
		t.Fatalf("messages %+v", msgs)
	}
}

// TestT226_APostToAnExternalChannelPredictsDisclosure: when the gateway
// reports the channel external, the post predicts teams.message.disclose
// (external_disclosure); an internal channel predicts nothing.
// Covers: T-226, HR-524
func TestT226_APostToAnExternalChannelPredictsDisclosure(t *testing.T) {
	p := decode(t)
	on, _ := p.Definition("teams.message.post")
	var rules []consequences.Rule
	for _, r := range p.Consequences {
		if r.Operation == on.Operation {
			d, _ := p.Definition(r.Consequence.Operation)
			rules = append(rules, consequences.Rule{ConsequenceRule: r, Definition: d})
		}
	}
	now := time.Now()
	fact := func(members map[string]any) map[string]fdomain.Fact {
		return map[string]fdomain.Fact{"teams.channel.external": {
			Name: "teams.channel.external", SubjectType: "teams_channel", SubjectID: teams.TeamID,
			Value: fdomain.Value{Type: fdomain.TypeObject, Object: members}, ObservedAt: now.Add(-time.Second),
		}}
	}
	ev := consequences.NewEvaluator(celenv.DefaultLimits)
	for name, c := range map[string]struct {
		members map[string]any
		want    consequences.State
	}{
		"other tenant": {map[string]any{"external": true, "other_tenant": true, "guests": false, "members": 2}, consequences.Predicted},
		"guests":       {map[string]any{"external": true, "other_tenant": false, "guests": true, "members": 2}, consequences.Predicted},
		"internal":     {map[string]any{"external": false, "other_tenant": false, "guests": false, "members": 2}, consequences.NotTriggered},
		"unread":       {map[string]any{"unread": "Teams answered HTTP 403"}, consequences.Unknown},
	} {
		out := ev.Evaluate(context.Background(), rules, consequences.Input{On: on, TargetID: teams.TeamID, Facts: fact(c.members), Now: now})
		if len(out) != 1 || out[0].Err != nil || out[0].State != c.want {
			t.Fatalf("%s: %+v", name, out)
		}
		if c.want == consequences.Predicted && (out[0].Operation != "teams.message.disclose" || out[0].Target.ID != teams.TeamID) {
			t.Fatalf("%s: %+v", name, out[0])
		}
	}
	if !slices.ContainsFunc(on.Prerequisites, func(pr domain.Prerequisite) bool { return pr.Fact == "teams.channel.external" }) {
		t.Fatal("the post does not read teams.channel.external first")
	}
	if c, ok := on.Supports(domain.ConstraintDestinationSet, ""); !ok || !c.Required {
		t.Fatal("a post needs a destination bound")
	}
}
