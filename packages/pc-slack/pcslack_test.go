// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pcslack_test

import (
	"context"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	pcslack "github.com/katocxl/pantherclaw/packages/pc-slack"
)

var tc = mapping.Context{
	Org: "01920000-0000-7000-8000-000000000001", Env: "01920000-0000-7000-8000-000000000002",
	RunID: "01920000-0000-7000-8000-000000000003", ActionID: "01920000-0000-7000-8000-000000000004",
	AgentInstance: "01920000-0000-7000-8000-000000000005",
}

func decode(t *testing.T) *domain.Package {
	t.Helper()
	p, err := manifest.Decode(pcslack.Package)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func mapper(t *testing.T) *mapping.Mapper {
	t.Helper()
	m, err := mapping.New(decode(t), celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestT146_SlackPostIsOneActionOnEveryRoute: a post through the Web API and
// through the Slack MCP server's tools is the same action, whose target and
// destination are the channel, so a grant or policy that bounds channels
// bounds both routes (D25, F099).
func TestT146_SlackPostIsOneActionOnEveryRoute(t *testing.T) {
	m := mapper(t)
	ctx := context.Background()
	h, err := m.HTTPRequest(ctx, tc, "POST", "/chat.postMessage", "", "application/json",
		[]byte(`{"channel":"C0APPROVAL1","text":"Deploy finished"}`))
	if err != nil {
		t.Fatal(err)
	}
	c, err := m.MCP(ctx, tc, "slack_post_message", []byte(`{"channel_id":"C0APPROVAL1","text":"Deploy finished"}`))
	if err != nil {
		t.Fatal(err)
	}
	if h.Action.DedupeKey != c.Action.DedupeKey || h.Action.Route != c.Action.Route || string(h.Action.Params) != string(c.Action.Params) ||
		h.Action.Target != c.Action.Target {
		t.Fatalf("routes differ:\n%s\n%s", h.Canonical, c.Canonical)
	}
	a := h.Action
	if a.Operation != "slack.message.post" || a.Target.ID != "C0APPROVAL1" || len(a.Destinations) != 1 ||
		a.Destinations[0].ID != "C0APPROVAL1" || a.Destinations[0].Kind != "external" {
		t.Fatalf("action: %s", h.Canonical)
	}
	r, err := m.MCP(ctx, tc, "slack_reply_to_thread", []byte(`{"channel_id":"C0APPROVAL1","thread_ts":"1700000000.000100","text":"Done"}`))
	if err != nil || !strings.Contains(string(r.Canonical), "1700000000.000100") {
		t.Fatalf("reply: %v %s", err, r.Canonical)
	}
	for name, args := range map[string]string{
		"lowercase channel": `{"channel_id":"c0approval1","text":"x"}`,
		"user id":           `{"channel_id":"U0APPROVAL1","text":"x"}`,
		"no text":           `{"channel_id":"C0APPROVAL1"}`,
		"too long":          `{"channel_id":"C0APPROVAL1","text":"` + strings.Repeat("x", 4001) + `"}`,
		"unknown field":     `{"channel_id":"C0APPROVAL1","text":"x","as_user":true}`,
	} {
		if _, err := m.MCP(ctx, tc, "slack_post_message", []byte(args)); err == nil {
			t.Errorf("%s: mapped", name)
		}
	}
}

// TestHR316_SlackTextIsDisclosedContentAndExternalChannelsAreAConsequence:
// the message text is a content param with disclosure limits (D70, HR-079),
// every post waits for the channel's sharing fact, a post to a shared
// channel predicts external_disclosure, and only a bot token is ever sent
// (D25, HR-301).
func TestHR316_SlackTextIsDisclosedContentAndExternalChannelsAreAConsequence(t *testing.T) {
	p := decode(t)
	post, ok := p.Definition("slack.message.post")
	if !ok {
		t.Fatal("no slack.message.post")
	}
	text := post.Params["text"]
	if text.Type != domain.TypeContent || !text.Disclosure || text.MaxBytes != 4000 {
		t.Fatalf("text: %+v", text)
	}
	if len(post.Prerequisites) != 1 || post.Prerequisites[0].Fact != "slack.channel.external" || post.Prerequisites[0].MaxAgeSeconds != 300 {
		t.Fatalf("prerequisites: %+v", post.Prerequisites)
	}
	if post.Dispatch.HTTP.Success == nil || post.Dispatch.HTTP.Success.Field != "ok" || !post.Dispatch.HTTP.Success.Equals {
		t.Fatalf("success: %+v", post.Dispatch.HTTP.Success)
	}
	for _, op := range []string{"slack.message.post", "slack.channel.read"} {
		d, _ := p.Definition(op)
		if d.Dispatch.CredentialPattern != `^xoxb-[A-Za-z0-9-]{20,}$` {
			t.Fatalf("%s credential pattern %q", op, d.Dispatch.CredentialPattern)
		}
	}
	var found bool
	for _, c := range p.Consequences {
		if c.Operation == "slack.message.post" && c.Consequence.Effect == "external_disclosure" &&
			len(c.RequiresFacts) == 1 && c.RequiresFacts[0] == "slack.channel.external" {
			found = true
		}
	}
	if !found {
		t.Fatal("no external_disclosure consequence")
	}
}
