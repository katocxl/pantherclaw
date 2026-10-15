// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

import (
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	pcgithub "github.com/katocxl/pantherclaw/packages/pc-github"
)

// TestHR079_GitHubPullRequestBodyIsChecked (D73 M2): the shipped pc.github
// marks a pull request's body as a disclosure param with GitHub's 64 KiB
// limit, so a body toward GitHub (a public destination) is checked: dense
// raw bytes are denied DISCLOSURE_LIMIT; an ordinary body on a route the
// gateway mediates (MCP or HTTP) carries the obligation; through an SDK
// call or a hook (which the agent runs itself) it is checked here and
// carries none it could not honor (D76).
func TestHR079_GitHubPullRequestBodyIsChecked(t *testing.T) {
	pkg, err := manifest.Decode(pcgithub.Package)
	if err != nil {
		t.Fatal(err)
	}
	var def *defs.Definition
	for i := range pkg.Definitions {
		if pkg.Definitions[i].Operation == "github.pull.create" {
			def = &pkg.Definitions[i]
		}
	}
	if def == nil || !def.Params["body"].Disclosure || def.Params["body"].MaxBytes != 65536 ||
		def.Params["title"].Disclosure {
		t.Fatalf("pull.create params: %+v", def.Params)
	}
	run := func(channel, body string) *state {
		s := &state{
			a: actionir.ActionIR{Channel: channel}, ev: &Evaluation{}, def: def,
			conn: &Connection{Kind: "http", DestinationClass: "public"},
			vals: defs.Values{"body": {Type: defs.TypeContent, Str: body}, "title": {Type: defs.TypeContent, Str: "Fix"}},
		}
		s.disclosure()
		return s
	}
	decided := func(s *state, d adomain.Decision, code string) bool {
		for _, it := range s.cl.items {
			if it.effect == d && it.Code == code {
				return true
			}
		}
		return false
	}
	var dense strings.Builder
	for i := range 2000 {
		dense.WriteByte(byte('!' + i%94))
	}
	if s := run("mcp", dense.String()); !decided(s, adomain.Deny, ReasonDisclosureLimit) || len(s.ev.Obligations) != 0 {
		t.Fatalf("dense body: %+v %+v", s.cl.items, s.ev.Obligations)
	}
	s := run("mcp", "Bumps the dependency to fix CVE-2026-1234.")
	if len(s.ev.Obligations) != 1 || s.ev.Obligations[0].Kind != pdomain.DisclosureLimits || s.ev.Obligations[0].Param != "body" ||
		s.ev.Obligations[0].Max != "65536" || !decided(s, adomain.AllowWithObligations, ReasonDisclosureLimits) {
		t.Fatalf("mediated body: %+v", s.ev.Obligations)
	}
	sdk := run(string(defs.ChannelSDK), "Bumps the dependency.")
	if len(sdk.ev.Obligations) != 0 || !decided(sdk, adomain.Allow, ReasonDisclosureLimits) {
		t.Fatalf("sdk body: %+v %+v", sdk.ev.Obligations, sdk.cl.items)
	}
	if s := run(string(defs.ChannelSDK), dense.String()); !decided(s, adomain.Deny, ReasonDisclosureLimit) {
		t.Fatal("an SDK call is not checked")
	}
	// D76: a hook (gh pr create run by the agent, seen by the PreToolUse
	// hook) runs the tool inside the agent: within its limits it is
	// allowed with no obligation; over them it is denied.
	hook := run(string(defs.ChannelHook), "Bumps the dependency.")
	if len(hook.ev.Obligations) != 0 || !decided(hook, adomain.Allow, ReasonDisclosureLimits) ||
		decided(hook, adomain.AllowWithObligations, ReasonDisclosureLimits) {
		t.Fatalf("hook body: %+v %+v", hook.ev.Obligations, hook.cl.items)
	}
	if s := run(string(defs.ChannelHook), dense.String()); !decided(s, adomain.Deny, ReasonDisclosureLimit) || len(s.ev.Obligations) != 0 {
		t.Fatal("a hook call over its limits is not denied")
	}
	if s := run(string(defs.ChannelHTTP), "Bumps the dependency."); len(s.ev.Obligations) != 1 {
		t.Fatal("an HTTP call through the gateway carries no obligation")
	}
}
