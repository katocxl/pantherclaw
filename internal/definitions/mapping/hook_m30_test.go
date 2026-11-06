// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapping

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// TestHR712_AConfigWriteMapsToAgentConfigWrite: the hook's agent_config
// call is pc.shell agent_config.write on the one local workspace, with the
// path joined to its base and normalized, its class, and the tool call id
// as the dedupe key (G0 M30 D943, D943a d). Anything but a write of a
// listed class with a call id maps to nothing.
func TestHR712_AConfigWriteMapsToAgentConfigWrite(t *testing.T) {
	m := shellMapper(t)
	ctx := context.Background()
	in := func(op, path, class, call string) []byte {
		return []byte(`{"op":"` + op + `","path":"` + path + `","class":"` + class + `","cwd":"/home/dev/repo","call":"` + call + `"}`)
	}
	a, err := m.Hook(ctx, tc, "agent_config", in("write", "./.claude/settings.json", "settings", "toolu_01"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Action.Operation != "agent_config.write" || a.Action.Target.ID != "local" || a.Action.DedupeKey == "" ||
		!strings.Contains(string(a.Action.Params), `"path":"/home/dev/repo/.claude/settings.json"`) ||
		!strings.Contains(string(a.Action.Params), `"class":"settings"`) {
		t.Fatalf("mapped %s", a.Canonical)
	}
	b, err := m.Hook(ctx, tc, "agent_config", in("write", ".claude/settings.json", "settings", "toolu_02"))
	if err != nil || b.Action.DedupeKey == a.Action.DedupeKey {
		t.Fatalf("another call id is another action: %v", err)
	}
	for name, raw := range map[string][]byte{
		"not a write":   in("delete", "CLAUDE.md", "memory", "toolu_01"),
		"unknown class": in("write", "CLAUDE.md", "secrets", "toolu_01"),
		"no call":       in("write", "CLAUDE.md", "memory", ""),
	} {
		if _, err := m.Hook(ctx, tc, "agent_config", raw); err == nil || (!errors.Is(err, actionir.ErrAmbiguous) && !errors.Is(err, ErrUnmapped)) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
