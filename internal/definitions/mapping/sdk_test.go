// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapping

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
)

// TestHR201_SDKCallsMapThroughTheHookAndMCPMappings: an SDK call maps
// through the reviewed hook or MCP mapping exactly as that channel's call
// does, except that the action's channel is sdk (F099); no other channel
// maps an SDK call, and a mapping of one channel is not reached through
// the other.
func TestHR201_SDKCallsMapThroughTheHookAndMCPMappings(t *testing.T) {
	ctx := context.Background()
	for name, m := range map[string]struct {
		mapper *Mapper
		via    domain.Channel
		tool   string
		input  string
	}{
		"shell": {shellMapper(t), domain.ChannelHook, "shell", hookInput("bash", "go test ./...", "/home/dev/repo/./src/..", "toolu_01")},
		"mcp":   {mapperFor(t, mockRaw(t)), domain.ChannelMCP, "create_refund", `{"charge":"ch_1","amount":"30.00","currency":"USD","reason":"duplicate"}`},
	} {
		got, err := m.mapper.SDK(ctx, tc, m.via, m.tool, []byte(m.input))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var direct actionir.Parsed
		if m.via == domain.ChannelHook {
			direct, err = m.mapper.Hook(ctx, tc, m.tool, []byte(m.input))
		} else {
			direct, err = m.mapper.MCP(ctx, tc, m.tool, []byte(m.input))
		}
		if err != nil {
			t.Fatal(err)
		}
		a := direct.Action
		a.Channel = string(domain.ChannelSDK)
		want, err := actionir.Encode(a)
		if err != nil {
			t.Fatal(err)
		}
		if got.Action.Channel != "sdk" || got.Action.Route != direct.Action.Route || !bytes.Equal(got.Canonical, want.Canonical) {
			t.Errorf("%s: sdk %s, want %s", name, got.Canonical, want.Canonical)
		}
	}
	shell, payments := shellMapper(t), mapperFor(t, mockRaw(t))
	for name, err := range map[string]error{
		"http":          second(payments.SDK(ctx, tc, domain.ChannelHTTP, "create_refund", []byte(`{}`))),
		"sdk":           second(payments.SDK(ctx, tc, domain.ChannelSDK, "create_refund", []byte(`{}`))),
		"mcp as hook":   second(payments.SDK(ctx, tc, domain.ChannelHook, "create_refund", []byte(`{}`))),
		"hook as mcp":   second(shell.SDK(ctx, tc, domain.ChannelMCP, "shell", []byte(hookInput("bash", "ls", "/x", "t1")))),
		"unknown tool":  second(shell.SDK(ctx, tc, domain.ChannelHook, "exec", []byte(`{}`))),
		"unknown input": second(shell.SDK(ctx, tc, domain.ChannelHook, "shell", []byte(`{"shell":"bash","command":"ls","cwd":"/x","call":"t1","x":"y"}`))),
	} {
		want := ErrUnmapped
		if name == "unknown input" {
			want = actionir.ErrAmbiguous
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", name, err, want)
		}
	}
}

func second(_ actionir.Parsed, err error) error { return err }
