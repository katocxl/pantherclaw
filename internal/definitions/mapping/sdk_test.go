// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapping

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
)

// TestHR201_SDKCallsMapThroughTheMCPMappings: an SDK call maps through the
// reviewed MCP mapping exactly as the MCP face's call does, except that
// the action's channel is sdk (F099); a hook mapping (the shell) is never
// reached through it, and input the mapping does not read is refused.
func TestHR201_SDKCallsMapThroughTheMCPMappings(t *testing.T) {
	ctx := context.Background()
	payments := mapperFor(t, mockRaw(t))
	const refund = `{"charge":"ch_1","amount":"30.00","currency":"USD","reason":"duplicate"}`
	got, err := payments.SDK(ctx, tc, "create_refund", []byte(refund))
	if err != nil {
		t.Fatal(err)
	}
	direct, err := payments.MCP(ctx, tc, "create_refund", []byte(refund))
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
		t.Fatalf("sdk %s, want %s", got.Canonical, want.Canonical)
	}
	shell := shellMapper(t)
	for name, err := range map[string]error{
		"the shell":     second(shell.SDK(ctx, tc, "shell", []byte(hookInput("bash", "ls", "/x", "t1")))),
		"an unknown":    second(payments.SDK(ctx, tc, "delete_everything", []byte(`{}`))),
		"unknown input": second(payments.SDK(ctx, tc, "get_refund", []byte(`{"refund":"re_1","x":"y"}`))),
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

// TestF346_ToolsListsExactlyTheMappedMCPTools: the SDK face's listing is
// every MCP mapping of the package with its operation, sorted, and
// nothing else: no hook or HTTP mapping (G0 M8 C2).
func TestF346_ToolsListsExactlyTheMappedMCPTools(t *testing.T) {
	raw := mockRaw(t)
	p, err := manifest.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	var want []Tool
	for _, d := range p.Definitions {
		for _, m := range d.Mappings {
			if m.Channel == domain.ChannelMCP {
				want = append(want, Tool{Tool: m.Tool, Operation: d.Operation})
			}
		}
	}
	slices.SortFunc(want, func(a, b Tool) int { return strings.Compare(a.Tool, b.Tool) })
	if got := mapperFor(t, raw).Tools(); len(want) == 0 || !slices.Equal(got, want) {
		t.Fatalf("tools %v, want %v", got, want)
	}
	if got := shellMapper(t).Tools(); len(got) != 0 {
		t.Fatalf("the shell package lists %v", got)
	}
}
