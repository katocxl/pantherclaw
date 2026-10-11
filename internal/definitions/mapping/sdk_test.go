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
