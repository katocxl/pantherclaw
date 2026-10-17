// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package a2astore

import (
	"bytes"
	"errors"
	"net/http/httptest"
	"testing"

	wire "github.com/katocxl/pantherclaw/internal/a2a"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	a2asim "github.com/katocxl/pantherclaw/internal/sim/a2a"
)

// TestHR322_OnlyTheServersOwnReadIsPinned: the pin is the card the server
// read, never one a caller supplied; a public connection cannot read a
// card on a loopback address; failures map to stable codes.
func TestHR322_OnlyTheServersOwnReadIsPinned(t *testing.T) {
	ts := httptest.NewServer(a2asim.New(a2asim.Options{}, a2asim.Faults{}, nil).Handler())
	t.Cleanup(ts.Close)
	p := NewPinner()
	cfg := &pb.A2AConfig{
		CardUrl: ts.URL + wire.CardPath, PinnedCard: []byte(`{"name":"forged"}`), CardDigest: make([]byte, 32),
		Interface: &pb.A2AInterface{Protocol: wire.BindingJSONRPC, Url: ts.URL + a2asim.JSONRPCPath}, Skills: []string{"refunds"},
	}
	got, err := p.Pin(t.Context(), cfg, true)
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	d, err := wire.Digest(got.GetPinnedCard())
	if err != nil || bytes.Contains(got.GetPinnedCard(), []byte("forged")) || !bytes.Equal(d[:], got.GetCardDigest()) {
		t.Fatalf("pinned %s (%x): %v", got.GetPinnedCard(), got.GetCardDigest(), err)
	}
	if bytes.Contains(cfg.GetPinnedCard(), []byte("Simulated")) {
		t.Fatal("Pin changed the caller's configuration")
	}
	if _, err := p.Pin(t.Context(), cfg, false); !errors.Is(err, ErrCardFetch) {
		t.Fatalf("public pin of a loopback card: %v, want ErrCardFetch", err)
	}
	bad := base(cfg)
	bad.Skills = []string{"transfers"}
	if _, err := p.Pin(t.Context(), bad, true); !errors.Is(err, ErrCardSkill) {
		t.Fatalf("undeclared skill: %v", err)
	}
	bad = base(cfg)
	bad.Interface = &pb.A2AInterface{Protocol: wire.BindingHTTPJSON, Url: ts.URL + a2asim.JSONRPCPath}
	if _, err := p.Pin(t.Context(), bad, true); !errors.Is(err, ErrCardInterface) {
		t.Fatalf("binding mix-up: %v", err)
	}
	bad = base(cfg)
	bad.CardKeys = []byte(`{"keys":[]}`)
	if _, err := p.Pin(t.Context(), bad, true); !errors.Is(err, ErrCardKeys) {
		t.Fatalf("empty JWKS: %v", err)
	}
}

func base(c *pb.A2AConfig) *pb.A2AConfig {
	return &pb.A2AConfig{CardUrl: c.GetCardUrl(), Interface: c.GetInterface(), Skills: c.GetSkills(), CardKeys: c.GetCardKeys()}
}
