// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package a2astore

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	wire "github.com/katocxl/pantherclaw/internal/a2a"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
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

// TestHR221_A2ASimulatedCardURLMustBeALocalLiteral (D96 M1): a simulated
// connection's card URL is fetched only when it is a loopback literal of
// the interface URL's origin and that origin answers the simulator
// handshake; a DNS name, another origin, a private address or a server
// that is not a simulator is refused before any card is read, and the
// simulated client reaches loopback only.
func TestHR221_A2ASimulatedCardURLMustBeALocalLiteral(t *testing.T) {
	sim := httptest.NewServer(a2asim.New(a2asim.Options{}, a2asim.Faults{}, nil).Handler())
	t.Cleanup(sim.Close)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"x","supportedInterfaces":[{"url":"` + "http://" + r.Host + `/a2a","protocolBinding":"JSONRPC"}]}`))
	}))
	t.Cleanup(plain.Close)
	p := NewPinner()
	cfg := func(card, iface string) *pb.A2AConfig {
		return &pb.A2AConfig{CardUrl: card, Interface: &pb.A2AInterface{Protocol: wire.BindingJSONRPC, Url: iface}}
	}
	u, _ := url.Parse(sim.URL)
	for name, c := range map[string]*pb.A2AConfig{
		"dns name":      cfg("http://localhost:"+u.Port()+wire.CardPath, "http://localhost:"+u.Port()+a2asim.JSONRPCPath),
		"other origin":  cfg(plain.URL+wire.CardPath, sim.URL+a2asim.JSONRPCPath),
		"private addr":  cfg("http://10.0.0.5:8443"+wire.CardPath, "http://10.0.0.5:8443/a2a"),
		"not simulator": cfg(plain.URL+wire.CardPath, plain.URL+"/a2a"),
	} {
		if _, err := p.Pin(t.Context(), c, true); !errors.Is(err, ErrSimulatedCardURL) {
			t.Errorf("%s: %v, want ErrSimulatedCardURL", name, err)
		}
	}
	if _, err := p.Pin(t.Context(), cfg(sim.URL+wire.CardPath, sim.URL+a2asim.JSONRPCPath), true); err != nil {
		t.Fatalf("simulator on loopback: %v", err)
	}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://10.0.0.1:9/", nil)
	if resp, err := p.Simulated.Do(req); err == nil || !errors.Is(err, httpx.ErrDestinationDenied) {
		if resp != nil {
			_ = resp.Body.Close()
		}
		t.Fatalf("the simulated client reached 10/8: %v", err)
	}
}
