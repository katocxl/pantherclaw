// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package report

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
)

func sample() Report {
	at := time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)
	digest := "sha256:" + strings.Repeat("a", 64)
	return Report{
		Format: Format, Session: "0199d3c2-7a10-7000-8000-000000000001", Nonce: "n0nce-0123456789abcdef", Kind: KindSandbox,
		StartedAt: at, FinishedAt: at.Add(time.Second),
		Images:  Images{Agent: digest, Edge: digest, Probe: digest},
		Engine:  Engine{Version: "29.8.2", APIVersion: "1.56", Runtime: "runc", Desktop: true},
		Network: Network{Name: "pc-sbx-1", Internal: true, GatewayModeIPv4: "isolated"},
		Config:  Config{Digest: digest, Checks: []Check{{ID: "read_only_root", OK: true}}},
		Results: []Result{
			{Name: "ipv6", Role: RoleProbe, Expect: Blocked, Observed: Blocked, Detail: "[2001:db8::1]:443: network is unreachable"},
			{Name: "edge_mediated", Role: RolePositive, Expect: Reachable, Observed: Reachable},
		},
		Canary: Canary{Hits: []Hit{}},
	}
}

func key(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func TestHR215_ASignedReportVerifiesWithItsSessionKeyOnly(t *testing.T) {
	k := key(t)
	compact, err := Sign(k, sample())
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(compact, pub(k))
	if err != nil {
		t.Fatal(err)
	}
	if got.Nonce != sample().Nonce || len(got.Results) != 2 || !got.Results[0].Passed() {
		t.Fatalf("verified %+v", got)
	}
	if _, err := Verify(compact, pub(key(t))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("another session's key: %v", err)
	}
	parts := strings.Split(compact, ".")
	tampered := parts[0] + "." + parts[1][:len(parts[1])-2] + "AA." + parts[2]
	if _, err := Verify(tampered, pub(k)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered: %v", err)
	}
	if _, err := Verify(parts[0]+"."+parts[1]+".", pub(k)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unsigned: %v", err)
	}
}

// TestHR215_OnlyCanonicalStrictReportsVerify: a validly signed payload
// that is not canonical JSON, carries an unknown member or another type is
// rejected.
func TestHR215_OnlyCanonicalStrictReportsVerify(t *testing.T) {
	k := key(t)
	s, err := jws.NewSigner(KeyID(pub(k)), k)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := sample().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct{ typ, payload string }{
		"not canonical":  {Type, " " + string(canon)},
		"unknown member": {Type, strings.Replace(string(canon), `{"canary"`, `{"admin":true,"canary"`, 1)},
		"another type":   {"pap+jwt", string(canon)},
		"not a report":   {Type, `{}`},
	} {
		compact, err := s.Sign(tc.typ, []byte(tc.payload))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(compact, pub(k)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestReportBounds(t *testing.T) {
	for name, mutate := range map[string]func(*Report){
		"format":        func(r *Report) { r.Format = "v0" },
		"kind":          func(r *Report) { r.Kind = "agent" },
		"short nonce":   func(r *Report) { r.Nonce = "abc" },
		"runtime":       func(r *Report) { r.Engine.Runtime = "nvidia" },
		"digest":        func(r *Report) { r.Images.Agent = "latest" },
		"times":         func(r *Report) { r.FinishedAt = r.StartedAt.Add(-time.Second) },
		"long detail":   func(r *Report) { r.Results[0].Detail = strings.Repeat("x", MaxDetail+1) },
		"bad name":      func(r *Report) { r.Results[0].Name = "Edge Mediated" },
		"role":          func(r *Report) { r.Results[0].Role = "agent" },
		"expect error":  func(r *Report) { r.Results[0].Expect = Error },
		"observed":      func(r *Report) { r.Results[0].Observed = "maybe" },
		"many results":  func(r *Report) { r.Results = make([]Result, MaxResults+1) },
		"hit proto":     func(r *Report) { r.Canary.Hits = []Hit{{Proto: "icmp", Port: 1, Marker: r.Nonce}} },
		"hit port":      func(r *Report) { r.Canary.Hits = []Hit{{Proto: "tcp", Port: 0, Marker: r.Nonce}} },
		"invalid utf-8": func(r *Report) { r.Results[0].Detail = "\xff" },
	} {
		r := sample()
		mutate(&r)
		if _, err := Sign(key(t), r); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if (Result{Expect: Error, Observed: Error}).Passed() {
		t.Fatal("an error passed")
	}
}

// FuzzProbeReport: no payload, however signed, panics the verifier or
// verifies without passing Validate.
func FuzzProbeReport(f *testing.F) {
	k := key(f)
	canon, err := sample().Canonical()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(canon)
	f.Add([]byte(`{"format":"pantherclaw.probe-report/v1"}`))
	f.Add([]byte(`[]`))
	s, err := jws.NewSigner(KeyID(pub(k)), k)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		compact, err := s.Sign(Type, payload)
		if err != nil {
			return
		}
		r, err := Verify(compact, pub(k))
		if err != nil {
			return
		}
		if r.Validate() != nil {
			t.Fatalf("verified an invalid report: %s", payload)
		}
		if again, err := r.Canonical(); err != nil || string(again) != string(payload) {
			t.Fatalf("verified a payload that is not the report's canonical form:\n%s\n%s", payload, again)
		}
	})
}
