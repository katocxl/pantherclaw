// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateways/ca"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// TestHR493_TheListenerCertificateIsReissuedDaily (ADR-0040, gateway
// listener certificate, off the decision path): the same certificate is
// served for a day, a new one after it, and none is valid for more than
// seven days.
// Covers: HR-493
func TestHR493_TheListenerCertificateIsReissuedDaily(t *testing.T) {
	reg := keys.NewRegistry()
	k, err := keys.GenerateSigningKey(keys.PurposeGatewayCA)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Put(k); err != nil {
		t.Fatal(err)
	}
	authority, err := ca.New(reg)
	if err != nil {
		t.Fatal(err)
	}
	clk := clock.NewFake(time.Now())
	l := &listenerCerts{ca: authority, names: []string{"gw-api.example.test"}, clk: clk}
	first, err := l.get(nil)
	if err != nil {
		t.Fatal(err)
	}
	clk.Advance(listenerReissue - time.Second)
	if again, _ := l.get(nil); again != first {
		t.Fatal("reissued within a day")
	}
	clk.Advance(time.Second)
	next, err := l.get(nil)
	if err != nil || next == first {
		t.Fatalf("not reissued after a day: %v", err)
	}
	for _, c := range []*[][]byte{&first.Certificate, &next.Certificate} {
		cert, err := x509.ParseCertificate((*c)[0])
		if err != nil {
			t.Fatal(err)
		}
		if life := cert.NotAfter.Sub(cert.NotBefore); life > 7*24*time.Hour+time.Hour {
			t.Fatalf("a listener certificate valid for %v", life)
		}
	}
}
