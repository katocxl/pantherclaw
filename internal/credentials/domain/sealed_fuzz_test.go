// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
)

// FuzzSealedCredential (G0 M6, HR-060, HR-182): no blob panics the format
// check or opening, and a blob that passes the check has the sealed
// shape. With the broker key, only the exact sealed bytes open, and only
// for the binding they were sealed to: a changed org, connection, host,
// version or placement never opens them, and two bindings whose fields
// hold no line break and whose hosts no comma share an info only when
// they are the same binding.
func FuzzSealedCredential(f *testing.F) {
	key, err := pccrypto.GenerateSealKey()
	if err != nil {
		f.Fatal(err)
	}
	b := binding()
	secret := []byte("sk_live_very_secret")
	sealed, err := pccrypto.Seal(key.PublicKey(), b.Info(), domain.AAD, secret)
	if err != nil {
		f.Fatal(err)
	}
	flipped := slices.Clone(sealed)
	flipped[len(flipped)-1] ^= 1
	f.Add(sealed, b.Org, b.Connection, b.AllowedHosts[0], b.Header, int32(3))
	f.Add(flipped, b.Org, b.Connection, b.AllowedHosts[1], b.Header, int32(3))
	f.Add(sealed[:domain.MinSealed-1], b.Org, b.Connection, "payments.example.test,auth.example.test:8443", b.Header, int32(3))
	f.Add(append([]byte{0x01, 0x00, 0x00}, sealed[3:]...), b.Org+"\nconnection="+b.Connection, "", b.AllowedHosts[0], b.Header, int32(-3))
	f.Add([]byte{}, b.Org, b.Connection, b.AllowedHosts[0], "X-Api-Key", int32(4))
	f.Fuzz(func(t *testing.T, blob []byte, org, connection, host, header string, version int32) {
		if domain.CheckFormat(blob) == nil {
			if len(blob) < domain.MinSealed || len(blob) > domain.MaxSealed || blob[0] != 0x01 ||
				binary.BigEndian.Uint16(blob[1:3]) != domain.EncLen {
				t.Fatalf("the format check accepted %d bytes starting %x", len(blob), blob[:min(3, len(blob))])
			}
		}
		if got, err := pccrypto.Open(key, b.Info(), domain.AAD, blob); err == nil && (!bytes.Equal(blob, sealed) || !bytes.Equal(got, secret)) {
			t.Fatalf("another blob opened for the binding: %x", blob)
		} else if err != nil && !errors.Is(err, pccrypto.ErrDecrypt) && !errors.Is(err, pccrypto.ErrSealedFormat) {
			t.Fatalf("opening failed outside its errors: %v", err)
		}
		other := domain.Binding{
			Org: org, Connection: connection, Version: version, AllowedHosts: []string{b.AllowedHosts[0], host},
			BrokerKey: b.BrokerKey, Header: header, Scheme: b.Scheme,
		}
		if _, err := pccrypto.Open(key, other.Info(), domain.AAD, sealed); err == nil && !bytes.Equal(other.Info(), b.Info()) {
			t.Fatalf("the credential opened for another binding:\n%s", other.Info())
		}
		if strings.ContainsRune(org+connection+host+header, '\n') || strings.ContainsRune(host, ',') {
			return
		}
		if bytes.Equal(other.Info(), b.Info()) &&
			(org != b.Org || connection != b.Connection || version != b.Version || header != b.Header || host != b.AllowedHosts[1]) {
			t.Fatalf("two bindings share one info:\n%+v\n%+v", other, b)
		}
	})
}
