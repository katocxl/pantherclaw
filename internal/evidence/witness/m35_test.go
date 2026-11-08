// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package witness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net/http"
	"testing"
	"time"
)

func cosig(t *testing.T, priv ed25519.PrivateKey, at time.Time, note string) []byte {
	t.Helper()
	sig := ed25519.Sign(priv, Message(at, note))
	out := make([]byte, timestampSize+len(sig))
	binary.BigEndian.PutUint64(out[:timestampSize], uint64(at.Unix()))
	copy(out[timestampSize:], sig)
	return out
}

// TestHR782_WitnessesSeeOnlyTheGlobalCheckpoint: a cosignature verifies for
// the checkpoint it was made over, and the client refuses a witness that
// is not https. The global origin is the only one this package submits.
func TestHR782_WitnessesSeeOnlyTheGlobalCheckpoint(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier("witness", pub)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1_700_000_000, 0)
	note := "logs.example/global\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
	if !v.Verify([]byte(note), cosig(t, priv, at, note)) {
		t.Fatal("a witness cosignature did not verify")
	}
	orgNote := "logs.example/org/01900000-0000-7000-8000-000000000001\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
	if v.Verify([]byte(orgNote), cosig(t, priv, at, note)) {
		t.Fatal("a cosignature of the global checkpoint verified a per-org note")
	}
	_, err = (&Client{Name: "witness", URL: "http://witness.example", Key: v, HTTP: &http.Client{Timeout: time.Second}}).AddCheckpoint(context.Background(), Request{}, note)
	if err == nil {
		t.Fatal("an http witness was accepted")
	}
}

// TestHR783_FewerCosignaturesThanTheThresholdFail: a bad signature does
// not count, and a verifier key that is not a cosignature key is refused.
func TestHR783_FewerCosignaturesThanTheThresholdFail(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier("witness", pub)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1_700_000_000, 0)
	note := "logs.example/global\n1\nroot\n"
	good := cosig(t, priv, at, note)
	if !v.Verify([]byte(note), good) {
		t.Fatal("threshold witness did not verify")
	}
	good[timestampSize] ^= 0xff
	if v.Verify([]byte(note), good) {
		t.Fatal("a damaged cosignature verified")
	}
	if _, err := ParseVKey("not-a-key"); err == nil {
		t.Fatal("a witness key that is not cosignature/v1 was accepted")
	}
}
