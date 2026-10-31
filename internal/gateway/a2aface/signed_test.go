// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package a2aface

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	wire "github.com/katocxl/pantherclaw/internal/a2a"
)

const rewrittenCard = `{"name":"peer","version":"1","description":"d","supportedInterfaces":[{"url":"https://gw/a2a/peer","protocolBinding":"JSONRPC","protocolVersion":"1.0"}]}`

func cardKey(t *testing.T) (ed25519.PrivateKey, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := wire.PublicJWKS(map[string]crypto.PublicKey{"a2a-card-1": pub})
	if err != nil {
		t.Fatal(err)
	}
	return priv, jwks
}

func signedFace(sign SignCard) (*Handler, *bytes.Buffer) {
	var logs bytes.Buffer
	h := &Handler{log: slog.New(slog.NewTextHandler(&logs, nil)), now: time.Now}
	return h.WithCardSigner(sign), &logs
}

// TestHR590_AFailedSigningServesTheCardUnsigned: however signing fails, the
// card goes out as rewritten, with no signature that does not verify, and the
// failure is logged.
// Covers: F882
func TestHR590_AFailedSigningServesTheCardUnsigned(t *testing.T) {
	priv, jwks := cardKey(t)
	good, err := wire.Sign([]byte(rewrittenCard), "a2a-card-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	other, err := wire.Sign(bytes.Replace([]byte(rewrittenCard), []byte(`"peer"`), []byte(`"evil"`), 1), "a2a-card-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	_, otherKeys := cardKey(t)
	for name, sign := range map[string]SignCard{
		"the server refuses": func(context.Context, string, []byte) ([]byte, []byte, error) {
			return nil, nil, errors.New("A2A_CARD_MISMATCH")
		},
		"the server is slow": func(ctx context.Context, _ string, _ []byte) ([]byte, []byte, error) {
			<-ctx.Done()
			return nil, nil, ctx.Err()
		},
		"an empty answer": func(context.Context, string, []byte) ([]byte, []byte, error) { return nil, nil, nil },
		"a broken signature": func(context.Context, string, []byte) ([]byte, []byte, error) {
			return bytes.Replace(good, []byte(`"signature":"`), []byte(`"signature":"AAAA`), 1), jwks, nil
		},
		"a signature under another key": func(context.Context, string, []byte) ([]byte, []byte, error) { return good, otherKeys, nil },
		"no keys":                       func(context.Context, string, []byte) ([]byte, []byte, error) { return good, []byte(`{"keys":[]}`), nil },
		"another card, validly signed":  func(context.Context, string, []byte) ([]byte, []byte, error) { return other, jwks, nil },
		"an unsigned answer": func(context.Context, string, []byte) ([]byte, []byte, error) {
			return []byte(rewrittenCard), jwks, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			h, logs := signedFace(sign)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			got := h.signed(ctx, "conn", []byte(rewrittenCard))
			if !bytes.Equal(got, []byte(rewrittenCard)) {
				t.Fatalf("served %s", got)
			}
			if !strings.Contains(logs.String(), "gateway.a2a_card_unsigned") {
				t.Fatalf("not logged: %q", logs.String())
			}
			if _, ok := h.cards.get(sha256Of(rewrittenCard), time.Now()); ok {
				t.Fatal("a failure was cached")
			}
		})
	}
}

func sha256Of(s string) [32]byte { return sha256.Sum256([]byte(s)) }

// TestHR590_ASignedCardVerifiesAndIsCachedAnHour (D232): a good answer is
// served, verifies under the published key, and is reused for an hour.
// Covers: F882
func TestHR590_ASignedCardVerifiesAndIsCachedAnHour(t *testing.T) {
	priv, jwks := cardKey(t)
	calls := 0
	h, _ := signedFace(func(_ context.Context, conn string, card []byte) ([]byte, []byte, error) {
		calls++
		if conn != "conn" {
			t.Errorf("connection %q", conn)
		}
		s, err := wire.Sign(card, "a2a-card-1", priv)
		return s, jwks, err
	})
	clock := time.Unix(1000, 0)
	h.now = func() time.Time { return clock }
	got := h.signed(context.Background(), "conn", []byte(rewrittenCard))
	keys, err := wire.ParseKeys(jwks)
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.VerifySignatures(got, keys); err != nil {
		t.Fatalf("served card: %v (%s)", err, got)
	}
	clock = clock.Add(59 * time.Minute)
	if again := h.signed(context.Background(), "conn", []byte(rewrittenCard)); !bytes.Equal(again, got) || calls != 1 {
		t.Fatalf("within the hour: %d calls", calls)
	}
	clock = clock.Add(2 * time.Minute)
	if h.signed(context.Background(), "conn", []byte(rewrittenCard)); calls != 2 {
		t.Fatalf("after the hour: %d calls", calls)
	}
}

// TestCardWithoutSignerStaysUnsigned: a face with no signer serves as before.
func TestCardWithoutSignerStaysUnsigned(t *testing.T) {
	h := &Handler{}
	if got := h.signed(context.Background(), "c", []byte(rewrittenCard)); !bytes.Equal(got, []byte(rewrittenCard)) {
		t.Fatalf("served %s", got)
	}
}

// TestSignedCardCacheIsBounded: past the bound the cache starts again.
func TestSignedCardCacheIsBounded(t *testing.T) {
	var c signedCards
	now := time.Unix(1000, 0)
	for i := range maxSignedCards + 5 {
		c.put([32]byte{byte(i), byte(i >> 8)}, []byte("x"), now)
	}
	if len(c.byID) > maxSignedCards {
		t.Fatalf("%d entries", len(c.byID))
	}
}

// TestD253_AFailureHoldsForAMinute: a card that failed to sign is served
// unsigned for 60 seconds with no further call, then tried again; a reader
// that hung up holds nothing back.
// Covers: F882
func TestD253_AFailureHoldsForAMinute(t *testing.T) {
	calls := 0
	h, _ := signedFace(func(context.Context, string, []byte) ([]byte, []byte, error) {
		calls++
		return nil, nil, errors.New("A2A_CARD_NO_PUBLIC_URL")
	})
	now := time.Now()
	h.now = func() time.Time { return now }
	ctx := context.Background()
	for range 3 {
		if got := h.signed(ctx, "conn", []byte(rewrittenCard)); !bytes.Equal(got, []byte(rewrittenCard)) {
			t.Fatalf("served %s", got)
		}
	}
	if calls != 1 {
		t.Fatalf("%d calls within the minute", calls)
	}
	now = now.Add(signFailureTTL)
	h.signed(ctx, "conn", []byte(rewrittenCard))
	if calls != 2 {
		t.Fatalf("%d calls after the minute", calls)
	}

	gone, cancel := context.WithCancel(ctx)
	cancel()
	now = now.Add(signFailureTTL)
	h.signed(gone, "conn", []byte(rewrittenCard))
	h.signed(ctx, "conn", []byte(rewrittenCard))
	if calls != 4 {
		t.Fatalf("%d calls: a reader's hang-up held the card back", calls)
	}
}
