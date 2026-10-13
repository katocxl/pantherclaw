// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package actiontoken_test

import (
	"encoding/json/v2"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/actiontoken"
)

// payload keeps what it was asked to sign.
type payload struct{ b []byte }

func (p *payload) Sign(_ string, b []byte) (string, error) {
	p.b = b
	return "signed", nil
}

// TestHR188_ATestTokenEndsWithItsLease: a token lives TTL, or only up to
// NotAfter when that comes first, so a connection test's token ends with
// its lease; a dispatch's token, which sets no NotAfter, lives TTL.
func TestHR188_ATestTokenEndsWithItsLease(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for name, tc := range map[string]struct {
		notAfter time.Time
		exp      int64
	}{
		"a dispatch":           {time.Time{}, now.Unix() + 60},
		"a lease ending first": {now.Add(30*time.Second + 900*time.Millisecond), now.Unix() + 30},
		"a lease ending later": {now.Add(2 * time.Minute), now.Unix() + 60},
	} {
		var p payload
		if _, _, err := actiontoken.Mint(&p, actiontoken.Token{Operation: "payments.account.read", Now: now, NotAfter: tc.notAfter}); err != nil {
			t.Fatal(err)
		}
		var c struct {
			Iat int64 `json:"iat"`
			Exp int64 `json:"exp"`
		}
		if err := json.Unmarshal(p.b, &c); err != nil {
			t.Fatal(err)
		}
		if c.Iat != now.Unix() || c.Exp != tc.exp {
			t.Errorf("%s: iat %d, exp %d, want %d and %d", name, c.Iat, c.Exp, now.Unix(), tc.exp)
		}
	}
}
