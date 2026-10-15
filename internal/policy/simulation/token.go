// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package simulation

import (
	"encoding/base64"

	"github.com/katocxl/pantherclaw/internal/platform/page"
)

// A sample page token is the last sample's transaction id and evaluation.
func sampleToken(k SampleKey) string {
	b := make([]byte, 0, 17)
	b = append(b, k.Transaction[:]...)
	b = append(b, byte(k.Evaluation)) //nolint:gosec // G115: an evaluation is 1..64
	return base64.RawURLEncoding.EncodeToString(b)
}

func parseSampleToken(s string) (SampleKey, error) {
	if s == "" {
		return SampleKey{}, nil
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != 17 || b[16] < 1 || b[16] > 64 {
		return SampleKey{}, page.ErrBadToken
	}
	var k SampleKey
	copy(k.Transaction[:], b[:16])
	if k.Transaction.IsZero() {
		return SampleKey{}, page.ErrBadToken
	}
	k.Evaluation = int(b[16])
	return k, nil
}
