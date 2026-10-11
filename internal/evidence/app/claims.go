// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"encoding/base64"
	"encoding/json/v2"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// claimRef is a coverage claim of a decision receipt: the snapshot it
// names and when the decision was made.
type claimRef struct {
	Snapshot ids.UUID
	At       time.Time
}

// coverageClaims are the coverage claims of the decision receipts (G0 M9,
// HR-217). The bundle carries, for each, the claimed snapshot's ledger
// entry, the scope's next snapshot and its invalidations up to the
// decision, so `pclaw verify` checks each claim offline. The receipts are
// the server's own records; only the bundle's verifier checks signatures.
func coverageClaims(receipts []string) []claimRef {
	var out []claimRef
	for _, r := range receipts {
		parts := strings.Split(r, ".")
		if len(parts) != 3 {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			continue
		}
		var c struct {
			Iat int64 `json:"iat"`
			Pap struct {
				Coverage *struct {
					Snapshot string `json:"snapshot"`
				} `json:"coverage"`
			} `json:"pap"`
		}
		if json.Unmarshal(raw, &c) != nil || c.Pap.Coverage == nil {
			continue
		}
		if id, err := ids.ParseUUID(c.Pap.Coverage.Snapshot); err == nil {
			out = append(out, claimRef{Snapshot: id, At: time.Unix(c.Iat, 0).UTC()})
		}
	}
	return out
}
