// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"encoding/base64"
	"encoding/json/v2"
	"strings"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// claimedSnapshots are the coverage snapshots the decision receipts claim
// (G0 M9, HR-217): their ledger entries go into the bundle with the
// receipts, so `pclaw verify` checks each claim offline. The receipts are
// the server's own records; only the bundle's verifier checks signatures.
func claimedSnapshots(receipts []string) []ids.UUID {
	var out []ids.UUID
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
			out = append(out, id)
		}
	}
	return out
}
