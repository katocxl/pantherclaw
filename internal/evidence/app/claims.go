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
	// Agent, Connection and Operation are the claimed scope.
	Agent, Connection ids.UUID
	Operation         string
}

// coverageClaims are the coverage claims of the decision receipts (G0 M9,
// HR-217). The bundle carries, for each, the claimed snapshot's ledger
// entry, the scope's next snapshot and its invalidations up to the
// decision, and the scope's snapshot current at decision time with the one
// after it (T-089), so `pclaw verify` checks each claim offline. The receipts are
// the server's own records; only the bundle's verifier checks signatures.
// A claim the receipt says was unavailable names no snapshot, so it needs
// no entries.
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
					Unavailable string `json:"unavailable"`
					Snapshot    string `json:"snapshot"`
					Scope       struct {
						Agent      string `json:"agent"`
						Connection string `json:"connection"`
						Operation  string `json:"operation"`
					} `json:"scope"`
				} `json:"coverage"`
			} `json:"pap"`
		}
		if json.Unmarshal(raw, &c) != nil || c.Pap.Coverage == nil || c.Pap.Coverage.Unavailable != "" {
			continue
		}
		ref := claimRef{At: time.Unix(c.Iat, 0).UTC(), Operation: c.Pap.Coverage.Scope.Operation}
		ref.Snapshot, _ = ids.ParseUUID(c.Pap.Coverage.Snapshot)
		ref.Agent, _ = ids.ParseUUID(c.Pap.Coverage.Scope.Agent)
		ref.Connection, _ = ids.ParseUUID(c.Pap.Coverage.Scope.Connection)
		out = append(out, ref)
	}
	return out
}
