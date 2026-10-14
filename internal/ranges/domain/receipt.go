// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/base64"
	"encoding/json/v2"
	"strings"
)

// Receipt is the part of a decision receipt's payload a range reads (the
// server derives a step from it; `pclaw verify` re-derives it offline). The
// signature is checked elsewhere: by the bundle, against the pinned keys.
type Receipt struct {
	Decision string
	// Simulated is nil when the receipt does not say.
	Simulated *bool
	// Decisive is the first checklist item's code when it is decisive, as
	// the transaction's reason code is; Reasons are all the items' codes.
	Decisive string
	Reasons  []string
}

// ParseReceipt reads a compact JWS receipt's payload.
func ParseReceipt(compact string) (Receipt, bool) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return Receipt{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Receipt{}, false
	}
	var b struct {
		Pap struct {
			Decision  string `json:"decision"`
			Simulated *bool  `json:"simulated"`
			Checklist []struct {
				Code     string `json:"code"`
				Decisive bool   `json:"decisive"`
			} `json:"checklist"`
		} `json:"pap"`
	}
	if json.Unmarshal(raw, &b) != nil {
		return Receipt{}, false
	}
	out := Receipt{Decision: b.Pap.Decision, Simulated: b.Pap.Simulated, Decisive: "UNEXPLAINED"}
	for i, it := range b.Pap.Checklist {
		out.Reasons = append(out.Reasons, it.Code)
		if i == 0 && it.Decisive {
			out.Decisive = it.Code
		}
	}
	return out, true
}
