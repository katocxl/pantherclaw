// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package a2a

import (
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/katocxl/pantherclaw/internal/sim/payments"
)

// ErrNoPeerRun refuses a verified token that names no peer run.
var ErrNoPeerRun = errors.New("peer_run_missing")

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// PeerVerifier is what a PantherClaw peer agent's helper does (sdk/go/a2a,
// D33, D77): verify the message's PAP-Action token against PantherClaw's
// keys, addressed to audience (the peer's interface URL), for exactly this
// body and the operation a2a.message.send on the peer, once; then read the
// delegated run from its pc_peer_run claim. A message without one is
// refused.
func PeerVerifier(v *payments.ActionVerifier) func(r *http.Request, body []byte) (string, error) {
	return func(r *http.Request, body []byte) (string, error) {
		if err := v.Verify(r.Context(), r, body, payments.Want{Operation: "a2a.message.send", TargetType: "a2a.agent", TargetID: "peer"}); err != nil {
			return "", err
		}
		parts := strings.Split(r.Header.Get(payments.HeaderAction), ".")
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return "", ErrNoPeerRun
		}
		var c struct {
			PeerRun string `json:"pc_peer_run"`
		}
		if json.Unmarshal(payload, &c) != nil || !uuidRE.MatchString(c.PeerRun) {
			return "", ErrNoPeerRun
		}
		return c.PeerRun, nil
	}
}
