// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package egress

import (
	"net/netip"
	"time"
)

// ModelMaxAnswer caps a model connection's answer, read as it arrives
// (G0 M29 D814): past it Open's body fails with ErrTooLarge.
const ModelMaxAnswer = 16 << 20

// NewModelClient returns a model connection's client: NewClient's hardened
// client with the model path's fixed answer cap instead of a connection's
// setting, which a model connection does not have (D811, D814).
func NewModelClient(baseURL string, timeout time.Duration, allowed []netip.Prefix) (*Client, error) {
	c, err := NewClient(baseURL, timeout, 0, allowed)
	if err != nil {
		return nil, err
	}
	c.maxBytes = ModelMaxAnswer
	return c, nil
}
