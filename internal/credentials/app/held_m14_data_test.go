// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
)

// TestHeld_PostgresTakesACredentialWithoutAHeader (G0 M14 D84): a held
// postgres connection takes its role's password with no header; every
// other kind still needs one, and a postgres connection that is not held
// or is retired takes none.
func TestHeld_PostgresTakesACredentialWithoutAHeader(t *testing.T) {
	hdr := "Authorization"
	for _, c := range []struct {
		conn dbq.PcConnection
		ok   bool
	}{
		{dbq.PcConnection{Kind: "postgres", AccessMode: "pantherclaw_held", State: "ACTIVE"}, true},
		{dbq.PcConnection{Kind: "postgres", AccessMode: "none", State: "ACTIVE"}, false},
		{dbq.PcConnection{Kind: "postgres", AccessMode: "pantherclaw_held", State: "RETIRED"}, false},
		{dbq.PcConnection{Kind: "http", AccessMode: "pantherclaw_held", State: "ACTIVE"}, false},
		{dbq.PcConnection{Kind: "a2a", AccessMode: "pantherclaw_held", State: "ACTIVE"}, false},
		{dbq.PcConnection{Kind: "mcp", AccessMode: "pantherclaw_held", State: "ACTIVE"}, false},
		{dbq.PcConnection{Kind: "http", AccessMode: "pantherclaw_held", State: "ACTIVE", CredentialHeader: &hdr}, true},
	} {
		_, err := held(c.conn, nil)
		if (err == nil) != c.ok || (err != nil && !errors.Is(err, ErrNotHeld)) {
			t.Errorf("%s %s %s: %v", c.conn.Kind, c.conn.AccessMode, c.conn.State, err)
		}
	}
}
