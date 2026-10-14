// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgranges_test

import (
	"encoding/base64"
	"testing"

	"github.com/katocxl/pantherclaw/internal/ranges/adapters/pgranges"
	"github.com/katocxl/pantherclaw/internal/ranges/domain"
)

// compact wraps a payload as the middle part of a compact JWS; the stored
// reports were verified when they were accepted.
func compact(payload string) string {
	return "e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".c2ln"
}

func TestProbeOutcomeFollowsTheStoredResults(t *testing.T) {
	for name, tc := range map[string]struct{ payload, want string }{
		"all as expected": {`{"results":[{"name":"dns","role":"probe","expect":"blocked","observed":"blocked"},` +
			`{"name":"loopback","role":"positive_control","expect":"reachable","observed":"reachable"}]}`, domain.OutcomeBlocked},
		"one got out": {`{"results":[{"name":"dns","role":"probe","expect":"blocked","observed":"reachable"}]}`, domain.OutcomeAllow},
		"an error":    {`{"results":[{"name":"dns","role":"probe","expect":"blocked","observed":"error"}]}`, domain.OutcomeAllow},
		"no results":  {`{"results":[]}`, domain.OutcomeAllow},
	} {
		got, err := pgranges.ProbeOutcome(compact(tc.payload))
		if err != nil || got != tc.want {
			t.Errorf("%s: %q, %v, want %q", name, got, err, tc.want)
		}
	}
	for _, bad := range []string{"", "a.b", "a.!!.c", compact("not json")} {
		if _, err := pgranges.ProbeOutcome(bad); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}
