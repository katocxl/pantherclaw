// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgranges_test

import (
	"encoding/base64"
	"testing"

	"github.com/katocxl/pantherclaw/internal/ranges/adapters/pgranges"
)

// compact wraps a payload as the middle part of a compact JWS; the stored
// reports were verified when they were accepted.
func compact(payload string) string {
	return "e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".c2ln"
}

func TestProbeResultsMapEachNameToWhatItObserved(t *testing.T) {
	got, err := pgranges.ProbeResults(compact(`{"results":[` +
		`{"name":"dns","role":"probe","expect":"blocked","observed":"blocked"},` +
		`{"name":"loopback","role":"positive_control","expect":"reachable","observed":"reachable"},` +
		`{"name":"v6","role":"probe","expect":"blocked","observed":"error"}]}`))
	if err != nil || len(got) != 3 || got["dns"] != "blocked" || got["loopback"] != "reachable" || got["v6"] != "error" {
		t.Fatalf("%v, %v", got, err)
	}
	for _, bad := range []string{"", "a.b", "a.!!.c", compact("not json")} {
		if _, err := pgranges.ProbeResults(bad); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}
