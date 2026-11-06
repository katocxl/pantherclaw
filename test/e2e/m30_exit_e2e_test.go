// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/redteam/app"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// TestE2E_M30_GapsFromTheThreatMapHoldWhatTheyShould is M30's exit journey
// (G0 M30): on full stacks, through the gateway's faces,
//   - an injection phrase hidden by base64, hex or percent-encoding
//     holds in ACTIVE and a plain comment passes (HR-703, RT-200);
//   - making a repository public holds SHARE_PUBLIC and a transfer to an
//     account the org has not listed holds SHARE_ACCOUNT_NOT_OWNED, and
//     neither reaches GitHub (HR-707, RT-201);
//   - an MCP token bound to a client's key is refused without its proof
//     (HR-700, RT-202);
//   - the hook asks before an agent rewrites its memory file and is
//     refused, while an ordinary write asks nothing (HR-712, RT-203).
func TestE2E_M30_GapsFromTheThreatMapHoldWhatTheyShould(t *testing.T) {
	set, err := app.LoadDir("../../redteam/scenarios")
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]domain.Scenario{}
	for _, l := range set {
		byID[l.Scenario.ID] = l.Scenario
	}
	for _, id := range []string{"RT-200", "RT-201", "RT-202", "RT-203"} {
		t.Run(id, func(t *testing.T) {
			sc, ok := byID[id]
			if !ok {
				t.Fatalf("%s is not in the catalog", id)
			}
			d := newRangeDriver(t)
			res := (&app.Runner{Driver: d, Timeout: 5 * time.Minute}).Run(context.Background(), sc)
			if res.Verdict != domain.VerdictPass {
				for _, st := range res.Steps {
					t.Logf("step %s: matched=%v observed %s/%s/%s %s", st.StepID, st.Matched, st.Observed.Outcome, st.Observed.Reason,
						st.Observed.Code, firstN([]byte(st.Observed.Detail), 600))
				}
				t.Fatalf("%s %s: %s", id, res.Verdict, res.Detail)
			}
			if id != "RT-201" {
				return
			}
			// Held means not sent: GitHub saw no visibility change and no
			// transfer.
			for _, r := range d.s.gh.sim.Requests() {
				if (r.Method == http.MethodPatch && strings.Count(r.Path, "/") == 3 && strings.HasPrefix(r.Path, "/repos/")) ||
					strings.HasSuffix(r.Path, "/transfer") {
					t.Errorf("a held share reached GitHub: %s %s", r.Method, r.Path)
				}
			}
		})
	}
}
