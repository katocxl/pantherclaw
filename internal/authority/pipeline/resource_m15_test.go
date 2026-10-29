// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// asResource reviews get_refund as the MCP resource payments://refunds/{refund}
// read through a kind-mcp connection (G0 M15 D30, D36).
func asResource(t *testing.T) func([]byte) []byte {
	return func(raw []byte) []byte {
		for _, r := range [][2]string{
			{"      - channel: http\n        method: GET\n        path: /v1/refunds/{refund}\n        route: payments-refund-get\n" +
				"        extract:\n          target_id: path.refund\n          params: {}\n", ""},
			{
				"      - channel: mcp\n        tool: get_refund\n        route: payments-refund-get\n" +
					"        description: Read one refund on the simulated payments API by its id.\n" +
					"        input_schema:\n          type: object\n          additionalProperties: false\n          required: [refund]\n" +
					"          properties:\n            refund:\n              type: string\n              description: The refund id\n" +
					"              pattern: '^re_[A-Za-z0-9-]{1,64}$'\n        extract:\n          target_id: input.refund\n",
				"      - channel: mcp_resource\n        resource: 'payments://refunds/{refund}'\n        route: payments-refund-get\n" +
					"        extract:\n          target_id: path.refund\n",
			},
			{
				"    dispatch:\n      http:\n        method: GET\n        path: /v1/refunds/{target.id}\n",
				"    dispatch:\n      mcp:\n        resource: 'payments://refunds/{target.id}'\n        upstream_digest: sha256:" +
					strings.Repeat("0f", 32) + "\n",
			},
		} {
			if bytes.Count(raw, []byte(r[0])) != 1 {
				t.Fatalf("mock payments package: %q not found once", r[0])
			}
			raw = bytes.Replace(raw, []byte(r[0]), []byte(r[1]), 1)
		}
		return raw
	}
}

// TestHR419_AResourceReadIsAReviewedRouteOfTheMCPChannel: a resource read's
// action is channel mcp through the mcp_resource mapping's route, and
// scope accepts it as a reviewed route of a kind-mcp connection; the same
// route through another gateway channel is not one.
// Covers: F352
func TestHR419_AResourceReadIsAReviewedRouteOfTheMCPChannel(t *testing.T) {
	f := newFxWith(t, asResource(t), "")
	gw := ids.NewV7()
	c := connection(gw)
	c.Kind = "mcp"
	f.w.PutConnection(c)
	p, err := f.mapper.ReadResource(context.Background(), mapping.Context{
		Org: org.String(), Env: f.env.String(), RunID: f.run.String(), ActionID: ids.NewV7().String(), AgentInstance: f.instance.String(),
		Connection: c.ID.String(),
	}, "payments://refunds/re_1")
	if err != nil {
		t.Fatal(err)
	}
	eval := func(ch string) *pipeline.Evaluation {
		p.Action.Channel = ch
		return f.eval(pipeline.Request{
			Org: org, Action: p, Identity: pipeline.Identity{InstanceID: f.instance, AgentID: f.agent, AttestationLevel: 1, JKT: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"},
			Gateway: gw.String(),
		})
	}
	scope := func(ev *pipeline.Evaluation) string {
		for _, it := range ev.Checklist {
			if it.Step == pipeline.StepScope {
				return it.Code
			}
		}
		return ""
	}
	if got := scope(eval("mcp")); got != pipeline.ReasonRouteReviewed {
		t.Fatalf("an mcp resource read: scope %s", got)
	}
	if got := scope(eval("http")); got != pipeline.ReasonRouteUnknown {
		t.Fatalf("the resource route through http: scope %s", got)
	}
}
