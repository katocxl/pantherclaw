// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
)

// TestHR085_TheGatewayPlacesTheCredentialOnAConnectorsEgress: a request a
// connector made, mapped through its egress connection, is rebuilt from
// the reviewed definition, carries the credential the gateway places and
// the call's idempotency key, and comes back without the credential. A
// quarantined egress connection sends nothing (G0 M9 design decisions 6
// and 18).
func TestHR085_TheGatewayPlacesTheCredentialOnAConnectorsEgress(t *testing.T) {
	h := setup(t, withCredential(t, []string{"127.0.0.1"}), func(h *harness) { h.target.echo = "Authorization" })
	ctx := mapping.Context{
		Org: testOrg, Env: testEnv, RunID: "01920000-0000-7000-8000-0000000000f1", ActionID: "01920000-0000-7000-8000-0000000000f2",
		AgentInstance: testAgent, Connection: connID,
	}
	a, err := h.conn.Mapper.HTTP(t.Context(), ctx, http.MethodPost, "/v1/refunds", "",
		[]byte(`{"charge":"ch_1","amount":"30.00","currency":"USD","reason":"duplicate"}`))
	if err != nil {
		t.Fatal(err)
	}
	res, err := h.gw.engine.ConnectorEgress(t.Context(), h.conn, a, "txn-1")
	if err != nil || res.Status != http.StatusOK {
		t.Fatalf("egress = %d %v", res.Status, err)
	}
	body, hdr := h.target.req(0)
	if hdr.Get("Authorization") != "Bearer "+testSecret || hdr.Get("Idempotency-Key") != "pc-txn-1" {
		t.Fatalf("target got Authorization %q, Idempotency-Key %q", hdr.Get("Authorization"), hdr.Get("Idempotency-Key"))
	}
	if !strings.Contains(body, `"charge":"ch_1"`) {
		t.Fatalf("target got %s", body)
	}
	if strings.Contains(string(res.Body), testSecret) || !strings.Contains(string(res.Body), "[REDACTED]") {
		t.Fatalf("the credential came back: %q", res.Body)
	}

	h.containment.mu.Lock()
	h.containment.conns[connID] = "QUARANTINED"
	h.containment.mu.Unlock()
	if _, err := h.gw.engine.ConnectorEgress(t.Context(), h.conn, a, "txn-1"); !errors.Is(err, dispatch.ErrEgressContained) || h.target.calls() != 1 {
		t.Fatalf("quarantined: %v, target %d", err, h.target.calls())
	}
}
