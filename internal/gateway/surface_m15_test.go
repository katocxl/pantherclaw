// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/upstream"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/sim/mcpsim"
)

// Package mutations for the reviewed surface (G0 M15 D30, D32): get_refund
// as the resource payments://refunds/{refund}, read upstream at the
// simulator's payments://refunds/{target.id}.
const (
	getRefundMCP = "      - channel: mcp\n        tool: get_refund\n        route: payments-refund-get\n" +
		"        description: Read one refund on the simulated payments API by its id.\n" +
		"        input_schema:\n          type: object\n          additionalProperties: false\n          required: [refund]\n" +
		"          properties:\n            refund:\n              type: string\n              description: The refund id\n" +
		"              pattern: '^re_[A-Za-z0-9-]{1,64}$'\n        extract:\n          target_id: input.refund\n"
	getRefundResource = "      - channel: mcp_resource\n        resource: 'payments://refunds/{refund}'\n        route: payments-refund-get\n" +
		"        description: One refund on the simulated payments API.\n        extract:\n          target_id: path.refund\n"
	// getRefundHTTP goes: one operation is a tool or a resource, never both
	// (D36).
	getRefundHTTP = "      - channel: http\n        method: GET\n        path: /v1/refunds/{refund}\n        route: payments-refund-get\n" +
		"        extract:\n          target_id: path.refund\n          params: {}\n"
	getRefundHTTPDispatch = "    dispatch:\n      http:\n        method: GET\n        path: /v1/refunds/{target.id}\n"
	createRefundMCP       = "      - channel: mcp\n        tool: create_refund\n        route: payments-refund\n"
)

// withSurface makes the connection a kind-mcp connection to a simulated
// MCP server with faults f: create_refund is the upstream tool (with the
// elicitation fields given, if any) and get_refund the reviewed resource.
func withSurface(t *testing.T, f mcpsim.Faults, fields string) (*mcpsim.Server, func(*harness)) {
	t.Helper()
	sim := mcpsim.New(f)
	ts := httptest.NewServer(sim.Handler())
	t.Cleanup(ts.Close)
	create, err := upstream.ToolDigest(mcpsim.New(mcpsim.Faults{}).Tools()[0])
	if err != nil {
		t.Fatal(err)
	}
	resDigest := "sha256:" + strings.Repeat("0f", 32)
	return sim, func(h *harness) {
		h.conn.Kind, h.targetURL = "mcp", ts.URL+"/mcp"
		h.mutatePkg = func(raw []byte) []byte {
			changes := [][2]string{
				{
					"    dispatch:\n      http:\n        method: POST\n        path: /v1/refunds\n        body:\n",
					"    dispatch:\n      mcp:\n        tool: create_refund\n        upstream_digest: " + create + "\n        arguments:\n",
				},
				{"        idempotency_header: Idempotency-Key\n", ""},
				{getRefundMCP, getRefundResource},
				{getRefundHTTP, ""},
				{getRefundHTTPDispatch, "    dispatch:\n      mcp:\n        resource: 'payments://refunds/{target.id}'\n        upstream_digest: " + resDigest + "\n"},
			}
			if fields != "" {
				changes = append(changes, [2]string{createRefundMCP, createRefundMCP + "        elicitation:\n          fields:\n" + fields})
			}
			for _, r := range changes {
				if bytes.Count(raw, []byte(r[0])) != 1 {
					t.Fatalf("mock payments package: %q not found once", r[0])
				}
				raw = bytes.Replace(raw, []byte(r[0]), []byte(r[1]), 1)
			}
			return raw
		}
	}
}

// rawReply is a JSON-RPC answer read loosely.
type rawReply struct {
	code   int
	Result map[string]jsontext.Value `json:"result"`
	Error  *struct {
		Code    int                       `json:"code"`
		Message string                    `json:"message"`
		Data    map[string]jsontext.Value `json:"data"`
	} `json:"error"`
}

// rawCall posts a 2026-07-28 request for method with params, Mcp-Name
// name, in run, as the test workload.
func (h *harness) rawCall(t *testing.T, method, params, name, run string, hdr map[string]string) rawReply {
	t.Helper()
	return h.rawPost(t, method, jsonRPC(method, params), name, run, hdr)
}

// rawPost posts a 2026-07-28 body for method, Mcp-Name name, in run.
func (h *harness) rawPost(t *testing.T, method, body, name, run string, hdr map[string]string) rawReply {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, h.url+mcpPath, strings.NewReader(body))
	req.Header.Set("Authorization", "PAP "+testWorkloadToken())
	req.Header.Set(HeaderProof, "proof-not-checked-by-the-gateway")
	req.Header.Set(HeaderRunID, run)
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", method)
	if name != "" {
		req.Header.Set("Mcp-Name", name)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	r := rawReply{code: resp.StatusCode}
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("reply %d %q: %v", resp.StatusCode, b, err)
	}
	return r
}

// refundOn creates a refund through the upstream tool and returns its id.
func refundOn(t *testing.T, h *harness) string {
	t.Helper()
	r := h.mcpCall(t, http.MethodPost, mcpPath, jsonRPC("tools/call", refundArgs), nil)
	var re struct {
		ID string `json:"id"`
	}
	if r.body.Result.IsError || json.Unmarshal(r.body.Result.StructuredContent, &re) != nil || re.ID == "" {
		t.Fatalf("create_refund = %+v %+v", r.body.Error, r.body.Result)
	}
	return re.ID
}

// TestHR419_AReviewedResourceIsAReadOperation: a connection with a reviewed
// resource advertises resources (no subscriptions) and lists its template
// with the package's description; resources/read of a URI the template
// matches maps to the read's action, which the Authority decides, and is
// committed with BeginDispatch binding the canonical {uri}, read upstream
// and recorded ACCEPTED; the agent gets the contents with PantherClaw's
// facts.
// Covers: F352
func TestHR419_AReviewedResourceIsAReadOperation(t *testing.T) {
	sim, opt := withSurface(t, mcpsim.Faults{}, "")
	h := setup(t, opt)
	id := refundOn(t, h)
	run := ids.NewV7().String()

	d := h.rawCall(t, "server/discover", "", "", run, nil)
	if !strings.Contains(string(d.Result["capabilities"]), `"resources":{"listChanged":false,"subscribe":false}`) {
		t.Fatalf("capabilities %s", d.Result["capabilities"])
	}
	l := h.rawCall(t, "resources/templates/list", "", "", run, nil)
	if want := `[{"uriTemplate":"payments://refunds/{refund}","name":"payments-refund-get","title":"Read one refund",` +
		`"description":"One refund on the simulated payments API."}]`; string(l.Result["resourceTemplates"]) != want {
		t.Fatalf("templates %s, want %s", l.Result["resourceTemplates"], want)
	}
	if s := h.rawCall(t, "resources/list", "", "", run, nil); string(s.Result["resources"]) != "[]" {
		t.Fatalf("resources %s", s.Result["resources"])
	}

	before := h.auth.snap()
	uri := mcpsim.ResourcePrefix + id
	r := h.rawCall(t, "resources/read", `"uri":"`+uri+`"`, uri, run, nil)
	if r.Error != nil || !strings.Contains(string(r.Result["contents"]), `\"id\":\"`+id+`\"`) || string(r.Result["resultType"]) != `"complete"` {
		t.Fatalf("resources/read = %+v %v", r.Error, r.Result)
	}
	s := h.auth.snap()
	a := s.actions[len(s.actions)-1].Action
	if a.Operation != "payments.refund.get" || a.Channel != "mcp" || a.Route != "payments-refund-get" || a.Target.ID != id {
		t.Fatalf("action %+v", a)
	}
	params, _ := upstream.ReadParams(uri)
	sum := sha256.Sum256(params)
	begin := s.begins[len(s.begins)-1]
	if len(s.begins) != len(before.begins)+1 || !bytes.Equal(begin.GetOutboundBodySha256(), sum[:]) || begin.GetOutboundUrl() != h.targetURL {
		t.Fatalf("BeginDispatch %+v", begin)
	}
	if rec := s.records[len(s.records)-1]; rec.GetOutcome() != pb.Outcome_OUTCOME_ACCEPTED || !strings.Contains(string(r.Result["_meta"]), s.txn) {
		t.Fatalf("recorded %+v, meta %s", rec, r.Result["_meta"])
	}
	if got := sim.ResourceReads(); !slices.Equal(got, []string{uri}) {
		t.Fatalf("upstream reads %q", got)
	}
}

// TestHR419_AnUnreviewedURINeverReachesTheServer: a URI no reviewed
// template matches is "Resource not found" before any decision; one whose
// value breaks the target's identity, or that a policy denies, is refused
// with PantherClaw's facts; in each case the server reads nothing. A
// subscription is not a method, and a connection without a reviewed
// resource serves no resources at all.
// Covers: F352
func TestHR419_AnUnreviewedURINeverReachesTheServer(t *testing.T) {
	sim, opt := withSurface(t, mcpsim.Faults{}, "")
	h := setup(t, opt)
	id := refundOn(t, h)
	run := ids.NewV7().String()
	decided := h.auth.snap().authorize
	for _, uri := range []string{"payments://other/" + id, "payments://refunds/" + id + "/x", "https://evil.example/" + id, "payments://refunds/"} {
		r := h.rawCall(t, "resources/read", `"uri":"`+uri+`"`, uri, run, nil)
		if r.Error == nil || r.Error.Code != -32002 || r.Error.Message != "Resource not found" {
			t.Errorf("%s: %+v", uri, r.Error)
		}
	}
	if n := h.auth.snap().authorize; n != decided {
		t.Fatalf("%d decisions for unreviewed URIs", n-decided)
	}
	// A value that would change the upstream path is invalid params (D44).
	climb := "payments://refunds/re_1%2F..%2Fadmin"
	if r := h.rawCall(t, "resources/read", `"uri":"`+climb+`"`, climb, run, nil); r.Error == nil || r.Error.Code != -32602 {
		t.Fatalf("a value with a slash: %+v", r.Error)
	}
	// Matches the template, but the value is no refund id.
	bad := "payments://refunds/ch_1"
	if r := h.rawCall(t, "resources/read", `"uri":"`+bad+`"`, bad, run, nil); r.Error == nil || r.Error.Code != -32004 ||
		!strings.Contains(string(r.Error.Data["io.pantherclaw/error"]), "cannot_authorize") {
		t.Fatalf("a value outside the identity: %+v", r.Error)
	}
	h.auth.mu.Lock()
	h.auth.decision = pb.Decision_DECISION_DENY
	h.auth.mu.Unlock()
	uri := mcpsim.ResourcePrefix + id
	if r := h.rawCall(t, "resources/read", `"uri":"`+uri+`"`, uri, run, nil); r.Error == nil || r.Error.Code != -32004 ||
		!strings.Contains(string(r.Error.Data["io.pantherclaw/error"]), "GRANT_AMOUNT_EXCEEDED") {
		t.Fatalf("a denied read: %+v", r.Error)
	}
	if got := sim.ResourceReads(); len(got) != 0 {
		t.Fatalf("the server read %q", got)
	}
	if r := h.rawCall(t, "resources/subscribe", `"uri":"`+uri+`"`, "", run, nil); r.Error == nil || r.Error.Code != -32601 {
		t.Fatalf("subscribe: %+v", r.Error)
	}

	plain := setup(t)
	if r := plain.rawCall(t, "resources/templates/list", "", "", run, nil); r.Error == nil || r.Error.Code != -32601 {
		t.Fatalf("a connection without resources: %+v", r.Error)
	}
	if d := plain.rawCall(t, "server/discover", "", "", run, nil); strings.Contains(string(d.Result["capabilities"]), "resources") {
		t.Fatalf("capabilities %s", d.Result["capabilities"])
	}
}

// TestHR419_ResourcesInASession: the 2025-11-25 face lists and reads the
// same reviewed resources in a session, and initialize advertises them.
// Covers: F352
func TestHR419_ResourcesInASession(t *testing.T) {
	sim, opt := withSurface(t, mcpsim.Faults{Legacy: true}, "")
	h := setup(t, opt)
	id := refundOn(t, h)
	run := ids.NewV7().String()
	r := h.mcpCall(t, http.MethodPost, mcpPath, legacyRPC("initialize", initParams),
		map[string]string{HeaderRunID: run, "MCP-Protocol-Version": "", "Mcp-Method": ""})
	sid := r.hdr.Get("Mcp-Session-Id")
	if !strings.Contains(string(r.body.Result.Capabilities), `"resources":{"listChanged":false,"subscribe":false}`) {
		t.Fatalf("initialize capabilities %s", r.body.Result.Capabilities)
	}
	uri := mcpsim.ResourcePrefix + id
	read := h.inSession(t, http.MethodPost, sid, run, legacyRPC("resources/read", `"uri":"`+uri+`"`), nil)
	if read.code != http.StatusOK || read.body.Error != nil || len(h.auth.snap().records) != 2 ||
		!slices.Equal(sim.ResourceReads(), []string{uri}) {
		t.Fatalf("resources/read in a session = %d %+v, reads %q", read.code, read.body.Error, sim.ResourceReads())
	}
	miss := h.inSession(t, http.MethodPost, sid, run, legacyRPC("resources/read", `"uri":"payments://nothing"`), nil)
	if miss.errCode() != -32002 || len(sim.ResourceReads()) != 1 {
		t.Fatalf("an unreviewed URI in a session: %+v", miss.body.Error)
	}
}

// TestHR419_AnIdenticalHeldReadReusesItsAction (D44 L6, HR-185 parity):
// while a resource read is held, the same read by the same run and
// instance carries the held action id, so an approval binds to it; a
// read in another run gets an action of its own. Tasks are for tools/call
// only.
// Covers: F352
func TestHR419_AnIdenticalHeldReadReusesItsAction(t *testing.T) {
	_, opt := withSurface(t, mcpsim.Faults{}, "")
	h := setup(t, opt)
	id := refundOn(t, h)
	uri := mcpsim.ResourcePrefix + id
	run := ids.NewV7().String()
	h.auth.decide(pb.Decision_DECISION_REQUIRE_APPROVAL)
	last := func() string {
		s := h.auth.snap()
		return s.actions[len(s.actions)-1].Action.ActionID
	}
	h.rawCall(t, "resources/read", `"uri":"`+uri+`"`, uri, run, nil)
	first := last()
	h.rawCall(t, "resources/read", `"uri":"`+uri+`"`, uri, run, nil)
	if again := last(); again != first {
		t.Fatalf("the identical held read got action %s, want %s", again, first)
	}
	h.rawCall(t, "resources/read", `"uri":"`+uri+`"`, uri, ids.NewV7().String(), nil)
	if other := last(); other == first {
		t.Fatal("a read in another run reused the held action")
	}
}
