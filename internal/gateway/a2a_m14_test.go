// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"bufio"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	wire "github.com/katocxl/pantherclaw/internal/a2a"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	a2asim "github.com/katocxl/pantherclaw/internal/sim/a2a"
)

type a2aRig struct {
	*harness
	sim  *a2asim.Server
	peer *control.Connection
}

// setupA2A is the harness with an a2a connection "peer" to a simulated
// A2A agent over binding, its card pinned as the server pins it.
func setupA2A(t *testing.T, binding string) *a2aRig {
	t.Helper()
	sim := a2asim.New(a2asim.Options{}, a2asim.Faults{}, nil)
	ts := httptest.NewServer(sim.Handler())
	t.Cleanup(ts.Close)
	iface := ts.URL + a2asim.JSONRPCPath
	if binding == wire.BindingHTTPJSON {
		iface = ts.URL + a2asim.RESTPath
	}
	pinned, err := wire.Pin(t.Context(), ts.Client(), wire.PinRequest{
		CardURL: ts.URL + wire.CardPath, Binding: binding, URL: iface, Skills: []string{"refunds", "echo"},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := compile(t, "../../packages/pc-a2a/package.yaml", nil)
	if err != nil {
		t.Fatal(err)
	}
	peer := &control.Connection{
		GatewayConnection: &pb.GatewayConnection{
			Id: ids.NewV7().String(), Name: "peer", Kind: "a2a", Package: "pc.a2a", PackageVersion: "1.0.0", BaseUrl: iface,
			AllowedHosts: []string{"127.0.0.1"}, DestinationClass: "internal", AccessMode: "pantherclaw_held", DefaultMode: "enforce",
			MaxResponseBytes: 1 << 20, TimeoutMs: 2000, State: "ACTIVE", Revision: 1,
			A2A: &pb.A2AConfig{
				CardUrl: ts.URL + wire.CardPath, PinnedCard: pinned.Card, CardDigest: pinned.Digest[:],
				Interface: &pb.A2AInterface{Protocol: binding, Url: iface}, Skills: []string{"refunds", "echo"},
				MaxAnswerBytes: 1 << 20, MaxStreamSeconds: 30,
			},
		},
		Package: c.Package, Mapper: c.Mapper, Modes: map[string]string{},
	}
	h := setup(t, func(h *harness) { h.extra = append(h.extra, peer) })
	return &a2aRig{harness: h, sim: sim, peer: peer}
}

const a2aSend = `{"jsonrpc":"2.0","id":7,"method":"SendMessage","params":{"message":{"messageId":"m1","role":"ROLE_USER",` +
	`"parts":[{"text":"refund ch_1"}],"metadata":{"skill":"refunds"}}}}`

// TestHR323_A2AFaceSendsTheRebuiltMessage: a JSON-RPC SendMessage through
// the face is decided, rebuilt and sent over the pinned binding; the agent
// gets the peer's task in its own binding and may read it, and only it.
func TestHR323_A2AFaceSendsTheRebuiltMessage(t *testing.T) {
	for _, binding := range []string{wire.BindingJSONRPC, wire.BindingHTTPJSON} {
		t.Run(binding, func(t *testing.T) {
			r := setupA2A(t, binding)
			run := ids.NewV7().String()
			hdr := map[string]string{HeaderRunID: run, "Content-Type": "application/json"}
			got := r.call(t, http.MethodPost, "/a2a/peer", a2aSend, hdr)
			var env struct {
				ID     int                      `json:"id"`
				Result wire.SendMessageResponse `json:"result"`
				Error  *wire.RPCError           `json:"error"`
			}
			if err := json.Unmarshal([]byte(got.body), &env); err != nil || env.Error != nil || env.ID != 7 || env.Result.Task == nil ||
				env.Result.Task.Status.State != wire.StateCompleted {
				t.Fatalf("send: %d %s", got.code, got.body)
			}
			rec := r.sim.Received()
			if len(rec) != 1 || rec[0].Message.MessageID != r.auth.snap().txn || rec[0].Message.Text() != "refund ch_1" || rec[0].Binding != binding {
				t.Fatalf("the peer received %+v", rec)
			}
			a := r.auth.snap().actions[0].Action
			if a.Operation != "a2a.message.send" || a.Channel != "a2a" || a.Route != "a2a-send" || a.Connection != r.peer.GetId() {
				t.Fatalf("action %+v", a)
			}
			task := env.Result.Task.ID
			read := r.call(t, http.MethodGet, "/a2a/peer/tasks/"+task, "", hdr)
			if read.code != http.StatusOK || !strings.Contains(read.body, task) {
				t.Fatalf("own task: %d %s", read.code, read.body)
			}
			other := r.call(t, http.MethodGet, "/a2a/peer/tasks/"+task, "", map[string]string{HeaderRunID: ids.NewV7().String()})
			if other.code != http.StatusNotFound || !strings.Contains(other.body, "A2A_TASK_UNKNOWN") {
				t.Fatalf("another run reads the task: %d %s", other.code, other.body)
			}
		})
	}
}

// TestHR327_A2AFaceRelaysStreamsEventByEvent: a streamed message is
// relayed as server-sent events in the agent's binding.
func TestHR327_A2AFaceRelaysStreamsEventByEvent(t *testing.T) {
	r := setupA2A(t, wire.BindingHTTPJSON)
	body := `{"message":{"messageId":"m1","role":"ROLE_USER","parts":[{"text":"go"}],"metadata":{"skill":"echo"}}}`
	got := r.call(t, http.MethodPost, "/a2a/peer/message:stream", body, map[string]string{HeaderRunID: ids.NewV7().String()})
	if got.code != http.StatusOK || got.hdr.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("stream: %d %s", got.code, got.body)
	}
	n := 0
	sc := bufio.NewScanner(strings.NewReader(got.body))
	for sc.Scan() {
		if data, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
			if !jsontext.Value(data).IsValid() || strings.HasPrefix(data, `{"jsonrpc"`) {
				t.Fatalf("event %q", data)
			}
			n++
		}
	}
	if n != 4 {
		t.Fatalf("%d events: %s", n, got.body)
	}
}

// TestHR322_A2ACardDriftRefusesTheConnection: a re-read that finds another
// card reports drift and refuses the connection, before any decision or
// send, until a new pin.
func TestHR322_A2ACardDriftRefusesTheConnection(t *testing.T) {
	r := setupA2A(t, wire.BindingJSONRPC)
	reports := cardReports{}
	r.gw.checkA2ACards(t.Context(), r.gw.config.Current(), reports)
	if len(r.driftReports()) != 0 {
		t.Fatalf("drift on the pinned card: %v", r.driftReports())
	}
	r.sim.SetFaults(a2asim.Faults{Description: "Now also moves money"})
	r.gw.checkA2ACards(t.Context(), r.gw.config.Current(), reports)
	if d := r.driftReports(); len(d) != 1 || !strings.Contains(d[0], "a2a.card") {
		t.Fatalf("drift reports %v", d)
	}
	before := r.auth.snap().authorize
	got := r.call(t, http.MethodPost, "/a2a/peer", a2aSend, map[string]string{HeaderRunID: ids.NewV7().String()})
	if !strings.Contains(got.body, "A2A_CARD_DRIFT") || r.auth.snap().authorize != before || len(r.sim.Received()) != 0 {
		t.Fatalf("drifted connection served: %d %s", got.code, got.body)
	}
}

func TestA2AFaceServesThePinnedCardRewritten(t *testing.T) {
	r := setupA2A(t, wire.BindingJSONRPC)
	got := r.call(t, http.MethodGet, "/a2a/peer"+wire.CardPath, "", nil)
	c, err := wire.ParseCard([]byte(got.body))
	if err != nil || len(c.SupportedInterfaces) != 1 || !strings.HasSuffix(c.SupportedInterfaces[0].URL, "/a2a/peer") {
		t.Fatalf("card: %d %s %v", got.code, got.body, err)
	}
}

// call is harness.do without reading the answer as an HTTP-face refusal.
func (r *a2aRig) call(t *testing.T, method, path, body string, hdr map[string]string) reply {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), method, r.url+path, strings.NewReader(body))
	req.Header.Set("Authorization", "PAP "+testWorkloadToken())
	req.Header.Set(HeaderProof, "proof-not-checked-by-the-gateway")
	req.Header.Set(HeaderRunID, ids.NewV7().String())
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return reply{code: resp.StatusCode, hdr: resp.Header, body: string(b)}
}

// TestHR322_A2ACardDriftClearsOnlyOnThePinnedCard (D96 L1, L2): an
// oversize card is drift; once the peer serves the pinned card again, the
// gateway's own refusal lifts (the server keeps a drifted connection
// quarantined until a new pin is confirmed), and drift is reported once.
func TestHR322_A2ACardDriftClearsOnlyOnThePinnedCard(t *testing.T) {
	r := setupA2A(t, wire.BindingJSONRPC)
	reports := cardReports{}
	r.sim.SetFaults(a2asim.Faults{Description: strings.Repeat("x", wire.MaxCardBytes)})
	r.gw.checkA2ACards(t.Context(), r.gw.config.Current(), reports)
	r.gw.checkA2ACards(t.Context(), r.gw.config.Current(), reports)
	if d := r.driftReports(); len(d) != 1 || !strings.Contains(d[0], "invalid") {
		t.Fatalf("oversize card: drift reports %v", d)
	}
	if got := r.call(t, http.MethodPost, "/a2a/peer", a2aSend, nil); !strings.Contains(got.body, "A2A_CARD_DRIFT") {
		t.Fatalf("drifted connection served: %s", got.body)
	}
	r.sim.SetFaults(a2asim.Faults{})
	r.gw.checkA2ACards(t.Context(), r.gw.config.Current(), reports)
	got := r.call(t, http.MethodPost, "/a2a/peer", a2aSend, nil)
	if strings.Contains(got.body, "A2A_CARD_DRIFT") || len(r.sim.Received()) != 1 {
		t.Fatalf("pinned card again, still refused: %s", got.body)
	}
}

// TestHR322_A2ACardDriftReportIsRetried (D112): a drift report the server
// does not take is sent again, after a backoff that grows, until it is
// taken; then it is not sent again for the same drift.
func TestHR322_A2ACardDriftReportIsRetried(t *testing.T) {
	r := setupA2A(t, wire.BindingJSONRPC)
	reports := cardReports{}
	ok, tries := r.gw.reportDrift, 0
	r.gw.reportDrift = func(ctx context.Context, conn string, d dispatch.Drift) error {
		tries++
		if tries < 3 {
			return errors.New("server unavailable")
		}
		return ok(ctx, conn, d)
	}
	r.sim.SetFaults(a2asim.Faults{Description: "Now also moves money"})
	r.gw.checkA2ACards(t.Context(), r.gw.config.Current(), reports)
	now := time.Now()
	r.gw.reportA2ACards(t.Context(), reports, now)
	if tries != 1 || len(r.driftReports()) != 0 {
		t.Fatalf("before the backoff: %d tries, reports %v", tries, r.driftReports())
	}
	now = now.Add(cardReportFirst)
	r.gw.reportA2ACards(t.Context(), reports, now)
	r.gw.reportA2ACards(t.Context(), reports, now.Add(cardReportFirst))
	if tries != 2 {
		t.Fatalf("the backoff did not grow: %d tries", tries)
	}
	r.gw.reportA2ACards(t.Context(), reports, now.Add(2*cardReportFirst))
	r.gw.checkA2ACards(t.Context(), r.gw.config.Current(), reports)
	r.gw.reportA2ACards(t.Context(), reports, now.Add(time.Hour))
	if d := r.driftReports(); tries != 3 || len(d) != 1 || !strings.Contains(d[0], "a2a.card") {
		t.Fatalf("%d tries, reports %v", tries, d)
	}
}
