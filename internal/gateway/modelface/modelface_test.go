// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package modelface_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/gateway/modelface"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

const (
	public = "https://gw.example"
	host   = "api.anthropic.com"
)

type engine struct {
	client     *egress.Client
	unverified bool
	contained  string
	pap        pap.Code
	verified   int
}

func (e *engine) Nonce(context.Context) string { return "n" }
func (e *engine) ReportUnknown(context.Context, *pb.WorkloadCredentials, string, string) (pap.Code, string) {
	return pap.CodeInstanceNotAdmitted, "n"
}

func (e *engine) Verify(_ context.Context, _ *pb.WorkloadCredentials, run string) (dispatch.Verified, error) {
	e.verified++
	if e.pap != "" {
		return dispatch.Verified{Code: e.pap}, nil
	}
	return dispatch.Verified{OK: run != ""}, nil
}
func (e *engine) ModelContained(*control.Connection) string { return e.contained }
func (e *engine) ModelClient(context.Context, *control.Connection) (*egress.Client, bool) {
	return e.client, !e.unverified
}

type ctl struct {
	mu       sync.Mutex
	refuse   bool
	asked    []string
	reported int64
}

func (c *ctl) Authorize(_ context.Context, conn, run, h string, n int64) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.asked = append(c.asked, conn+" "+run+" "+h)
	if c.refuse {
		return "", errors.New("MODEL_ROUTE_CLOSED")
	}
	return ids.NewV7().String(), nil
}

func (c *ctl) Report(_ context.Context, _, _ string, n int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reported += n
	return nil
}

type cfg struct{ c *control.Config }

func (c cfg) Current() *control.Config { return c.c }

type world struct {
	relay  *httptest.Server
	got    chan *http.Request
	bodies chan []byte
	eng    *engine
	ctl    *ctl
	h      http.Handler
	conns  map[string]*control.Connection
}

func newWorld(t *testing.T, answer func(w http.ResponseWriter)) *world {
	t.Helper()
	w := &world{got: make(chan *http.Request, 4), bodies: make(chan []byte, 4), ctl: &ctl{}}
	w.relay = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.got <- r
		w.bodies <- b
		answer(rw)
	}))
	t.Cleanup(w.relay.Close)
	cl, err := egress.NewClient(w.relay.URL, 10*time.Second, 8<<20, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	if err != nil {
		t.Fatal(err)
	}
	w.eng = &engine{client: cl}
	mk := func(id, name string, simulated, relay bool) *control.Connection {
		return &control.Connection{GatewayConnection: &pb.GatewayConnection{
			Id: id, Name: name, Kind: "http", BaseUrl: w.relay.URL, Simulated: simulated, ModelRelay: relay, State: "ACTIVE",
		}}
	}
	w.conns = map[string]*control.Connection{
		"relay":    mk(ids.NewV7().String(), "relay", true, true),
		"real":     mk(ids.NewV7().String(), "real", false, true),
		"twin":     mk(ids.NewV7().String(), "twin", true, false),
		"unmarked": mk(ids.NewV7().String(), "unmarked", false, false),
	}
	w.h = modelface.New(w.eng, w.ctl, cfg{&control.Config{ByName: w.conns}}, public, nil)
	return w
}

func token(t *testing.T) string {
	t.Helper()
	sub := pap.Instance{Org: ids.New[ids.Org](), Agent: ids.NewV7(), Instance: ids.NewV7()}.String()
	payload, err := json.Marshal(map[string]any{"sub": sub, "cnf": map[string]string{"jkt": "k"}, "pap": map[string]string{"env": "e"}})
	if err != nil {
		t.Fatal(err)
	}
	return "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

func (w *world) call(t *testing.T, conn string, body []byte, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/model/"+conn+"/"+host+"/v1/messages?beta=true", bytes.NewReader(body))
	r.Header.Set("Authorization", "PAP "+token(t))
	r.Header.Set(dispatch.HeaderProof, "proof")
	r.Header.Set(dispatch.HeaderRunID, ids.NewV7().String())
	r.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	w.h.ServeHTTP(rec, r)
	return rec
}

func (w *world) relayed() bool {
	select {
	case <-w.got:
		return true
	default:
		return false
	}
}

// TestHR613_TheModelFaceStreamsBytesUnchangedAndCountsThem: a verified call of
// an open campaign reaches the relay byte for byte, with no credential, and
// its answer comes back; the server is asked first and told the answer's size
// (D313).
// Covers: F906
func TestHR613_TheModelFaceStreamsBytesUnchangedAndCountsThem(t *testing.T) {
	answer := "event: message_start\ndata: {}\n\n"
	w := newWorld(t, func(rw http.ResponseWriter) {
		rw.Header().Set("Content-Type", "text/event-stream")
		rw.Header().Set("Set-Cookie", "x=1")
		_, _ = io.WriteString(rw, answer)
	})
	body := []byte(`{"model":"m","stream":true,"messages":[{"role":"user","content":"AKIAIOSFODNN7EXAMPLE"}]}`)
	rec := w.call(t, "relay", body, map[string]string{"X-Api-Key": "sk-ant-leak", "Anthropic-Version": "2023-06-01", "Cookie": "c=1"})
	if rec.Code != http.StatusOK || rec.Body.String() != answer {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Set-Cookie") != "" || rec.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("answer headers %v", rec.Header())
	}
	r, got := <-w.got, <-w.bodies
	if !bytes.Equal(got, body) {
		t.Fatalf("the relay got %q, want the bytes unchanged", got)
	}
	if r.URL.Path != "/v1/messages" || r.URL.RawQuery != "beta=true" {
		t.Fatalf("relay path %s?%s", r.URL.Path, r.URL.RawQuery)
	}
	for _, k := range []string{"X-Api-Key", "Authorization", "Cookie", dispatch.HeaderProof} {
		if r.Header.Get(k) != "" {
			t.Fatalf("%s reached the relay", k)
		}
	}
	if r.Header.Get("Anthropic-Version") != "2023-06-01" {
		t.Fatal("the API version header was dropped")
	}
	if w.eng.verified != 1 || len(w.ctl.asked) != 1 || !strings.HasSuffix(w.ctl.asked[0], " "+host) {
		t.Fatalf("verified %d, asked %v", w.eng.verified, w.ctl.asked)
	}
	if w.ctl.reported != int64(len(answer)) {
		t.Fatalf("reported %d bytes, want %d", w.ctl.reported, len(answer))
	}
}

// TestHR614_OnlyASimulatedModelRelayIsServed: a real connection, a simulated
// connection that is no relay, and an unknown name are refused before the
// Authority or the server is asked, and nothing reaches the relay.
// Covers: F906
func TestHR614_OnlyASimulatedModelRelayIsServed(t *testing.T) {
	w := newWorld(t, func(http.ResponseWriter) {})
	for _, name := range []string{"real", "twin", "unmarked", "nope"} {
		if rec := w.call(t, name, []byte(`{}`), nil); rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), modelface.CodeUnknownConnection) {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if w.relayed() || w.eng.verified != 0 || len(w.ctl.asked) != 0 {
		t.Fatal("a refused connection reached further")
	}
}

// TestHR614_TheModelFaceKnowsARelayByItsMark: the gateway hands the face
// only /model/{name}/… where {name} is marked as a simulated model relay;
// every other /model/… path, a connection named model included, stays with
// the connection routes (D525 L5).
// Covers: F906
func TestHR614_TheModelFaceKnowsARelayByItsMark(t *testing.T) {
	w := newWorld(t, func(http.ResponseWriter) {})
	w.conns["model"] = &control.Connection{GatewayConnection: &pb.GatewayConnection{
		Id: ids.NewV7().String(), Name: "model", Kind: "http", BaseUrl: "https://payments.example.test", State: "ACTIVE",
	}}
	h := modelface.New(w.eng, w.ctl, cfg{&control.Config{ByName: w.conns}}, public, nil)
	if !h.Serves("/model/relay/" + host + "/v1/messages") {
		t.Fatal("the relay is not served")
	}
	for _, p := range []string{
		"/model/real/" + host + "/v1", "/model/twin/" + host + "/v1", "/model/nope/" + host + "/v1",
		"/model/model/" + host + "/v1", "/model/v1/charges", "/model", "/relay/" + host + "/v1",
	} {
		if h.Serves(p) {
			t.Errorf("%s went to the model face", p)
		}
	}
	if (&modelface.Handler{}).Serves("/model/relay/" + host + "/v1") {
		t.Error("served with no configuration")
	}
}

// TestHR614_TheRouteIsOffWithoutAnOpenCampaign: when the server refuses (no
// open campaign, a real agent, a closed campaign, another host or the run
// total), nothing is sent.
// Covers: F906
func TestHR614_TheRouteIsOffWithoutAnOpenCampaign(t *testing.T) {
	w := newWorld(t, func(http.ResponseWriter) {})
	w.ctl.refuse = true
	rec := w.call(t, "relay", []byte(`{}`), nil)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), modelface.CodeRouteClosed) || w.relayed() {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
}

// TestHR613_ContainmentAuthorityAndHandshakeStopTheRoute: an unverified
// workload, containment, an unverified relay and an oversized body each stop
// the call before anything is sent.
// Covers: F906
func TestHR613_ContainmentAuthorityAndHandshakeStopTheRoute(t *testing.T) {
	w := newWorld(t, func(http.ResponseWriter) {})
	w.eng.pap = pap.CodeInstanceNotAdmitted
	if rec := w.call(t, "relay", []byte(`{}`), nil); rec.Code != http.StatusUnauthorized || len(w.ctl.asked) != 0 {
		t.Fatalf("unverified workload: %d", rec.Code)
	}
	w.eng.pap = ""
	w.eng.contained = dispatch.CodeKillSwitch
	if rec := w.call(t, "relay", []byte(`{}`), nil); rec.Code != http.StatusServiceUnavailable || len(w.ctl.asked) != 0 {
		t.Fatalf("contained: %d", rec.Code)
	}
	w.eng.contained = ""
	w.eng.unverified = true
	if rec := w.call(t, "relay", []byte(`{}`), nil); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), modelface.CodeUnverified) {
		t.Fatalf("unverified relay: %d %s", rec.Code, rec.Body.String())
	}
	w.eng.unverified = false
	if rec := w.call(t, "relay", make([]byte, modelface.MaxBody+1), nil); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large body: %d", rec.Code)
	}
	if w.relayed() {
		t.Fatal("a stopped call reached the relay")
	}
}

// TestHR613_AnAnswerPastTheCapIsCut: an answer longer than 8 MiB breaks the
// agent's connection rather than reading as whole.
// Covers: F906
func TestHR613_AnAnswerPastTheCapIsCut(t *testing.T) {
	w := newWorld(t, func(rw http.ResponseWriter) {
		_, _ = rw.Write(make([]byte, modelface.MaxBody+1024))
	})
	defer func() {
		if r, _ := recover().(error); !errors.Is(r, http.ErrAbortHandler) {
			t.Fatalf("recovered %v, want ErrAbortHandler", r)
		}
		if w.ctl.reported > modelface.MaxBody {
			t.Fatalf("reported %d", w.ctl.reported)
		}
	}()
	w.call(t, "relay", []byte(`{}`), nil)
	t.Fatal("the answer was not cut")
}

// TestPath parses the face's path.
func TestPath(t *testing.T) {
	for p, ok := range map[string]bool{
		"/model/relay/api.openai.com/v1/chat": true, "/model/relay/api.openai.com": true,
		"/model/relay/API.openai.com/v1": false, "/model//h/v1": false, "/model/relay": false, "/mcp/x": false, "/model/re%2Flay/h/v1": false,
	} {
		if _, _, _, got := modelface.Path(p); got != ok {
			t.Errorf("%s: %v", p, got)
		}
	}
}
