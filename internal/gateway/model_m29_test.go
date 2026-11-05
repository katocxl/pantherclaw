// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	simmodel "github.com/katocxl/pantherclaw/internal/sim/model"
)

// The model path through the whole gateway (G0 M29 D812–D820): the HTTP
// face hands a model connection's call to modelconn; the target is
// pantherclaw-sim model (HR-699), never a real provider.

// withModel makes the harness connection an Anthropic or OpenAI model
// connection to target (the fake model's URL), its key sealed for hosts,
// placed in header with scheme.
func withModel(t *testing.T, pkg, target string, hosts []string, header, scheme string) func(*harness) {
	return func(h *harness) {
		h.pkgFile = "../../packages/" + pkg + "/package.yaml"
		h.targetURL = target
		h.conn.Name, h.conn.Kind, h.conn.GatewayConnection.Package = "llm", "model", strings.ReplaceAll(pkg, "pc-", "pc.")
		h.conn.BaseUrl, h.conn.MaxResponseBytes, h.conn.TimeoutMs = target+"/v1", 0, 0
		h.conn.Model = &pb.ModelConfig{MaxOutputTokens: 77}
		dir := t.TempDir()
		kek := filepath.Join(dir, "kek")
		if err := keys.GenerateKEKFile(kek); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "broker.json")
		if _, err := broker.Generate(t.Context(), path, []string{kek}); err != nil {
			t.Fatal(err)
		}
		key, err := broker.Load(t.Context(), path, []string{kek})
		if err != nil {
			t.Fatal(err)
		}
		h.broker = NewBroker(key, nil, nil)
		h.broker.id = "bk-1"
		pub, _ := pccrypto.ParseSealPublicKey(key.PublicKey())
		bind := domain.Binding{Org: testOrg, Connection: connID, Version: 1, AllowedHosts: hosts, BrokerKey: "bk-1", Header: header, Scheme: scheme}
		blob, err := pccrypto.Seal(pub, bind.Info(), domain.AAD, []byte(testSecret))
		if err != nil {
			t.Fatal(err)
		}
		h.conn.AccessMode = "pantherclaw_held"
		h.conn.Credential = &pb.SealedCredential{
			Id: ids.NewV7().String(), ConnectionId: connID, Version: 1, BrokerKeyId: "bk-1", Sealed: blob, AllowedHosts: hosts,
			Header: header, Scheme: scheme,
		}
	}
}

// fakeModel starts pantherclaw-sim model accepting testSecret.
func fakeModel(t *testing.T, f simmodel.Faults) (*simmodel.Server, string) {
	t.Helper()
	sim := simmodel.New(testSecret, f, pclog.Discard())
	s := httptest.NewServer(sim.Handler())
	t.Cleanup(s.Close)
	return sim, s.URL
}

// anthropicModel is a harness with an Anthropic model connection to the
// fake model, its key in x-api-key; more options apply after.
func anthropicModel(t *testing.T, f simmodel.Faults, opts ...func(*harness)) (*harness, *simmodel.Server) {
	t.Helper()
	sim, url := fakeModel(t, f)
	return setup(t, append([]func(*harness){withModel(t, "pc-anthropic", url, []string{"127.0.0.1"}, "x-api-key", "")}, opts...)...), sim
}

// modelReply is the gateway's answer to a model call; err is a read error
// of its body (an aborted stream).
type modelReply struct {
	code int
	hdr  http.Header
	body string
	err  error
}

// call sends a model call as a verified workload over the "llm" connection.
func (h *harness) call(t *testing.T, path, body string, hdr map[string]string) modelReply {
	t.Helper()
	method := http.MethodPost
	if body == "" {
		method = http.MethodGet
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, h.url+"/llm"+path, strings.NewReader(body))
	req.Header.Set("Authorization", "PAP "+testWorkloadToken())
	req.Header.Set(HeaderProof, "proof-not-checked-by-the-gateway")
	req.Header.Set(HeaderRunID, ids.NewV7().String())
	req.Header.Set(HeaderActionID, ids.NewV7().String())
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	return modelReply{code: resp.StatusCode, hdr: resp.Header, body: string(b), err: err}
}

// refusedAs checks a refusal in Anthropic's error shape.
func refusedAs(t *testing.T, name string, r modelReply, status int, typ, code string) {
	t.Helper()
	if r.code != status || !strings.Contains(r.body, `"type":"error"`) || !strings.Contains(r.body, `"type":"`+typ+`"`) ||
		!strings.Contains(r.body, code) {
		t.Errorf("%s = %d %s, want %d %s %s", name, r.code, r.body, status, typ, code)
	}
}

const messages = `{"model":"sim-model","max_tokens":5,"messages":[{"role":"user","content":"hello"}]}`

// TestHR690_TheModelKeyIsPlacedByTheGatewayOnItsHostOnly: the fake model
// gets the gateway's sealed key, never the key or header the agent sent,
// and the agent never sees the key; a key sealed for other hosts sends
// nothing (G0 M29 D811, D812).
//
// Covers: F980, HR-690
func TestHR690_TheModelKeyIsPlacedByTheGatewayOnItsHostOnly(t *testing.T) {
	h, sim := anthropicModel(t, simmodel.Faults{})
	agentKey := "agent-own-" + "key-0123456789"
	r := h.call(t, "/v1/messages", messages, map[string]string{"x-api-key": agentKey, "X-Forward-Me": "1"})
	st := sim.Stats()
	if r.code != http.StatusOK || st.LastKey != testSecret || sim.Presented(agentKey) || strings.Contains(r.body, testSecret) {
		t.Fatalf("call = %d %s; the model got %q, the agent's key presented %v", r.code, r.body, st.LastKey, sim.Presented(agentKey))
	}
	if !strings.Contains(r.body, simmodel.Reply) || h.auth.snap().outcome() != pb.Outcome_OUTCOME_ACCEPTED {
		t.Fatalf("call = %s, outcome %v", r.body, h.auth.snap().outcome())
	}

	sim2, url := fakeModel(t, simmodel.Faults{})
	h = setup(t, withModel(t, "pc-anthropic", url, []string{"api.anthropic.com"}, "x-api-key", ""))
	r = h.call(t, "/v1/messages", messages, nil)
	if r.code != http.StatusBadGateway || !strings.Contains(r.body, "credential_unavailable") || sim2.Stats().Requests != 0 {
		t.Fatalf("a key sealed for another host: %d %s, model requests %d", r.code, r.body, sim2.Stats().Requests)
	}
}

// TestHR691_TheDecisionBindsTheBodyTheProviderGets: the fake model gets
// the re-encoded body with the connection's max tokens added, whose hash is
// the action's body_sha256 and BeginDispatch's body hash; a duplicate
// member, another query or another path is refused before any decision
// (G0 M29 D812, D813).
//
// Covers: F980, HR-691
func TestHR691_TheDecisionBindsTheBodyTheProviderGets(t *testing.T) {
	h, sim := anthropicModel(t, simmodel.Faults{})
	r := h.call(t, "/v1/messages?beta=true", `{ "model" : "sim-model", "messages" : [ ] }`, nil)
	if r.code != http.StatusOK {
		t.Fatalf("call = %d %s", r.code, r.body)
	}
	s := h.auth.snap()
	a, p := s.actions[0].Action, params(t, s.actions[0])
	sent := sim.Stats().LastBodySHA256
	if p["body_sha256"] != sent || hex.EncodeToString(s.begins[0].GetOutboundBodySha256()) != sent ||
		p["max_tokens"] != "77" || a.Target.Type != "model" || a.Target.ID != "sim-model" ||
		!strings.HasSuffix(s.begins[0].GetOutboundUrl(), "/v1/messages?beta=true") {
		t.Fatalf("action %+v, begin %v, the model got %s", a, s.begins[0], sent)
	}
	for name, tc := range map[string]struct {
		path, body string
		status     int
		code       string
	}{
		"duplicate member": {"/v1/messages", `{"model":"sim-model","max_tokens":5,"max_tokens":900000}`, 400, "invalid_json"},
		"another query":    {"/v1/messages?debug=1", messages, 400, "query_not_allowed"},
		"api-version":      {"/v1/messages?api-version=1", messages, 400, "query_not_allowed"},
		"another path":     {"/v1/messages/../files", messages, 404, "unknown_route"},
		"no base path":     {"/messages", messages, 404, "unknown_route"},
	} {
		r := h.call(t, tc.path, tc.body, nil)
		if r.code != tc.status || !strings.Contains(r.body, tc.code) {
			t.Errorf("%s = %d %s", name, r.code, r.body)
		}
	}
	if n := h.auth.snap().authorize; n != 1 || sim.Stats().Requests != 1 {
		t.Fatalf("refused calls were decided (%d) or sent (%d)", n-1, sim.Stats().Requests-1)
	}
}

// TestHR692_AModelAnswerStreamsAndACutOneIsNeverWhole: a streamed answer
// passes with its usage recorded; a cut stream breaks the agent's
// connection and is UNKNOWN; a body over 16 MiB is refused unsent
// (G0 M29 D814, D818).
//
// Covers: F981, HR-692
func TestHR692_AModelAnswerStreamsAndACutOneIsNeverWhole(t *testing.T) {
	h, sim := anthropicModel(t, simmodel.Faults{})
	r := h.call(t, "/v1/messages", `{"model":"sim-model","max_tokens":5,"stream":true,"messages":[]}`, nil)
	rec := h.auth.snap().records
	if r.code != http.StatusOK || r.err != nil || !strings.HasPrefix(r.hdr.Get("Content-Type"), "text/event-stream") ||
		!strings.Contains(r.body, "message_stop") || len(rec) != 1 || rec[0].GetOutcome() != pb.Outcome_OUTCOME_ACCEPTED ||
		!rec[0].GetModelUsage().GetReported() || rec[0].GetModelUsage().GetOutputTokens() == 0 {
		t.Fatalf("stream = %d %v %q, records %v", r.code, r.err, r.body, rec)
	}
	r = h.call(t, "/v1/messages", `{"model":"sim-cut","max_tokens":5,"stream":true,"messages":[]}`, nil)
	rec = h.auth.snap().records
	if r.err == nil || strings.Contains(r.body, "message_stop") || len(rec) != 2 || rec[1].GetOutcome() != pb.Outcome_OUTCOME_UNKNOWN ||
		rec[1].GetModelUsage().GetReported() {
		t.Fatalf("cut stream = %d %v %q, records %v", r.code, r.err, r.body, rec)
	}
	big := `{"model":"sim-model","max_tokens":5,"p":"` + strings.Repeat("a", 16<<20) + `"}`
	before := sim.Stats().Requests
	refusedAs(t, "17 MiB", h.call(t, "/v1/messages", big, nil), http.StatusRequestEntityTooLarge, "request_too_large", "body_too_large")
	if sim.Stats().Requests != before {
		t.Fatal("the model got the oversized body")
	}
}

// TestT312_AnAnswerPastTheCapIsAbortedAndUnknown: a provider answering
// more than 16 MiB, streamed or not, has the agent's connection broken and
// the call recorded UNKNOWN; nothing past the cap passes as a whole answer.
//
// Covers: HR-692
func TestT312_AnAnswerPastTheCapIsAbortedAndUnknown(t *testing.T) {
	for _, ct := range []string{"application/json", "text/event-stream"} {
		huge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", ct)
			chunk := bytes.Repeat([]byte("a"), 1<<20)
			for range 17 {
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
		}))
		t.Cleanup(huge.Close)
		h := setup(t, withModel(t, "pc-anthropic", huge.URL, []string{"127.0.0.1"}, "x-api-key", ""))
		r := h.call(t, "/v1/messages", messages, nil)
		if r.err == nil || len(r.body) > 16<<20 || h.auth.snap().outcome() != pb.Outcome_OUTCOME_UNKNOWN {
			t.Errorf("%s: %d bytes, err %v, outcome %v %.300s", ct, len(r.body), r.err, h.auth.snap().outcome(), r.body)
		}
	}
}

// TestHR694_TheWholePromptIsScannedForSecrets: a clean prompt has no
// findings; a key format anywhere in the body goes to the Authority as a
// finding (held for an approver); the connection's own held key in a
// prompt is refused unasked; a body past the scan limits is refused
// (G0 M29 D817).
//
// Covers: F980, HR-694
func TestHR694_TheWholePromptIsScannedForSecrets(t *testing.T) {
	h, sim := anthropicModel(t, simmodel.Faults{})
	if r := h.call(t, "/v1/messages", messages, nil); r.code != http.StatusOK || len(h.auth.findings) != 0 {
		t.Fatalf("clean prompt = %d, findings %v", r.code, h.auth.findings)
	}
	key := "sk-" + "ant-" + "api03-" + strings.Repeat("Zq9_", 10)
	body := `{"model":"sim-model","max_tokens":5,"messages":[{"role":"user","content":[{"type":"text","text":"use ` + key + `"}]}]}`
	if r := h.call(t, "/v1/messages", body, nil); r.code != http.StatusOK || len(h.auth.findings) != 1 ||
		h.auth.findings[0].GetKind() != "anthropic" || !strings.HasPrefix(h.auth.findings[0].GetLocation(), "body:/messages/0/content/0") {
		t.Fatalf("a key in the prompt = %d, findings %v", r.code, h.auth.findings)
	}
	decided, sent := h.auth.snap().authorize, sim.Stats().Requests
	held := `{"model":"sim-model","max_tokens":5,"messages":[{"role":"user","content":"` + testSecret + `"}]}`
	refusedAs(t, "the held key", h.call(t, "/v1/messages", held, nil), http.StatusForbidden, "permission_error", "secret_in_payload")
	many := `{"model":"sim-model","max_tokens":5,"x":[` + strings.Repeat(`"a",`, 1<<20) + `"a"]}`
	refusedAs(t, "unscannable", h.call(t, "/v1/messages", many, nil), http.StatusForbidden, "permission_error", "payload_not_scannable")
	if h.auth.snap().authorize != decided || sim.Stats().Requests != sent {
		t.Fatal("a refused prompt was decided or sent")
	}
}

// TestT314_ASecretHiddenInAPromptIsStillFound: a key inside a member name,
// in base64, or as the model id is found; an OpenAI key in a chat prompt
// too.
//
// Covers: HR-694
func TestT314_ASecretHiddenInAPromptIsStillFound(t *testing.T) {
	h, _ := anthropicModel(t, simmodel.Faults{})
	key := "sk-" + "ant-" + "api03-" + strings.Repeat("Zq9_", 10)
	for name, body := range map[string]string{
		"member name": `{"model":"sim-model","max_tokens":5,"metadata":{"` + key + `":1}}`,
		"base64":      `{"model":"sim-model","max_tokens":5,"messages":[{"role":"user","content":"` + base64.StdEncoding.EncodeToString([]byte(key)) + `"}]}`,
		"model id":    `{"model":"` + key + `","max_tokens":5}`,
	} {
		before := len(h.auth.snap().actions)
		r := h.call(t, "/v1/messages", body, nil)
		if len(h.auth.snap().actions) == before || len(h.auth.findings) == 0 {
			t.Errorf("%s: %d %s, findings %v", name, r.code, r.body, h.auth.findings)
		}
	}
	// A key used as a member name never reaches the location (D1214).
	h.call(t, "/v1/messages", `{"model":"sim-model","max_tokens":5,"metadata":{"`+key+`":1}}`, nil)
	if len(h.auth.findings) != 1 || h.auth.findings[0].GetLocation() != "body:/metadata/<redacted>" {
		t.Fatalf("member name: findings %v", h.auth.findings)
	}
	_, url := fakeModel(t, simmodel.Faults{})
	o := setup(t, withModel(t, "pc-openai", url, []string{"127.0.0.1"}, "Authorization", "Bearer"))
	okey := "sk-" + "proj-" + strings.Repeat("Ab3-", 10)
	r := o.call(t, "/v1/chat/completions", `{"model":"sim-model","messages":[{"role":"user","content":"`+okey+`"}]}`, nil)
	if r.code != http.StatusOK || len(o.auth.findings) != 1 || o.auth.findings[0].GetKind() != "openai" {
		t.Fatalf("an OpenAI key = %d %s, findings %v", r.code, r.body, o.auth.findings)
	}
}

// TestHR695_NoModelPromptOrReplyIsCapturedOrLogged: a capture profile on a
// model connection captures nothing, and the gateway's log has the call's
// metadata and token counts but neither the prompt nor the reply
// (G0 M29 D820).
//
// Covers: F980, HR-695
func TestHR695_NoModelPromptOrReplyIsCapturedOrLogged(t *testing.T) {
	var logged bytes.Buffer
	h, _ := anthropicModel(t, simmodel.Faults{}, func(h *harness) {
		h.log = slog.New(slog.NewJSONHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug}))
		h.conn.Captures = []*pb.GatewayCaptureProfile{{
			Id: ids.NewV7().String(), Request: true, Response: true, ByteCap: 65536, Operations: []string{"anthropic.messages.create"},
			ExpireTime: timestamppb.New(time.Now().Add(time.Hour)),
		}}
	})
	prompt := "the-prompt-" + ids.NewV7().String()
	r := h.call(t, "/v1/messages", `{"model":"sim-model","max_tokens":5,"messages":[{"role":"user","content":"`+prompt+`"}]}`, nil)
	rec := h.auth.snap().records
	if r.code != http.StatusOK || len(rec) != 1 || len(rec[0].GetCaptures()) != 0 {
		t.Fatalf("call = %d, records %v", r.code, rec)
	}
	log := logged.String()
	if !strings.Contains(log, "gateway.model_call") || !strings.Contains(log, `"output_tokens"`) ||
		strings.Contains(log, prompt) || strings.Contains(log, simmodel.Reply) {
		t.Fatalf("log: %s", log)
	}
}

// TestHR696_AProviderSideToolNeedsItsTypeAllowed: a request naming a
// provider-side tool is refused before any decision unless that type is
// allowed on the connection; allowed, it passes with server_tools in the
// action (G0 M29 D813, FQ-B).
//
// Covers: F980, HR-696
func TestHR696_AProviderSideToolNeedsItsTypeAllowed(t *testing.T) {
	body := `{"model":"sim-model","max_tokens":5,"tools":[{"type":"web_search_20250305","name":"web_search"}],"messages":[]}`
	h, sim := anthropicModel(t, simmodel.Faults{})
	refusedAs(t, "not allowed", h.call(t, "/v1/messages", body, nil), http.StatusForbidden, "permission_error", "MODEL_SERVER_TOOL_NOT_ALLOWED")
	h.circuitMu.Lock()
	refusals := strings.Join(h.refusals, ";")
	h.circuitMu.Unlock()
	if h.auth.snap().authorize != 0 || sim.Stats().Requests != 0 || !strings.Contains(refusals, "model_server_tool_not_allowed anthropic.messages.create") {
		t.Fatalf("refused tool: decided %d, sent %d, reported %q", h.auth.snap().authorize, sim.Stats().Requests, refusals)
	}
	h, _ = anthropicModel(t, simmodel.Faults{}, func(h *harness) { h.conn.Model.AllowedServerTools = []string{"web_search_20250305"} })
	if r := h.call(t, "/v1/messages", body, nil); r.code != http.StatusOK ||
		fmt.Sprint(params(t, h.auth.snap().actions[0])["server_tools"]) != "[web_search_20250305]" {
		t.Fatalf("allowed tool = %d %s, action %+v", r.code, r.body, h.auth.snap().actions)
	}
}

// TestT315_ARefusalOrAnErrorCarriesNoPromptText: the agent-safe refusal
// in the provider's shape, and the gateway's log of a refused or failed
// call, name codes and the transaction, never the prompt.
//
// Covers: HR-695
func TestT315_ARefusalOrAnErrorCarriesNoPromptText(t *testing.T) {
	var logged bytes.Buffer
	h, _ := anthropicModel(t, simmodel.Faults{}, func(h *harness) {
		h.log = slog.New(slog.NewJSONHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug}))
		h.auth.decision = pb.Decision_DECISION_DENY
	})
	prompt := "the-prompt-" + ids.NewV7().String()
	r := h.call(t, "/v1/messages", `{"model":"sim-model","max_tokens":5,"messages":[{"role":"user","content":"`+prompt+`"}]}`, nil)
	refusedAs(t, "deny", r, http.StatusForbidden, "permission_error", "GRANT_AMOUNT_EXCEEDED")
	if strings.Contains(r.body, prompt) || strings.Contains(logged.String(), prompt) {
		t.Fatalf("the prompt leaked: %s / %s", r.body, logged.String())
	}
	h, _ = anthropicModel(t, simmodel.Faults{}, func(h *harness) {
		h.log = slog.New(slog.NewJSONHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	r = h.call(t, "/v1/messages", `{"model":"sim-error","max_tokens":5,"messages":[{"role":"user","content":"`+prompt+`"}]}`, nil)
	if r.code != 529 || h.auth.snap().outcome() != pb.Outcome_OUTCOME_FAILED || strings.Contains(logged.String(), prompt) {
		t.Fatalf("provider error = %d %s, outcome %v", r.code, r.body, h.auth.snap().outcome())
	}
}

// TestT310_TheAgentsKeyNeverReachesTheProviderAndTheGatewaysNeverComesBack:
// a model echoing every header it got cannot hand the gateway's key back
// to the agent, and the agent's own key in Authorization or x-api-key, or
// in the query, is never forwarded.
//
// Covers: HR-690
func TestT310_TheAgentsKeyNeverReachesTheProviderAndTheGatewaysNeverComesBack(t *testing.T) {
	got := make(chan http.Header, 1)
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		got <- r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", r.Header.Get("x-api-key"))
		_, _ = io.WriteString(w, `{"type":"message","content":[{"type":"text","text":"`+r.Header.Get("x-api-key")+`"}],"usage":{"input_tokens":1,"output_tokens":1}}`)
	}))
	t.Cleanup(echo.Close)
	h := setup(t, withModel(t, "pc-anthropic", echo.URL, []string{"127.0.0.1"}, "x-api-key", ""))
	agentKey := "sk-" + "ant-" + "api03-" + strings.Repeat("Ag3_", 10)
	r := h.call(t, "/v1/messages", messages, map[string]string{"Authorization-Extra": agentKey, "Anthropic-Api-Key": agentKey})
	hdr := <-got
	if hdr.Get("x-api-key") != testSecret || hdr.Get("Authorization-Extra") != "" || hdr.Get("Anthropic-Api-Key") != "" {
		t.Fatalf("the model got %v", hdr)
	}
	if r.code != http.StatusOK || strings.Contains(r.body, testSecret) || strings.Contains(r.hdr.Get("X-Request-Id"), testSecret) {
		t.Fatalf("the key came back: %d %v %s", r.code, r.hdr, r.body)
	}
	if r := h.call(t, "/v1/messages?key="+agentKey, messages, nil); r.code != http.StatusBadRequest {
		t.Fatalf("a key in the query = %d %s", r.code, r.body)
	}
}

// params decodes an action's params.
func params(t *testing.T, p actionir.Parsed) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(p.Action.Params, &m); err != nil {
		t.Fatal(err)
	}
	return m
}
