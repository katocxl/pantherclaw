// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// The AgentCore interceptor Lambda (G0 M34 D995, D995a; HR-766, T-345).

const (
	testARN = "arn:aws:bedrock-agentcore:us-east-1:111122223333:gateway/payments-gw-1"
	testRun = "01920000-0000-7000-8000-0000000000a1"
	// secretArg is a tool argument that must never be logged.
	secretArg = "tool-argument-never-logged-7f3a"
)

func testEvent() []byte {
	rpc := `{"jsonrpc":"2.0","id":"call-9","method":"tools/call","params":{"name":"t___create_refund","arguments":{"note":"` + secretArg + `"}}}`
	return []byte(`{"interceptorInputVersion":"1.0","mcp":{"gatewayRequest":{"path":"/mcp","httpMethod":"POST","body":` + rpc + `}}}`)
}

// passAnswer is a face's pass output.
const passAnswer = `{"interceptorOutputVersion":"1.0","mcp":{"transformedGatewayRequest":{"body":{"jsonrpc":"2.0","id":"call-9"}}}}`

// fakeFace is the gateway's runtime face.
type fakeFace struct {
	mu     sync.Mutex
	status int
	body   string
	hang   time.Duration
	ended  bool
	reqs   []*http.Request
	bodies [][]byte
}

func (f *fakeFace) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.reqs, f.bodies = append(f.reqs, r), append(f.bodies, b)
	status, body, hang, ended := f.status, f.body, f.hang, f.ended
	f.mu.Unlock()
	if hang > 0 {
		select {
		case <-time.After(hang):
		case <-r.Context().Done():
			return
		}
	}
	if ended {
		w.Header().Set(headerRunEnded, "1")
	}
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

// testInterceptor is an interceptor with a token and a run in place, asking
// face; logs go to logs.
func testInterceptor(t *testing.T, face http.Handler, logs *bytes.Buffer) *interceptor {
	t.Helper()
	ts := httptest.NewServer(face)
	t.Cleanup(ts.Close)
	ic, err := newInterceptor(config{gateway: ts.URL, server: ts.URL}, slog.New(slog.NewJSONHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ic.token, ic.run = "header.payload.sig", testRun
	return ic
}

type denied struct {
	MCP struct {
		Response struct {
			StatusCode int `json:"statusCode"`
			Body       struct {
				ID     any `json:"id"`
				Result struct {
					IsError bool `json:"isError"`
					Content []struct {
						Text string `json:"text"`
					} `json:"content"`
				} `json:"result"`
			} `json:"body"`
		} `json:"transformedGatewayResponse"`
		Request any `json:"transformedGatewayRequest"`
	} `json:"mcp"`
}

// isDeny reports whether out is the fail-closed deny for id.
func isDeny(out []byte, id any) bool {
	var d denied
	if json.Unmarshal(out, &d) != nil || d.MCP.Request != nil {
		return false
	}
	r := d.MCP.Response
	return r.StatusCode == http.StatusOK && r.Body.ID == id && r.Body.Result.IsError && len(r.Body.Result.Content) == 1 &&
		r.Body.Result.Content[0].Text == cannotDecide
}

// TestHR766_TheInterceptorReturnsTheGatewaysAnswer: a readable interceptor
// output from the face is returned as is; the request is a PAP/1 POST of
// the event, unchanged, to the customer's own gateway (FQ34-1) with the
// gateway ARN and the run; a PC-Run-Ended answer drops the run so a new
// one starts. Tool arguments never reach the log.
func TestHR766_TheInterceptorReturnsTheGatewaysAnswer(t *testing.T) {
	var logs bytes.Buffer
	face := &fakeFace{status: 200, body: passAnswer}
	ic := testInterceptor(t, face, &logs)
	out := ic.answer(context.Background(), testARN, testEvent(), time.Now().Add(time.Minute))
	if string(out) != passAnswer || len(face.reqs) != 1 {
		t.Fatalf("answer = %s, requests %d", out, len(face.reqs))
	}
	r := face.reqs[0]
	if r.Method != http.MethodPost || r.URL.Path != facePath || r.Header.Get(headerGateway) != testARN || r.Header.Get(headerRunID) != testRun ||
		r.Header.Get("Authorization") != "PAP header.payload.sig" || r.Header.Get("PAP-Proof") == "" || !bytes.Equal(face.bodies[0], testEvent()) {
		t.Fatalf("face request %s %s %v", r.Method, r.URL.Path, r.Header)
	}

	face.ended = true
	_ = ic.answer(context.Background(), testARN, testEvent(), time.Time{})
	if ic.Run() != "" {
		t.Fatal("PC-Run-Ended left the run in place")
	}
	if strings.Contains(logs.String(), secretArg) {
		t.Fatalf("a tool argument reached the log: %s", logs.String())
	}
}

// TestHR766_TheInterceptorFailsClosed: no gateway ARN, no token, no run,
// the gateway unreachable, a non-200 or unreadable answer, an answer that
// is no interceptor output, the deadline passed, and an event over 1 MiB
// each answer with the deny, keeping the request's id; none logs the tool
// arguments.
func TestHR766_TheInterceptorFailsClosed(t *testing.T) {
	type tc struct {
		face  *fakeFace
		arn   string
		token string
		run   string
		event []byte
		dead  time.Time
		down  bool
		id    any
	}
	ok := func() *fakeFace { return &fakeFace{status: 200, body: passAnswer} }
	big := append(testEvent(), bytes.Repeat([]byte(" "), maxEvent)...)
	for name, c := range map[string]tc{
		"no gateway ARN":   {face: ok(), id: "call-9"},
		"no token":         {face: ok(), arn: testARN, token: "-", id: "call-9"},
		"no run":           {face: ok(), arn: testARN, run: "-", id: "call-9"},
		"gateway down":     {face: ok(), arn: testARN, down: true, id: "call-9"},
		"HTTP 401":         {face: &fakeFace{status: 401, body: `{"code":"invalid_token"}`}, arn: testARN, id: "call-9"},
		"HTTP 403 refusal": {face: &fakeFace{status: 403, body: `{"code":"origin_not_allowed"}`}, arn: testARN, id: "call-9"},
		"not JSON":         {face: &fakeFace{status: 200, body: `<html>`}, arn: testARN, id: "call-9"},
		"other version":    {face: &fakeFace{status: 200, body: `{"interceptorOutputVersion":"2.0","mcp":{"transformedGatewayRequest":{}}}`}, arn: testARN, id: "call-9"},
		"both answers": {
			face: &fakeFace{status: 200, body: `{"interceptorOutputVersion":"1.0","mcp":{"transformedGatewayRequest":{},"transformedGatewayResponse":{}}}`},
			arn:  testARN, id: "call-9",
		},
		"unknown member": {face: &fakeFace{status: 200, body: `{"interceptorOutputVersion":"1.0","mcp":{"somethingElse":{}}}`}, arn: testARN, id: "call-9"},
		"too large answer": {face: &fakeFace{status: 200, body: `{"interceptorOutputVersion":"1.0","mcp":{"transformedGatewayRequest":{"body":"` +
			strings.Repeat("a", maxAnswer) + `"}}}`}, arn: testARN, id: "call-9"},
		"deadline passed": {
			face: &fakeFace{status: 200, body: passAnswer, hang: 2 * time.Second}, arn: testARN,
			dead: time.Now().Add(deadlineMargin + 100*time.Millisecond), id: "call-9",
		},
		"event over 1 MiB": {face: ok(), arn: testARN, event: big, id: nil},
	} {
		var logs bytes.Buffer
		ic := testInterceptor(t, c.face, &logs)
		if c.token == "-" {
			ic.token = ""
		}
		if c.run == "-" {
			ic.run = ""
		}
		if c.down {
			ic.c.gateway = "http://127.0.0.1:1"
		}
		ev := c.event
		if ev == nil {
			ev = testEvent()
		}
		start := time.Now()
		out := ic.answer(context.Background(), c.arn, ev, c.dead)
		if !isDeny(out, c.id) {
			t.Errorf("%s: %s", name, out)
		}
		if name == "deadline passed" && time.Since(start) > time.Second {
			t.Errorf("%s: answered after %s", name, time.Since(start))
		}
		if strings.Contains(logs.String(), secretArg) {
			t.Errorf("%s: a tool argument reached the log", name)
		}
	}
}

// TestHR766_TheKeyIsInMemoryAndTheConfigIsChecked: each interceptor makes a
// fresh Ed25519 key in memory (no key path in its configuration); the
// gateway and server URLs must be https or loopback http, --local listens
// on loopback only, and the Lambda role's credentials and names must be
// set.
func TestHR766_TheKeyIsInMemoryAndTheConfigIsChecked(t *testing.T) {
	a, _ := newInterceptor(config{}, slog.New(slog.DiscardHandler))
	b, _ := newInterceptor(config{}, slog.New(slog.DiscardHandler))
	if len(a.key) == 0 || bytes.Equal(a.key, b.key) {
		t.Fatal("the interceptor did not make a fresh key")
	}
	set := func(t *testing.T, env map[string]string) {
		for k, v := range map[string]string{
			envServerURL: "https://pc.example", envGatewayURL: "https://gw.example:8443", envOrg: "01920000-0000-7000-8000-0000000000aa",
			envRuntimeAPI: "127.0.0.1:9001", envFunction: "pc-interceptor", envLogStream: "2026/11/05/[$LATEST]abc",
			"AWS_ACCESS_KEY_ID": "ASIATESTNOTREAL", "AWS_SECRET_ACCESS_KEY": "test-secret-not-real", "AWS_REGION": "us-east-1",
		} {
			if w, ok := env[k]; ok {
				v = w
			}
			t.Setenv(k, v)
		}
	}
	set(t, nil)
	c, err := loadConfig("")
	if err != nil || c.gateway != "https://gw.example:8443" || c.runName != "agentcore:pc-interceptor:2026/11/05/--LATEST-abc" {
		t.Fatalf("config = %+v, %v", c, err)
	}
	if _, err := loadConfig("127.0.0.1:9200"); err != nil {
		t.Fatalf("--local loopback: %v", err)
	}
	for name, tc := range map[string]struct {
		env   map[string]string
		local string
	}{
		"http gateway":       {env: map[string]string{envGatewayURL: "http://gw.example"}},
		"gateway with path":  {env: map[string]string{envGatewayURL: "https://gw.example/runtime"}},
		"no server":          {env: map[string]string{envServerURL: ""}},
		"bad org":            {env: map[string]string{envOrg: "acme"}},
		"no runtime API":     {env: map[string]string{envRuntimeAPI: ""}},
		"no AWS credentials": {env: map[string]string{"AWS_SECRET_ACCESS_KEY": ""}},
		"no function":        {env: map[string]string{envFunction: ""}},
		"public --local":     {local: "0.0.0.0:9200"},
	} {
		t.Run(name, func(t *testing.T) {
			set(t, tc.env)
			if _, err := loadConfig(tc.local); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// TestHR766_RunNamesKeepD992sCharacterSet: characters outside
// [A-Za-z0-9._:/-] become "-", and an over-long name loses the end of its
// function part, keeping the log stream whole (D995a).
func TestHR766_RunNamesKeepD992sCharacterSet(t *testing.T) {
	if got := runName("my fn", "2026/11/05/[$LATEST]abc"); got != "agentcore:my-fn:2026/11/05/--LATEST-abc" {
		t.Fatalf("runName = %q", got)
	}
	stream := "2026/11/05/[$LATEST]" + strings.Repeat("e", 100)
	got := runName(strings.Repeat("f", 120), stream)
	if len(got) != maxRunName || !strings.HasSuffix(got, ":2026/11/05/--LATEST-"+strings.Repeat("e", 100)) || !strings.HasPrefix(got, "agentcore:fff") {
		t.Fatalf("long runName = %q (%d)", got, len(got))
	}
	if got := runName("f", strings.Repeat("s", 300)); len(got) != maxRunName {
		t.Fatalf("over-long stream = %d", len(got))
	}
}

// TestT345_TheLambdaLoopAnswersEveryInvocation: the Runtime API loop reads
// the gateway ARN from the client context (custom, env or top level, JSON
// or base64) and posts an answer for every invocation, a deny while there
// is no token, never the error path (so AgentCore never forwards an
// undecided request).
func TestT345_TheLambdaLoopAnswersEveryInvocation(t *testing.T) {
	cc := `{"custom":{"GATEWAY_ARN":"` + testARN + `"}}`
	for _, raw := range []string{cc, base64.StdEncoding.EncodeToString([]byte(cc)), `{"env":{"GATEWAY_ARN":"` + testARN + `"}}`, `{"GATEWAY_ARN":"` + testARN + `"}`} {
		if got := clientContextGateway(raw); got != testARN {
			t.Errorf("client context %s = %q", raw, got)
		}
	}
	if got := clientContextGateway("not json"); got != "" {
		t.Errorf("unreadable client context = %q", got)
	}

	var mu sync.Mutex
	var posted []string
	var paths []string
	served := 0
	done := make(chan struct{})
	release := make(chan struct{})
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n := served
		mu.Unlock()
		if r.URL.Path == runtimeVersion+"/runtime/invocation/next" {
			switch n {
			case 1:
				<-release // the second invocation waits for the token
			case 2:
				<-r.Context().Done()
				return
			}
		}
		mu.Lock()
		defer mu.Unlock()
		paths = append(paths, r.URL.Path)
		switch {
		case r.URL.Path == runtimeVersion+"/runtime/invocation/next":
			served++
			w.Header().Set(headerRequestID, "req-"+string(rune('0'+served)))
			w.Header().Set(headerDeadline, "9999999999999")
			w.Header().Set(headerClientContext, cc)
			_, _ = w.Write(testEvent())
		case strings.HasSuffix(r.URL.Path, "/response"):
			b, _ := io.ReadAll(r.Body)
			posted = append(posted, string(b))
			if len(posted) == 2 {
				close(done)
			}
		default:
			t.Errorf("unexpected Runtime API call %s", r.URL.Path)
		}
	}))
	defer api.Close()
	face := &fakeFace{status: 200, body: passAnswer}
	ic := testInterceptor(t, face, &bytes.Buffer{})
	ic.token = "" // not enrolled yet: the first invocation is denied
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ic.serveLambda(ctx, strings.TrimPrefix(api.URL, "http://")) }()
	first := time.After(5 * time.Second)
	for {
		mu.Lock()
		n := len(posted)
		mu.Unlock()
		if n >= 1 {
			break
		}
		select {
		case <-first:
			t.Fatal("no answer posted")
		case <-time.After(10 * time.Millisecond):
		}
	}
	ic.mu.Lock()
	ic.token = "header.payload.sig"
	ic.mu.Unlock()
	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the second answer was not posted")
	}
	cancel()
	mu.Lock()
	defer mu.Unlock()
	if !isDeny([]byte(posted[0]), "call-9") || posted[1] != passAnswer {
		t.Fatalf("posted %q", posted)
	}
	for _, p := range paths {
		if strings.HasSuffix(p, "/error") {
			t.Fatalf("the loop used the error path: %v", paths)
		}
	}
	if err := ic.serveLambda(context.Background(), "127.0.0.1:1/x"); err == nil {
		t.Fatal("a Runtime API with a path was accepted")
	}
}
