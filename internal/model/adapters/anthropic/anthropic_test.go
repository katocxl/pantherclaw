// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package anthropic

import (
	"context"
	"crypto/x509"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/model/ports"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

const (
	testSchema = `{"type":"object","additionalProperties":false,"properties":{"a":{"type":"string"}},"required":["a"]}`
	okAnswer   = `{"content":[{"type":"thinking","thinking":""},{"type":"text","text":"{\"a\":\"b\"}"}],` +
		`"stop_reason":"end_turn","usage":{"input_tokens":12,"output_tokens":7}}`
)

// fake returns an adapter pointed at an httptest provider, through the real
// egress client with loopback allowed; no test reaches the real provider.
func fake(t *testing.T, h http.HandlerFunc) *Adapter {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	return &Adapter{
		client: httpx.NewEgressClient(httpx.EgressConfig{
			Timeout: Timeout, RootCAs: roots,
			AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		}),
		endpoint: srv.URL,
	}
}

func draftRequest() ports.DraftRequest {
	return ports.DraftRequest{
		Key: pclog.NewSecret("sk-test-key"), Model: DefaultModel, Task: ports.TaskSearchQuery,
		Text: "denied actions in production", Schema: jsontext.Value(testSchema),
		Catalog: ports.Catalog{Entities: []string{"transactions"}},
	}
}

func answer(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

// Covers: F181
func TestT234_RequestCarriesOnlyTheDraftFieldsAndNoTools(t *testing.T) {
	var got map[string]any
	var header http.Header
	a := fake(t, func(w http.ResponseWriter, r *http.Request) {
		header = r.Header.Clone()
		if err := json.UnmarshalRead(r.Body, &got); err != nil {
			t.Error(err)
		}
		_, _ = io.WriteString(w, okAnswer)
	})
	out, err := a.Draft(context.Background(), draftRequest())
	if err != nil {
		t.Fatal(err)
	}
	if string(out.Output) != `{"a":"b"}` || out.InputTokens != 12 || out.OutputTokens != 7 {
		t.Fatalf("output: %+v", out)
	}
	if header.Get("x-api-key") != "sk-test-key" || header.Get("anthropic-version") != apiVersion {
		t.Fatalf("headers: %v", header)
	}
	want := map[string]bool{"model": true, "max_tokens": true, "system": true, "messages": true, "output_config": true}
	for k := range got {
		if !want[k] {
			t.Errorf("unexpected request field %q", k)
		}
	}
	if len(got) != len(want) {
		t.Errorf("request fields: %v", got)
	}
	format := got["output_config"].(map[string]any)["format"].(map[string]any)
	if format["type"] != "json_schema" {
		t.Errorf("format: %v", format)
	}
}

func TestRequestIsRefusedBeforeAnyCall(t *testing.T) {
	a := fake(t, func(http.ResponseWriter, *http.Request) { t.Error("the provider was called") })
	mutate := map[string]func(*ports.DraftRequest){
		"text too long": func(r *ports.DraftRequest) { r.Text = strings.Repeat("x", ports.MaxUserText+1) },
		"empty text":    func(r *ports.DraftRequest) { r.Text = "" },
		"no key":        func(r *ports.DraftRequest) { r.Key = pclog.Secret[string]{} },
		"bad model":     func(r *ports.DraftRequest) { r.Model = "a b" },
		"bad schema":    func(r *ports.DraftRequest) { r.Schema = jsontext.Value(`{`) },
		"unknown task":  func(r *ports.DraftRequest) { r.Task = "RUN" },
	}
	for name, m := range mutate {
		t.Run(name, func(t *testing.T) {
			r := draftRequest()
			m(&r)
			if _, err := a.Draft(context.Background(), r); !errors.Is(err, ports.ErrInvalidRequest) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

// Covers: F181
func TestHR543_AnswersOtherThanOneFinishedTextBlockAreRefused(t *testing.T) {
	cases := map[string]struct {
		body string
		want error
	}{
		"refusal":      {`{"content":[],"stop_reason":"refusal"}`, ports.ErrRefused},
		"truncated":    {`{"content":[{"type":"text","text":"{"}],"stop_reason":"max_tokens"}`, ports.ErrInvalidOutput},
		"tool call":    {`{"content":[{"type":"tool_use","name":"x"}],"stop_reason":"end_turn"}`, ports.ErrInvalidOutput},
		"tool stop":    {`{"content":[{"type":"text","text":"{}"}],"stop_reason":"tool_use"}`, ports.ErrInvalidOutput},
		"two texts":    {`{"content":[{"type":"text","text":"{}"},{"type":"text","text":"{}"}],"stop_reason":"end_turn"}`, ports.ErrInvalidOutput},
		"no text":      {`{"content":[],"stop_reason":"end_turn"}`, ports.ErrInvalidOutput},
		"not json":     {`hello`, ports.ErrInvalidOutput},
		"over the cap": {`{"pad":"` + strings.Repeat("x", MaxResponse) + `"}`, ports.ErrInvalidOutput},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := fake(t, answer(http.StatusOK, c.body)).Draft(context.Background(), draftRequest())
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

func TestProviderStatusesMapWithoutTheProvidersWords(t *testing.T) {
	cases := map[int]error{
		http.StatusUnauthorized:        ports.ErrKeyRejected,
		http.StatusForbidden:           ports.ErrKeyRejected,
		http.StatusTooManyRequests:     ports.ErrProviderBusy,
		http.StatusInternalServerError: ports.ErrProviderFailed,
		http.StatusFound:               ports.ErrProviderFailed,
	}
	for status, want := range cases {
		_, err := fake(t, answer(status, "the provider's secret words")).Draft(context.Background(), draftRequest())
		if !errors.Is(err, want) {
			t.Fatalf("%d: err = %v, want %v", status, err, want)
		}
		if strings.Contains(err.Error(), "secret words") {
			t.Fatalf("%d: the provider's text reached the error: %v", status, err)
		}
	}
}

func TestEndpointIsFixedAndUsesTheEgressClient(t *testing.T) {
	a := New()
	if a.endpoint != "https://api.anthropic.com/v1/messages" {
		t.Fatalf("endpoint = %q", a.endpoint)
	}
	if a.client.Timeout != Timeout {
		t.Fatalf("timeout = %v", a.client.Timeout)
	}
	// The real client refuses loopback at dial time (HR-071).
	a.endpoint = httptest.NewTLSServer(answer(http.StatusOK, okAnswer)).URL
	if _, err := a.Draft(context.Background(), draftRequest()); !errors.Is(err, ports.ErrProviderTimeout) {
		t.Fatalf("err = %v", err)
	}
}
