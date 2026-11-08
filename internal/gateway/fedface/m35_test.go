// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package fedface

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func face() *Handler {
	h := New(nil, nil, nil, nil, "https://gw.example", nil)
	h.decide = func(context.Context, *call) answer {
		return answer{result: jsontext.Value(`{"ok":true}`), receipt: "receipt"}
	}
	return h
}

func post(t *testing.T, h http.Handler, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

const sendBody = `{"jsonrpc":"2.0","id":"1","method":"SendMessage","params":{}}`

// TestHR775_TheFederationFaceRefusesABrowserAndAnUnknownMethod: a known
// method is decided and carries a receipt; an Origin, an unknown method
// and a body over 1 MiB are refused.
func TestHR775_TheFederationFaceRefusesABrowserAndAnUnknownMethod(t *testing.T) {
	h := face()
	ok := post(t, h, "/fed/a2a/pay", sendBody, nil)
	if ok.Code != http.StatusOK || ok.Header().Get(HeaderReceipt) != "receipt" {
		t.Fatalf("SendMessage: %d %s", ok.Code, ok.Body.String())
	}
	origin := post(t, h, "/fed/a2a/pay", sendBody, map[string]string{"Origin": "https://evil.example"})
	if origin.Code != http.StatusForbidden || !strings.Contains(origin.Body.String(), CodeRefused) {
		t.Fatalf("origin: %d %s", origin.Code, origin.Body.String())
	}
	other := post(t, h, "/fed/a2a/pay", `{"jsonrpc":"2.0","id":"1","method":"tasks/get","params":{}}`, nil)
	if other.Code != http.StatusOK || !strings.Contains(other.Body.String(), CodeMethodNotDecided) {
		t.Fatalf("unknown method: %d %s", other.Code, other.Body.String())
	}
	huge := bytes.Repeat([]byte("a"), MaxBody+1)
	req := httptest.NewRequest(http.MethodPost, "/fed/a2a/pay", bytes.NewReader(huge))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		b, _ := io.ReadAll(rec.Body)
		t.Fatalf("oversize: %d %s", rec.Code, b)
	}
}
