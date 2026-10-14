// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package devicehttp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/devicehttp"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/oauthhttp"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
)

const publicOrigin = "https://pantherclaw.example"

// fakeDevice answers the confirmation page and the confirm POST.
type fakeDevice struct{ devicehttp.Device }

func (fakeDevice) Prompt(context.Context, string, string) (authnapp.DevicePrompt, error) {
	return authnapp.DevicePrompt{UserCode: "ABCD-EFGH", DeviceName: "laptop"}, nil
}

func (fakeDevice) Confirm(context.Context, string, string) (authnapp.Redirect, error) {
	return authnapp.Redirect{URL: "https://idp.example/auth", Binding: "b"}, nil
}

func newHandler(t *testing.T) http.Handler {
	t.Helper()
	limiter := httpx.NewLimiter(1000, time.Minute, clock.System{})
	h, err := devicehttp.New(fakeDevice{}, publicOrigin, limiter, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.Mount(mux, oauthhttp.New(nil, publicOrigin, limiter))
	// The API-wide default the pages must override.
	return httpx.SecurityHeaders(true, mux)
}

func send(t *testing.T, h http.Handler, method, target string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var body *strings.Reader
	if method == http.MethodPost {
		body = strings.NewReader(url.Values{"org": {"o"}, "user_code": {"ABCD-EFGH"}}.Encode())
	} else {
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, target, body)
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// Form pages (and the error page a refused POST returns) send "same-origin" so the browser's form POST carries our real
// origin (Fetch Standard: under "no-referrer" it carries "Origin: null").
func TestDevicePagesSendSameOriginReferrerPolicy(t *testing.T) {
	h := newHandler(t)
	for name, w := range map[string]*httptest.ResponseRecorder{
		"GET enter":      send(t, h, http.MethodGet, "/device", nil),
		"GET confirm":    send(t, h, http.MethodGet, "/device?org=o&user_code=ABCD-EFGH", nil),
		"POST forbidden": send(t, h, http.MethodPost, "/device", map[string]string{"Origin": "null"}),
	} {
		if got := w.Header().Get("Referrer-Policy"); got != "same-origin" {
			t.Errorf("%s: Referrer-Policy = %q, want same-origin", name, got)
		}
	}
}

func TestDeviceConfirmOriginChecks(t *testing.T) {
	h := newHandler(t)
	for _, tc := range []struct {
		name string
		hdr  map[string]string
		want int
	}{
		{"public origin", map[string]string{"Origin": publicOrigin}, http.StatusSeeOther},
		{"origin null", map[string]string{"Origin": "null"}, http.StatusForbidden},
		{"other origin", map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
		{"cross-site, no origin", map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"no headers", nil, http.StatusForbidden},
	} {
		if got := send(t, h, http.MethodPost, "/device", tc.hdr).Code; got != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, got, tc.want)
		}
	}
}
