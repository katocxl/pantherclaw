// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
)

// TestControlClientProxyIsOptIn (G0 M2 follow-up): pclaw's client uses a
// proxy only when PANTHERCLAW_HTTPS_PROXY names one; HTTPS_PROXY alone
// changes nothing (HR-072), and a bad value stops pclaw before any request.
func TestControlClientProxyIsOptIn(t *testing.T) {
	off, err := controlClient(envOf(map[string]string{"HTTPS_PROXY": "http://proxy.corp:3128", "HTTP_PROXY": "http://proxy.corp:3128"}))
	if err != nil {
		t.Fatal(err)
	}
	if off.Transport.(*http.Transport).Proxy != nil {
		t.Error("HTTPS_PROXY set a proxy without the opt-in")
	}
	on, err := controlClient(envOf(map[string]string{envHTTPSProxy: "http://proxy.corp:3128"}))
	if err != nil {
		t.Fatal(err)
	}
	proxy := on.Transport.(*http.Transport).Proxy
	if proxy == nil {
		t.Fatal("the opt-in set no proxy")
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://pc.example.com/rpc", nil)
	if u, err := proxy(req); err != nil || u == nil || u.Host != "proxy.corp:3128" {
		t.Errorf("proxy for the server: %v %v", u, err)
	}
	if _, err := controlClient(envOf(map[string]string{envHTTPSProxy: "socks5://proxy:1080"})); err == nil || !strings.Contains(err.Error(), envHTTPSProxy) {
		t.Errorf("a bad proxy: %v", err)
	}
	var out, errs bytes.Buffer
	if code := Run(context.Background(), []string{"whoami"}, &out, &errs, envOf(map[string]string{envHTTPSProxy: "proxy.corp"}), Options{}); code != 2 ||
		!strings.Contains(errs.String(), envHTTPSProxy) {
		t.Errorf("Run with a bad proxy: %d %q", code, errs.String())
	}
}
