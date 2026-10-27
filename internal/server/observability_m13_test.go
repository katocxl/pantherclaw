// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/telemetry"
)

// TestHR382_AdminListenerOffByDefaultAndLoopbackOnly: admin.addr is empty
// by default, so no admin listener runs, and the configuration refuses
// every address that is not a loopback IP literal.
func TestHR382_AdminListenerOffByDefaultAndLoopbackOnly(t *testing.T) {
	c := uiWebConfig()
	if c.Admin.Addr != "" {
		t.Fatalf("admin.addr defaults to %q", c.Admin.Addr)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	g, ctx := errgroup.WithContext(context.Background())
	if err := serveAdmin(ctx, g, &c, &telemetry.Telemetry{}, pclog.Discard()); err != nil {
		t.Fatalf("off: %v", err)
	}
	for _, bad := range []string{"0.0.0.0:6060", ":6060", "[::]:6060", "10.1.2.3:6060", "localhost:6060"} {
		c := uiWebConfig()
		c.Admin.Addr = bad
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "admin.addr") {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
	c.Admin.Addr = "127.0.0.1:6060"
	if err := c.Validate(); err != nil {
		t.Fatalf("loopback refused: %v", err)
	}
}

// TestHR382_AdminListenerServesMetricsOnLoopback starts the admin listener
// as serve does and reads /metrics through it.
func TestHR382_AdminListenerServesMetricsOnLoopback(t *testing.T) {
	c := uiWebConfig()
	c.Admin.Addr = "127.0.0.1:0"
	tel, err := telemetry.Setup(telemetry.Config{ServiceName: "t", Metrics: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tel.Shutdown(context.Background()) })
	telemetry.SetMaintenanceHold(true)
	t.Cleanup(func() { telemetry.SetMaintenanceHold(false) })
	ln, err := telemetry.ListenAdmin(context.Background(), c.Admin.Addr)
	if err != nil {
		t.Fatal(err)
	}
	srv := telemetry.NewAdminServer(telemetry.AdminHandler(tel.Reader()))
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("http://" + ln.Addr().String() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), "pc_maintenance_hold 1") {
		t.Fatalf("/metrics:\n%s", body)
	}
}

func TestObservabilityConfig(t *testing.T) {
	c := uiWebConfig()
	if c.Telemetry.OTLP.Endpoint != "" || c.Telemetry.OTLP.SampleRatio != 0.1 {
		t.Fatalf("defaults = %+v", c.Telemetry.OTLP)
	}
	for name, mut := range map[string]func(*Config){
		"http to a remote host": func(c *Config) { c.Telemetry.OTLP.Endpoint = "http://collector:4318" },
		"ratio above one":       func(c *Config) { c.Telemetry.OTLP.SampleRatio = 1.5 },
		"headers without endpoint": func(c *Config) {
			c.Telemetry.OTLP.HeadersFile = "headers"
		},
		"no service name": func(c *Config) { c.Telemetry.OTLP.ServiceName = "" },
	} {
		c := uiWebConfig()
		mut(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c.Telemetry.OTLP.Endpoint = "https://otlp-gateway-prod-eu-west-2.grafana.net/otlp"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}
