// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/config"
)

const (
	testOrg   = "01920000-0000-7000-8000-0000000000a1"
	testAgent = "01920000-0000-7000-8000-0000000000c1" // the instance id
	testEnv   = "01920000-0000-7000-8000-0000000000e1"
	testPin   = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

func TestConfigValidation(t *testing.T) {
	base := DefaultConfig()
	base.Control.CASHA256 = testPin
	if err := base.Validate(); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"public listen without TLS": func(c *Config) { c.Listen = "0.0.0.0:8090" },
		"half a TLS pair":           func(c *Config) { c.TLS.CertFile = "cert.pem" },
		"no cel cost limit":         func(c *Config) { c.CEL.MaxCost = 0 },
		"http api off loopback":     func(c *Config) { c.Control.APIURL = "http://10.0.0.5:8080" },
		"api path":                  func(c *Config) { c.Control.APIURL = "http://127.0.0.1:8080/api" },
		"plain gateway url":         func(c *Config) { c.Control.GatewayURL = "http://127.0.0.1:8443" },
		"bad pin":                   func(c *Config) { c.Control.CASHA256 = "sha256:abc" },
		"no identity dir":           func(c *Config) { c.Control.IdentityDir = "" },
		"no control timeout":        func(c *Config) { c.Control.Timeout = 0 },
		"bad prefix":                func(c *Config) { c.Egress.AllowedPrefixes = []string{"127.0.0.1"} },
		"no public url":             func(c *Config) { c.PublicURL = "" },
		"public url path":           func(c *Config) { c.PublicURL = "http://127.0.0.1:8090/gw" },
		"fact timeout over 5s":      func(c *Config) { c.GitHub.FactTimeout = config.Duration(6 * time.Second) },
		"negative fact timeout":     func(c *Config) { c.GitHub.FactTimeout = config.Duration(-time.Second) },
		"github api over http":      func(c *Config) { c.GitHub.APIURL = "http://api.github.com" },
		"github api with a query":   func(c *Config) { c.GitHub.APIURL = "https://api.github.com?x=1" },
		"github api not a url":      func(c *Config) { c.GitHub.APIURL = "ftp://api.github.com" },
	} {
		c := base
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	tlsListen := base
	tlsListen.Listen, tlsListen.TLS.CertFile, tlsListen.TLS.KeyFile = "0.0.0.0:8090", "cert.pem", "key.pem"
	if err := tlsListen.Validate(); err != nil {
		t.Fatalf("a TLS listener on a public address refused: %v", err)
	}
	for _, u := range []string{"https://ghe.example.com/api/v3", "http://127.0.0.1:9092"} {
		c := base
		c.GitHub.APIURL = u
		if err := c.Validate(); err != nil {
			t.Errorf("github.api_url %s refused: %v", u, err)
		}
	}
}

// TestConfigPlaintextPublishedLoopback: `pclaw up`'s gateway listens on all
// addresses inside its container in plain HTTP only with
// plaintext_published_loopback, only without TLS files, and only with a
// public_url on a loopback host (G0 M13 D39).
func TestConfigPlaintextPublishedLoopback(t *testing.T) {
	base := DefaultConfig()
	base.Control.CASHA256 = testPin
	base.Listen = "0.0.0.0:8090"
	if err := base.Validate(); err == nil {
		t.Fatal("a plain listener on all addresses accepted without the flag")
	}
	base.PlaintextPublishedLoopback = true
	for _, u := range []string{"http://localhost:8090", "http://127.0.0.1:8090", "http://[::1]:8090", "http://localhost"} {
		c := base
		c.PublicURL = u
		if err := c.Validate(); err != nil {
			t.Errorf("public_url %s refused: %v", u, err)
		}
	}
	for name, mutate := range map[string]func(*Config){
		"public url off loopback": func(c *Config) { c.PublicURL = "http://gateway.example.com:8090" },
		"public url on a LAN ip":  func(c *Config) { c.PublicURL = "http://192.168.1.5:8090" },
		"with tls files":          func(c *Config) { c.TLS.CertFile, c.TLS.KeyFile = "cert.pem", "key.pem" },
	} {
		c := base
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
