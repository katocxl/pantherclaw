// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"errors"
	"testing"
)

func TestM5ConfigValidation(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"IP RP id":       func(c *Config) { c.WebAuthn.RPID = "127.0.0.1" },
		"bad CIDR":       func(c *Config) { c.Notifications.AllowedPrivateRanges = []string{"10.0.0.0"} },
		"no concurrency": func(c *Config) { c.Notifications.Concurrency = 0 },
		"plaintext remote SMTP": func(c *Config) {
			c.Notifications.SMTP = SMTPConfig{Host: "smtp.example.test", Port: 25, TLS: "none", From: "pc@example.test"}
		},
		"SMTP user, no password": func(c *Config) {
			c.Notifications.SMTP = SMTPConfig{Host: "smtp.example.test", Port: 587, TLS: "starttls", From: "pc@example.test", Username: "u"}
		},
		"SMTP without from": func(c *Config) {
			c.Notifications.SMTP = SMTPConfig{Host: "smtp.example.test", Port: 587, TLS: "starttls"}
		},
	} {
		c := DefaultConfig()
		mutate(&c)
		if errs := c.validateM5(); len(errs) == 0 {
			t.Errorf("%s accepted", name)
		}
	}
	c := DefaultConfig()
	if errs := c.validateM5(); len(errs) != 0 {
		t.Fatalf("defaults: %v", errors.Join(errs...))
	}
	if c.webAuthnRPID() != "" {
		t.Error("an IP public URL turned WebAuthn on")
	}
	c.Auth.PublicURL = "http://localhost:8080"
	if c.webAuthnRPID() != "localhost" {
		t.Errorf("RP id %q", c.webAuthnRPID())
	}
}
