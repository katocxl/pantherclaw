// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/config"
)

// TestDevExample_MailsToTheLocalMailpit (G0 M5 follow-up): the
// development example sends email to the compose stack's Mailpit relay on
// loopback, in plaintext (allowed only there), and that relay is pinned by
// digest and published on 127.0.0.1 only.
func TestDevExample_MailsToTheLocalMailpit(t *testing.T) {
	example := DefaultConfig()
	if err := config.Load(&example, filepath.Join("..", "..", "deploy", "dev", "server.example.json"), noEnv); err != nil {
		t.Fatal(err)
	}
	s := example.Notifications.SMTP
	if s.Host != "127.0.0.1" || s.Port != 1025 || s.TLS != "none" || s.Username != "" {
		t.Fatalf("notifications.smtp %+v, want the local Mailpit relay", s)
	}
	if m, err := example.mailer(); err != nil || m == nil {
		t.Fatalf("mailer: %v, %v", m, err)
	}

	compose, err := os.ReadFile(filepath.Join("..", "..", "deploy", "compose", "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	svc := regexp.MustCompile(`(?ms)^  mailpit:\n(.*?)\n\n`).FindSubmatch(append(compose, '\n', '\n'))
	if svc == nil {
		t.Fatal("compose.yaml has no mailpit service")
	}
	body := string(svc[1])
	for _, want := range []*regexp.Regexp{
		regexp.MustCompile(`image: axllent/mailpit:v[0-9.]+@sha256:[0-9a-f]{64}\n`),
		regexp.MustCompile(`profiles: \["mail"\]`),
		regexp.MustCompile(`"127\.0\.0\.1:1025:1025"`),
		regexp.MustCompile(`"127\.0\.0\.1:8025:8025"`),
	} {
		if !want.MatchString(body) {
			t.Errorf("mailpit service lacks %s:\n%s", want, body)
		}
	}
	if regexp.MustCompile(`- "(0\.0\.0\.0:)?[0-9]+:[0-9]+"`).MatchString(body) {
		t.Errorf("mailpit publishes a port beyond loopback:\n%s", body)
	}
}
