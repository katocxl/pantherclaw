// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package siem

import (
	"errors"
	"testing"
	"time"
)

// TestT114_DestinationURLRules: an export destination is https, never
// PantherClaw itself, never a metadata service (by name or any address
// spelling, internal or not), and private or loopback only when marked
// internal (HR-259).
func TestT114_DestinationURLRules(t *testing.T) {
	const own = "pc.example.com"
	cases := []struct {
		url      string
		internal bool
		want     error
	}{
		{"https://siem.example.net/ingest", false, nil},
		{"https://siem.example.net:8443/ingest", false, nil},
		{"https://10.1.2.3/ingest", true, nil},
		{"https://127.0.0.1:9443/ingest", true, nil},
		{"https://[fd00::5]/ingest", true, nil},
		{"http://siem.example.net/ingest", false, ErrURL},
		{"https://user:pw@siem.example.net/", false, ErrURL},
		{"https://siem.example.net/#frag", false, ErrURL},
		{"https://siem.example.net:22/", false, ErrURL},
		{"https://pc.example.com/hook", false, ErrURL},
		{"https://10.1.2.3/ingest", false, ErrURL},
		{"https://127.0.0.1/ingest", false, ErrURL},
		{"https://2130706433/ingest", false, ErrURL}, // 127.0.0.1 as a decimal
		{"https://[::ffff:10.0.0.1]/", false, ErrURL},
		{"https://localhost/", true, ErrURL},
		{"https://169.254.169.254/latest/meta-data", false, ErrMetadata},
		{"https://169.254.169.254/latest/meta-data", true, ErrMetadata},
		{"https://0xa9fea9fe/", true, ErrMetadata},
		{"https://metadata.google.internal/", true, ErrMetadata},
		{"https://[fd00:ec2::254]/", true, ErrMetadata},
	}
	for _, c := range cases {
		err := CheckURL(c.url, own, c.internal, nil)
		if !errors.Is(err, c.want) && err != c.want {
			t.Errorf("CheckURL(%q, internal=%v) = %v, want %v", c.url, c.internal, err, c.want)
		}
	}
}

func TestValidClasses(t *testing.T) {
	for _, ok := range [][]string{{"decisions"}, {"alerts", "incidents", "audit", "containment", "coverage", "decisions"}} {
		if !validClasses(ok) {
			t.Errorf("validClasses(%v) = false", ok)
		}
	}
	for _, bad := range [][]string{nil, {}, {"payloads"}, {"alerts", "alerts"}, {""}} {
		if validClasses(bad) {
			t.Errorf("validClasses(%v) = true", bad)
		}
	}
}

func TestHealth(t *testing.T) {
	now := time.Now()
	cases := []struct {
		confirmed *time.Time
		failures  int
		want      string
	}{
		{nil, 0, HealthNotConfirmed},
		{&now, 0, HealthHealthy},
		{&now, 3, HealthDegraded},
		{nil, 10, HealthFailing},
	}
	for _, c := range cases {
		if got := healthOf(c.confirmed, c.failures); got != c.want {
			t.Errorf("healthOf(%v, %d) = %s, want %s", c.confirmed != nil, c.failures, got, c.want)
		}
	}
}
