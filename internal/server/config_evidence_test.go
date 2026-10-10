// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/platform/config"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

func TestEvidenceLogOriginIsDerivedAndValidated(t *testing.T) {
	derived := map[string]string{
		"http://127.0.0.1:8080":            "127.0.0.1:8080",
		"https://pc.example.com":           "pc.example.com",
		"https://pc.example.com/evidence/": "pc.example.com/evidence",
	}
	for public, want := range derived {
		c := Config{Auth: AuthConfig{PublicURL: public}}
		if got := c.logOrigin(); got != want || len(c.validateEvidence()) != 0 {
			t.Errorf("public URL %s: log origin %q (%v), want %q", public, got, c.validateEvidence(), want)
		}
	}
	for origin, ok := range map[string]bool{
		"log.example.com/pantherclaw": true,
		"https://log.example.com":     false,
		"log example":                 false,
		"log+example.com":             false,
		strings.Repeat("a", 201):      false,
	} {
		c := Config{Auth: AuthConfig{PublicURL: "https://pc.example.com"}, Evidence: EvidenceConfig{LogOrigin: origin}}
		if errs := c.validateEvidence(); (len(errs) == 0) != ok {
			t.Errorf("log origin %q: %v", truncateForTest(origin), errs)
		}
	}
}

func truncateForTest(s string) string {
	if len(s) > 20 {
		return s[:20] + "…"
	}
	return s
}

// TestMLDSACosignIsEnterpriseOnly: co-signing is refused at start without
// an Enterprise licence (G0 M7 decision 6), and only then is the
// checkpoints_pq key asked for.
func TestMLDSACosignIsEnterpriseOnly(t *testing.T) {
	c := Config{Evidence: EvidenceConfig{MLDSACosign: true}}
	for _, e := range []domain.Edition{domain.Community, domain.Team, domain.Business} {
		if err := c.checkEvidenceEdition(domain.Entitlements{Edition: e}); !errors.Is(err, errMLDSAEdition) {
			t.Errorf("%s: %v, want the edition refusal", e, err)
		}
	}
	if err := c.checkEvidenceEdition(domain.Entitlements{Edition: domain.Enterprise}); err != nil {
		t.Fatal(err)
	}
	if got := c.evidenceKeyPurposes(); len(got) != 1 || got[0] != keys.PurposeCheckpointsPQ {
		t.Fatalf("key purposes with co-signing = %v", got)
	}
	off := Config{}
	if off.checkEvidenceEdition(domain.Entitlements{Edition: domain.Community}) != nil || off.evidenceKeyPurposes() != nil {
		t.Fatal("co-signing off must need nothing")
	}
}

func TestCheckpointIntervalIsOneToSixtyMinutes(t *testing.T) {
	base := Config{Auth: AuthConfig{PublicURL: "https://pc.example.com"}}
	if base.checkpointInterval() != 5*time.Minute {
		t.Fatalf("default interval %s, want 5m", base.checkpointInterval())
	}
	for d, ok := range map[time.Duration]bool{
		time.Minute: true, time.Hour: true, 30 * time.Second: false, 61 * time.Minute: false,
	} {
		c := base
		c.Evidence.CheckpointInterval = config.Duration(d)
		if errs := c.validateEvidence(); (len(errs) == 0) != ok {
			t.Errorf("interval %s: %v", d, errs)
		}
		if ok && c.checkpointInterval() != d {
			t.Errorf("interval %s read as %s", d, c.checkpointInterval())
		}
	}
}
