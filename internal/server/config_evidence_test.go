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

// anchoringOn is a complete anchoring configuration.
func anchoringOn() AnchoringConfig {
	return AnchoringConfig{
		Enabled: true,
		Rekor:   RekorConfig{URL: "https://log2025-1.rekor.sigstore.dev", PublicKeyFile: "rekor.pub"},
		TSA:     TSAConfig{URL: "https://timestamp.sigstore.dev/api/v1/timestamp", CertChainFile: "tsa.pem"},
	}
}

// TestHR195_CommunityLicenceRefusesAnchoring: anchoring is Team edition
// (PN-007.3): refused at start on a Community licence, accepted on any paid
// edition, and needs nothing when it is off (the default).
func TestHR195_CommunityLicenceRefusesAnchoring(t *testing.T) {
	c := Config{Evidence: EvidenceConfig{Anchoring: anchoringOn()}}
	if err := c.checkEvidenceEdition(domain.CommunityEntitlements()); !errors.Is(err, errAnchoringEdition) {
		t.Fatalf("Community: %v, want the edition refusal", err)
	}
	for _, e := range []domain.Edition{domain.Team, domain.Business, domain.Enterprise} {
		if err := c.checkEvidenceEdition(domain.Entitlements{Edition: e}); err != nil {
			t.Errorf("%s: %v", e, err)
		}
	}
	if DefaultConfig().Evidence.Anchoring.Enabled {
		t.Fatal("anchoring is on by default")
	}
}

// TestAnchoringConfigIsValidated: when on, the log and the authority are
// https URLs with their key and chain files, the log origin defaults to the
// URL without its scheme, and the interval is 5 minutes to a day (an hour
// by default). Off, only the interval is checked.
func TestAnchoringConfigIsValidated(t *testing.T) {
	base := Config{Auth: AuthConfig{PublicURL: "https://pc.example.com"}}
	c := base
	c.Evidence.Anchoring = anchoringOn()
	if errs := c.validateEvidence(); len(errs) != 0 {
		t.Fatalf("a complete configuration: %v", errs)
	}
	if got := c.Evidence.Anchoring.rekorOrigin(); got != "log2025-1.rekor.sigstore.dev" {
		t.Fatalf("derived log origin %q", got)
	}
	if c.anchoringInterval() != time.Hour {
		t.Fatalf("default interval %s", c.anchoringInterval())
	}
	for name, change := range map[string]func(*AnchoringConfig){
		"http log":            func(a *AnchoringConfig) { a.Rekor.URL = "http://log.example" },
		"log with a query":    func(a *AnchoringConfig) { a.Rekor.URL = "https://log.example/?x=1" },
		"no log key":          func(a *AnchoringConfig) { a.Rekor.PublicKeyFile = "" },
		"origin with scheme":  func(a *AnchoringConfig) { a.Rekor.Origin = "https://log.example" },
		"no authority":        func(a *AnchoringConfig) { a.TSA.URL = "" },
		"authority with user": func(a *AnchoringConfig) { a.TSA.URL = "https://user@tsa.example/ts" },
		"no chain":            func(a *AnchoringConfig) { a.TSA.CertChainFile = "" },
		"interval too short":  func(a *AnchoringConfig) { a.Interval = config.Duration(time.Minute) },
		"interval too long":   func(a *AnchoringConfig) { a.Interval = config.Duration(25 * time.Hour) },
	} {
		c := base
		c.Evidence.Anchoring = anchoringOn()
		change(&c.Evidence.Anchoring)
		if errs := c.validateEvidence(); len(errs) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
	off := base
	off.Evidence.Anchoring.Interval = config.Duration(30 * time.Minute)
	if errs := off.validateEvidence(); len(errs) != 0 || off.anchoringInterval() != 30*time.Minute {
		t.Fatalf("anchoring off: %v", errs)
	}
}
