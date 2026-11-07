// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pack

import (
	"io/fs"
	"slices"
	"strings"
	"testing"

	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// TestHR750_TheCloakingDetectionAlertsOnly: pc.browser.cloaking is a
// community rule on audit.browser.cloaking_suspected only, attention ALERT
// (never an incident or a page), medium severity, mapped to AML.T0134, and
// labeled PARTIAL; no other built-in rule watches the compare.
func TestHR750_TheCloakingDetectionAlertsOnly(t *testing.T) {
	p, err := Load(env(t))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range p.Rules {
		r := c.Rule
		if r.ID != "pc.browser.cloaking" {
			if slices.Contains(r.On, "audit.browser.cloaking_suspected") {
				t.Errorf("%s also watches the compare", r.ID)
			}
			continue
		}
		found = true
		if r.Attention != reflexdomain.AttentionAlert || r.Severity != reflexdomain.SeverityMedium || r.Edition != "community" ||
			!slices.Equal(r.On, []string{"audit.browser.cloaking_suspected"}) || !slices.Equal(r.ATLAS, []string{"AML.T0134"}) ||
			!strings.Contains(r.Description, "PARTIAL") || !strings.Contains(r.Description, "alert only") {
			t.Fatalf("rule %+v", r)
		}
	}
	if !found {
		t.Fatal("pc.browser.cloaking is not in the pack")
	}
}

// TestHR750_NoPlaybookContainsOnTheCloakingAlert: nothing in the built-in
// pack directory names the rule but its own file, so no built-in response
// holds or contains on it.
func TestHR750_NoPlaybookContainsOnTheCloakingAlert(t *testing.T) {
	err := fs.WalkDir(builtin, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || path == "builtin/browser_cloaking.yaml" || strings.HasSuffix(path, "manifest.json") {
			return err
		}
		b, err := fs.ReadFile(builtin, path)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), "pc.browser.cloaking") {
			t.Errorf("%s names pc.browser.cloaking", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
