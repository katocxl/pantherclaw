// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle/bundletest"
)

// noNetwork fails any request: pclaw verify must never make one.
type noNetwork struct{ calls atomic.Int32 }

func (n *noNetwork) RoundTrip(*http.Request) (*http.Response, error) {
	n.calls.Add(1)
	return nil, errors.New("network access during pclaw verify")
}

func writeFile(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestHR196_PclawVerifyIsOffline: pclaw verify checks a good bundle with no
// login and no network, reports every check and the limits, and exits
// non-zero when a check fails.
func TestHR196_PclawVerifyIsOffline(t *testing.T) {
	iss := bundletest.NewIssuer(t)
	iss.Append(3)
	saved := iss.Checkpoint()
	iss.Append(2)
	iss.Checkpoint()
	a := iss.Anchor(3)
	b := iss.Bundle()
	b.Anchor = a

	dir := t.TempDir()
	bundlePath := writeFile(t, dir, "bundle.json", bundletest.Encode(t, b))
	trustPath := writeFile(t, dir, "trust.json", iss.Trust())
	rootPath := writeFile(t, dir, "trusted_root.json", iss.SigstoreRoot())
	prevPath := writeFile(t, dir, "previous.checkpoint", saved)

	nn := &noNetwork{}
	verify := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		// No PANTHERCLAW_SERVER, no API key and no login: verify needs none.
		code := Run(context.Background(), append([]string{"verify"}, args...), &out, &errb, envOf(nil),
			Options{HTTPClient: &http.Client{Transport: nn}})
		return code, out.String(), errb.String()
	}

	code, out, errs := verify(bundlePath, "--trust", trustPath, "--sigstore-trusted-root", rootPath, "--previous", prevPath)
	if code != 0 || !strings.Contains(out, "Result: PASSED") || !strings.Contains(out, bundle.Limits) ||
		!strings.Contains(out, "anchor.timestamp") || strings.Contains(out, "FAILED ") {
		t.Fatalf("verify = %d\n%s\n%s", code, out, errs)
	}

	// Flags may come first; --json prints the report as JSON.
	code, out, _ = verify("--json", "--trust", trustPath, bundlePath)
	var r bundle.Report
	if err := json.Unmarshal([]byte(out), &r); code != 0 || err != nil || r.Format != bundle.ReportFormat || r.Result != bundle.Passed ||
		r.Count(bundle.NotAvailable) == 0 {
		t.Fatalf("verify --json = %d %v\n%s", code, err, out)
	}

	// A modified bundle fails with exit code 1.
	b.Entries[1].Kind = "authz.other"
	tampered := writeFile(t, dir, "tampered.json", bundletest.Encode(t, b))
	code, out, errs = verify(tampered, "--trust", trustPath)
	if code != 1 || !strings.Contains(out, "FAILED        entry.link [seq 2]") || !strings.Contains(errs, "verification failed") {
		t.Fatalf("tampered = %d\n%s\n%s", code, out, errs)
	}
	// A file that is not a bundle is a failed report, not a crash.
	notBundle := writeFile(t, dir, "x.json", []byte(`{"format":"other"}`))
	if code, out, _ = verify(notBundle, "--trust", trustPath, "--json"); code != 1 || !strings.Contains(out, `"bundle.format"`) {
		t.Fatalf("not a bundle = %d\n%s", code, out)
	}
	// Usage errors.
	for _, args := range [][]string{{bundlePath}, {"--trust", trustPath}, {bundlePath, bundlePath, "--trust", trustPath}} {
		if code, _, _ := verify(args...); code != 2 {
			t.Errorf("verify %v = %d, want 2", args, code)
		}
	}
	// Unreadable or invalid inputs.
	if code, _, _ := verify(filepath.Join(dir, "missing.json"), "--trust", trustPath); code != 1 {
		t.Errorf("missing bundle = %d", code)
	}
	if code, _, _ := verify(bundlePath, "--trust", bundlePath); code != 1 {
		t.Errorf("a bundle as trust file = %d", code)
	}

	// An evidence pack is recognized and verified offline too: its signed
	// manifest, its files and the bundle inside; a changed byte fails it.
	raw, packTrust := iss.Pack()
	packPath := writeFile(t, dir, "pack.zip", raw)
	packTrustPath := writeFile(t, dir, "pack-trust.json", packTrust)
	code, out, errs = verify(packPath, "--trust", packTrustPath)
	if code != 0 || !strings.Contains(out, "pack.signature") || !strings.Contains(out, "entry.link") || !strings.Contains(out, "does not certify compliance") {
		t.Fatalf("verify pack = %d\n%s\n%s", code, out, errs)
	}
	if code, _, _ = verify(packPath, "--trust", trustPath); code != 1 {
		t.Fatalf("a pack whose key is not pinned = %d", code)
	}
	if n := nn.calls.Load(); n != 0 {
		t.Fatalf("pclaw verify made %d network requests", n)
	}
}
