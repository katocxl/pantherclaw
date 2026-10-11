// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundle_test

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/json/v2"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle/bundletest"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
)

// packKit signs test packs with an evidence_packs key the trust file pins,
// and co-signs them with the issuer's pinned ML-DSA-65 key.
type packKit struct {
	t      *testing.T
	iss    *bundletest.Issuer
	signer *jws.Signer
	trust  *bundle.Trust
}

func newPackKit(t *testing.T) *packKit {
	t.Helper()
	iss := bundletest.NewIssuer(t)
	iss.Append(3)
	iss.Checkpoint()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jws.NewSigner("evidence-packs-test-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	var tr bundle.Trust
	if err := json.Unmarshal(iss.Trust(), &tr); err != nil {
		t.Fatal(err)
	}
	tr.Keys = append(tr.Keys, bundle.TrustedKey{
		KID: signer.KeyID(), Purpose: bundle.PurposeEvidencePacks, Algorithm: bundle.AlgEdDSA, PublicKey: pub,
		NotBefore: bundletest.IssuedAt.Add(-time.Hour), State: bundle.StateActive,
	})
	raw, err := json.Marshal(tr)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := bundle.ParseTrust(raw)
	if err != nil {
		t.Fatal(err)
	}
	return &packKit{t: t, iss: iss, signer: signer, trust: trust}
}

const packTxn = "0192aaaa-bbbb-7ccc-8ddd-000000000001"

// build returns a pack of one transaction file and the issuer's bundle,
// its manifest changed by edit before signing; cosign adds the ML-DSA-65
// co-signature.
func (k *packKit) build(cosign bool, edit func(*pack.Manifest, []pack.File) []pack.File) []byte {
	k.t.Helper()
	b := k.iss.Bundle()
	files := []pack.File{
		{Path: "transactions/" + packTxn + ".json", Kind: pack.KindTransaction, Data: []byte(`{"id":"` + packTxn + `"}`)},
		{Path: "proofs/bundle-0001.json", Kind: pack.KindBundle, Data: bundletest.Encode(k.t, b)},
	}
	m := pack.Manifest{
		Format: pack.Format, Pack: "0192aaaa-bbbb-7ccc-8ddd-0000000000ff", Org: b.Org, Origin: b.Origin,
		Exporter: pack.Exporter{Type: "user", ID: "0192aaaa-bbbb-7ccc-8ddd-0000000000ee"},
		Created:  bundletest.IssuedAt.Format(time.RFC3339), Expires: bundletest.IssuedAt.Add(7 * 24 * time.Hour).Format(time.RFC3339),
		Scope: pack.Scope{Kind: pack.ScopeRun, Run: "0192aaaa-bbbb-7ccc-8ddd-0000000000dd"}, Include: pack.Include{Receipts: true},
		Filters: []string{"evidence.read"}, EffectStates: map[string]int{"UNKNOWN": 1},
		Transactions: []pack.TransactionState{{ID: packTxn, Decision: "ALLOW", Execution: "DISPATCHED", Effect: "UNKNOWN"}},
		Retention:    []pack.Retention{{Category: "receipts", Days: 365, Source: "default"}},
		Redactions:   []string{}, Gaps: []pack.Gap{{Subject: "anchor", Reason: pack.GapNotAnchored, Detail: "not anchored yet"}},
		Statement: pack.Statement,
	}
	if edit != nil {
		files = edit(&m, files)
	}
	for _, f := range files {
		m.Items = append(m.Items, pack.ItemOf(f))
	}
	payload, err := pack.Canonical(m)
	if err != nil {
		k.t.Fatal(err)
	}
	compact, err := k.signer.Sign(pack.JWSType, payload)
	if err != nil {
		k.t.Fatal(err)
	}
	var co []byte
	if cosign {
		signed, err := pack.ParseJWS(compact)
		if err != nil {
			k.t.Fatal(err)
		}
		sig, err := k.iss.PQKey().Sign(nil, signed.SigningInput, &mldsa.Options{Context: pack.CosignContext})
		if err != nil {
			k.t.Fatal(err)
		}
		if co, err = pack.Canonical(pack.Cosign{Algorithm: bundle.AlgMLDSA65, Kid: "checkpoints-pq-test-1", Signature: sig}); err != nil {
			k.t.Fatal(err)
		}
	}
	out, err := pack.Write(files, compact, co, bundletest.IssuedAt)
	if err != nil {
		k.t.Fatal(err)
	}
	return out
}

// statusOf is the worst status of a check: failed if any instance failed.
func statusOf(r *bundle.Report, name string) bundle.Status {
	var out bundle.Status
	for _, c := range r.Checks {
		switch {
		case c.Name != name:
		case c.Status == bundle.Failed:
			return bundle.Failed
		case out == "":
			out = c.Status
		}
	}
	return out
}

// repack returns the pack's ZIP with path replaced (data non-nil and
// present), added (data non-nil and absent) or removed (data nil).
func repack(t *testing.T, raw []byte, path string, data []byte) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	write := func(name string, b []byte) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	seen := false
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(rc)
		_ = rc.Close()
		if f.Name == path {
			seen = true
			if data == nil {
				continue
			}
			b = data
		}
		write(f.Name, b)
	}
	if !seen && data != nil {
		write(path, data)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestHR196_AGoodPackVerifiesOffline: a pack signed by a pinned
// evidence_packs key passes: signature, origin, every file's digest, the
// fixed statement, the co-signature and the bundle inside; its declared
// gaps are listed as not available, and the report ends with the pack's
// sentence.
func TestHR196_AGoodPackVerifiesOffline(t *testing.T) {
	k := newPackKit(t)
	raw := k.build(true, nil)
	if !bundle.IsPack(raw) || bundle.IsPack(bundletest.Encode(t, k.iss.Bundle())) {
		t.Fatal("packs and bundles are not told apart")
	}
	r := bundle.VerifyPack(raw, bundle.Options{Trust: k.trust})
	if r.Failed() {
		t.Fatalf("a good pack fails:\n%s", r.Text())
	}
	for _, name := range []string{"pack.signature", "pack.origin", "pack.items", "pack.statement", "pack.cosignature", "entry.link", "checkpoint.signature"} {
		if statusOf(r, name) != bundle.Passed {
			t.Errorf("%s did not pass:\n%s", name, r.Text())
		}
	}
	if statusOf(r, "pack.gap") != bundle.NotAvailable || !strings.HasSuffix(r.Limits, pack.Statement) {
		t.Fatalf("gaps and limits:\n%s", r.Text())
	}
	if r := bundle.VerifyPack(k.build(false, nil), bundle.Options{Trust: k.trust}); r.Failed() || statusOf(r, "pack.cosignature") != bundle.NotAvailable {
		t.Fatalf("a pack without a co-signature:\n%s", r.Text())
	}
}

// TestHR196_AChangedPackFailsItsManifest: a changed, added or removed file,
// a changed manifest or co-signature, a manifest without the fixed
// sentence or of another origin, and a key that is not pinned each fail.
func TestHR196_AChangedPackFailsItsManifest(t *testing.T) {
	k := newPackKit(t)
	good := k.build(true, nil)
	files, err := pack.Read(good)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(files[pack.ManifestPath]), ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	edited := base64.RawURLEncoding.EncodeToString(bytes.Replace(payload, []byte(`"UNKNOWN"`), []byte(`"CONFIRMED"`), 1))
	var co pack.Cosign
	if err := json.Unmarshal(files[pack.CosignPath], &co); err != nil {
		t.Fatal(err)
	}
	co.Signature[0] ^= 1
	badCosign, _ := pack.Canonical(co)

	cases := map[string]struct {
		raw   []byte
		check string
	}{
		"a changed file":        {repack(t, good, "transactions/"+packTxn+".json", []byte(`{"id":"x"}`)), "pack.item"},
		"an added file":         {repack(t, good, "transactions/extra.json", []byte(`{}`)), "pack.item"},
		"a removed file":        {repack(t, good, "transactions/"+packTxn+".json", nil), "pack.item"},
		"a changed manifest":    {repack(t, good, pack.ManifestPath, []byte(parts[0]+"."+edited+"."+parts[2])), "pack.signature"},
		"a changed cosignature": {repack(t, good, pack.CosignPath, badCosign), "pack.cosignature"},
		"no fixed sentence": {k.build(false, func(m *pack.Manifest, fs []pack.File) []pack.File {
			m.Statement = "This pack certifies compliance."
			return fs
		}), "pack.statement"},
		"another origin": {k.build(false, func(m *pack.Manifest, fs []pack.File) []pack.File {
			m.Origin = "elsewhere.test/org/" + m.Org
			return fs
		}), "pack.origin"},
		"a changed bundle inside": {k.build(false, func(_ *pack.Manifest, fs []pack.File) []pack.File {
			fs[1].Data = bytes.Replace(fs[1].Data, []byte(`"seq":2`), []byte(`"seq":9`), 1)
			return fs
		}), ""},
	}
	for name, c := range cases {
		r := bundle.VerifyPack(c.raw, bundle.Options{Trust: k.trust})
		if !r.Failed() || (c.check != "" && statusOf(r, c.check) != bundle.Failed) {
			t.Errorf("%s: %q is not failed:\n%s", name, c.check, r.Text())
		}
	}
	other := newPackKit(t)
	if r := bundle.VerifyPack(good, bundle.Options{Trust: other.trust}); statusOf(r, "pack.signature") != bundle.Failed {
		t.Fatalf("a pack signed by another deployment's key:\n%s", r.Text())
	}
	if r := bundle.VerifyPack([]byte("PK\x03\x04 not a zip"), bundle.Options{Trust: k.trust}); statusOf(r, "pack.format") != bundle.Failed {
		t.Fatalf("garbage:\n%s", r.Text())
	}
}
