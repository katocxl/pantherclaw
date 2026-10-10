// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundle

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/pack"
)

// PackLimits is the fixed statement a pack report ends with: the limits of
// a bundle, and the pack's own sentence (F526, F510).
const PackLimits = Limits + " " + pack.Statement

// IsPack reports whether b looks like a pack (a ZIP) rather than a bundle.
func IsPack(b []byte) bool { return bytes.HasPrefix(b, []byte("PK\x03\x04")) }

// maxItemFailures bounds the failed item checks listed one by one.
const maxItemFailures = 20

// VerifyPack checks an evidence pack offline against the pinned keys
// (HR-196): the manifest's signature by a pinned evidence_packs key valid
// when the pack was made, its origin, every file against its digest, that
// no file is unlisted, the optional ML-DSA-65 co-signature, the fixed
// statement, and every verify bundle inside (checkpoints, proofs, anchor).
// Gaps the manifest declares are listed as not available.
func VerifyPack(raw []byte, o Options) *Report {
	r := newReport()
	r.Limits = PackLimits
	if o.Trust == nil {
		r.add("pack.format", "", Failed, "a trust file is required")
		return r
	}
	files, err := pack.Read(raw)
	if err != nil {
		r.add("pack.format", "", Failed, "%v", err)
		return r
	}
	compact, ok := files[pack.ManifestPath]
	if !ok {
		r.add("pack.format", "", Failed, "the pack has no %s", pack.ManifestPath)
		return r
	}
	signed, err := pack.ParseJWS(string(compact))
	if err != nil {
		r.add("pack.signature", "", Failed, "%v", err)
		return r
	}
	m, err := pack.DecodeManifest(signed.Payload)
	if err != nil {
		r.add("pack.format", "", Failed, "%v", err)
		return r
	}
	subject := "pack " + m.Pack
	created, _ := time.Parse(time.RFC3339, m.Created)
	key := o.Trust.key(PurposeEvidencePacks, signed.Kid)
	switch {
	case key == nil:
		r.add("pack.signature", subject, Failed, "signed by %s, which is not an evidence_packs key in your trust file", truncate(signed.Kid))
	case !signed.Verify(key.ed):
		r.add("pack.signature", subject, Failed, "the manifest's signature does not verify: it was changed after signing")
	case !key.ValidAt(created):
		r.add("pack.signature", subject, Failed, "key %s was not valid when the pack was made (%s; state %s)", key.KID, m.Created, key.State)
	default:
		r.add("pack.signature", subject, Passed, "EdDSA signature by evidence_packs key %s, valid when made (%s)", key.KID, m.Created)
	}
	if want := o.Trust.LogOrigin + "/org/" + m.Org; m.Origin != want {
		r.add("pack.origin", subject, Failed, "the pack's origin %q is not %q, from your trust file", truncate(m.Origin), want)
	} else {
		r.add("pack.origin", subject, Passed, "evidence of org %s at %s", m.Org, o.Trust.LogOrigin)
	}
	verifyItems(r, m, files)
	verifyCosign(r, o.Trust, subject, signed.SigningInput, files)
	if m.Statement != pack.Statement {
		r.add("pack.statement", subject, Failed, "the manifest does not carry the fixed statement")
	} else {
		r.add("pack.statement", subject, Passed, "%s", pack.Statement)
	}
	for _, g := range m.Gaps {
		r.add("pack.gap", truncate(g.Subject), NotAvailable, "%s: %s", g.Reason, truncate(g.Detail))
	}
	for _, it := range m.Items {
		if it.Kind != pack.KindBundle {
			continue
		}
		data, ok := files[it.Path]
		if !ok {
			continue
		}
		b, err := Decode(data)
		if err != nil {
			r.add("pack.bundle", it.Path, Failed, "%v", err)
			continue
		}
		if b.Org != m.Org {
			r.add("pack.bundle", it.Path, Failed, "the bundle is of org %s, not the pack's", truncate(b.Org))
			continue
		}
		inner := Verify(b, o)
		for _, c := range inner.Checks {
			r.add(c.Name, strings.TrimSpace(it.Path+" "+c.Subject), c.Status, "%s", c.Detail)
		}
	}
	return r
}

func verifyItems(r *Report, m *pack.Manifest, files map[string][]byte) {
	listed := map[string]bool{pack.ManifestPath: true, pack.CosignPath: true}
	failures := 0
	fail := func(path, detail string) {
		failures++
		if failures <= maxItemFailures {
			r.add("pack.item", path, Failed, "%s", detail)
		}
	}
	for _, it := range m.Items {
		if listed[it.Path] {
			fail(it.Path, "listed twice")
			continue
		}
		listed[it.Path] = true
		data, ok := files[it.Path]
		if !ok {
			fail(it.Path, "listed in the manifest but missing from the pack")
			continue
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != it.SHA256 || int64(len(data)) != it.Size {
			fail(it.Path, "its SHA-256 or size differs from the manifest: the file was changed")
		}
	}
	var unlisted []string
	for p := range files {
		if !listed[p] {
			unlisted = append(unlisted, p)
		}
	}
	slices.Sort(unlisted)
	for _, p := range unlisted {
		fail(p, "in the pack but not in the manifest: a file was added")
	}
	switch {
	case failures > maxItemFailures:
		r.add("pack.item", "", Failed, "%d more item checks failed", failures-maxItemFailures)
	case failures == 0:
		r.add("pack.items", "", Passed, "all %d files match the manifest's digests, and no file is unlisted", len(m.Items))
	}
}

func verifyCosign(r *Report, t *Trust, subject string, input []byte, files map[string][]byte) {
	raw, ok := files[pack.CosignPath]
	if !ok {
		r.add("pack.cosignature", subject, NotAvailable, "the manifest has no ML-DSA-65 co-signature")
		return
	}
	var c pack.Cosign
	if err := json.Unmarshal(raw, &c, json.RejectUnknownMembers(true)); err != nil || c.Algorithm != AlgMLDSA65 {
		r.add("pack.cosignature", subject, Failed, "malformed co-signature")
		return
	}
	k := t.key(PurposeCheckpointsPQ, c.Kid)
	if k == nil {
		r.add("pack.cosignature", subject, NotAvailable, "co-signed by %s, which is not in your trust file", truncate(c.Kid))
		return
	}
	if k.State == StateRevoked {
		r.add("pack.cosignature", subject, Failed, "ML-DSA-65 key %s is revoked", k.KID)
		return
	}
	if len(c.Signature) != mldsa.MLDSA65SignatureSize || mldsa.Verify(k.mldsa, input, c.Signature, &mldsa.Options{Context: pack.CosignContext}) != nil {
		r.add("pack.cosignature", subject, Failed, "the ML-DSA-65 co-signature does not verify")
		return
	}
	r.add("pack.cosignature", subject, Passed, "ML-DSA-65 co-signature by %s", fmt.Sprint(k.KID))
}
