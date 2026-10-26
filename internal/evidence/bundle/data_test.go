// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundle

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"testing"
	"testing/fstest"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
)

const dataOrg = "0192aaaa-bbbb-7ccc-8ddd-000000000001"
const dataRequest = "0192aaaa-bbbb-7ccc-8ddd-000000000002"

func dataTestSigner(t *testing.T, purpose string) (*jws.Signer, Options) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jws.NewSigner("data-test", priv)
	if err != nil {
		t.Fatal(err)
	}
	trust := Trust{Format: TrustFormat, LogOrigin: "evidence.test", Keys: []TrustedKey{{KID: signer.KeyID(), Purpose: purpose, Algorithm: AlgEdDSA, PublicKey: pub, State: StateActive, NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}}}
	raw, err := json.Marshal(trust)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseTrust(raw)
	if err != nil {
		t.Fatal(err)
	}
	return signer, Options{Trust: parsed}
}

func signData(t *testing.T, signer *jws.Signer, typ string, value any) []byte {
	t.Helper()
	b, err := pack.Canonical(value)
	if err != nil {
		t.Fatal(err)
	}
	s, err := signer.Sign(typ, b)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(s)
}

func dataHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func exportFixture(t *testing.T, name string, content []byte) (exportDocument, fstest.MapFS) {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
	m := exportDocument{Format: "pantherclaw.export/v1", RegistryVersion: 1, Org: dataOrg, Request: dataRequest, CreatedAt: now, ExpiresAt: now.Add(7 * 24 * time.Hour), Projections: []dataProjection{{Table: "agents", Columns: []string{"id", "name"}}}, Excluded: []string{"credentials"}, Parts: []dataPart{{Number: 1, Size: int64(buf.Len()), SHA256: dataHash(buf.Bytes())}}, Files: []dataFile{{Path: name, Part: 1, Size: int64(len(content)), SHA256: dataHash(content)}}}
	return m, fstest.MapFS{"part-001.zip": &fstest.MapFile{Data: bytes.Clone(buf.Bytes())}}
}

func TestHR390_OfflineExportDetectsTamperingAndUnsafeArchive(t *testing.T) {
	signer, opts := dataTestSigner(t, PurposeEvidencePacks)
	m, parts := exportFixture(t, "tables/agents/000001.jsonl", []byte("{\"id\":\"a\",\"name\":\"test\"}\n"))
	raw := signData(t, signer, "pap-export+jwt", m)
	if r := VerifyExport(raw, parts, opts); r.Failed() {
		t.Fatal(r.Text())
	}
	parts["part-001.zip"].Data[35] ^= 1
	if r := VerifyExport(raw, parts, opts); !r.Failed() {
		t.Fatal("tampered part passed")
	}
	for _, name := range []string{"../escape", "/absolute", "tables/unknown/000001.jsonl"} {
		m, parts := exportFixture(t, name, []byte("{}\n"))
		if r := VerifyExport(signData(t, signer, "pap-export+jwt", m), parts, opts); !r.Failed() {
			t.Fatalf("unsafe/undeclared path passed: %s", name)
		}
	}
	m, parts = exportFixture(t, "tables/agents/000001.jsonl", []byte("{\"credential\":\"secret\"}\n"))
	if r := VerifyExport(signData(t, signer, "pap-export+jwt", m), parts, opts); !r.Failed() {
		t.Fatal("undeclared column passed")
	}
}

func TestHR390_OfflineExportRequiresRightPinnedPurposeAndEveryFile(t *testing.T) {
	signer, opts := dataTestSigner(t, PurposeEvidencePacks)
	m, parts := exportFixture(t, "tables/agents/000001.jsonl", []byte("{}\n"))
	delete(parts, "part-001.zip")
	if r := VerifyExport(signData(t, signer, "pap-export+jwt", m), parts, opts); !r.Failed() {
		t.Fatal("missing part passed")
	}
	m, parts = exportFixture(t, "tables/agents/000001.jsonl", []byte("{}\n"))
	if r := VerifyExport(signData(t, signer, "pap-deletion+jwt", m), parts, opts); !r.Failed() {
		t.Fatal("wrong type passed")
	}
	opts.Trust.Keys[0].Purpose = PurposeReceipts
	if r := VerifyExport(signData(t, signer, "pap-export+jwt", m), parts, opts); !r.Failed() {
		t.Fatal("wrong key purpose passed")
	}
}

func TestHR391_OfflineDeletionDistinguishesIntentFromCompletion(t *testing.T) {
	signer, opts := dataTestSigner(t, PurposeReceipts)
	now := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
	m := deletionDocument{Format: "pantherclaw.deletion/v1", Org: dataOrg, Request: dataRequest, Reason: "requested", Verified: true, RequestTime: now.Add(-8 * 24 * time.Hour), WindowEndTime: now.Add(-24 * time.Hour), StartTime: now.Add(-time.Minute), CompleteTime: now, BackupExpireTime: now.Add(60 * 24 * time.Hour)}
	if r := VerifyDeletion(signData(t, signer, "pap-deletion+jwt", m), opts); r.Failed() {
		t.Fatal(r.Text())
	}
	if r := VerifyDeletion(signData(t, signer, "pap-deletion-intent+jwt", m), opts); !r.Failed() {
		t.Fatal("intent accepted as completion")
	}
	m.Verified = false
	if r := VerifyDeletion(signData(t, signer, "pap-deletion+jwt", m), opts); !r.Failed() {
		t.Fatal("incomplete record passed")
	}
	m.Verified = true
	opts.Trust.Keys[0].State = StateRevoked
	if r := VerifyDeletion(signData(t, signer, "pap-deletion+jwt", m), opts); !r.Failed() {
		t.Fatal("revoked signer passed")
	}
}
