// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundle

import (
	"crypto/ed25519"
	"encoding/json/v2"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
)

// FuzzDataDocuments exercises the offline decoders' bounds and fail-closed
// handling. These deterministic keys are test-only, never deployment keys.
func FuzzDataDocuments(f *testing.F) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	trust := Trust{Format: TrustFormat, LogOrigin: "fuzz.test", Keys: []TrustedKey{
		{KID: "fuzz-receipts", Purpose: PurposeReceipts, Algorithm: AlgEdDSA, PublicKey: public, State: StateActive, NotBefore: now.Add(-time.Hour)},
		{KID: "fuzz-exports", Purpose: PurposeEvidencePacks, Algorithm: AlgEdDSA, PublicKey: public, State: StateActive, NotBefore: now.Add(-time.Hour)},
	}}
	encoded, err := json.Marshal(trust)
	if err != nil {
		f.Fatal(err)
	}
	pinned, err := ParseTrust(encoded)
	if err != nil {
		f.Fatal(err)
	}
	signer, err := jws.NewSigner("fuzz-receipts", private)
	if err != nil {
		f.Fatal(err)
	}
	record := deletionDocument{Format: "pantherclaw.deletion/v1", Org: dataOrg, Request: dataRequest, Reason: "requested", Verified: true, RequestTime: now, WindowEndTime: now, StartTime: now, CompleteTime: now, BackupExpireTime: now.Add(24 * time.Hour)}
	payload, err := json.Marshal(record)
	if err != nil {
		f.Fatal(err)
	}
	signed, err := signer.Sign("pap-deletion+jwt", payload)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(signed))
	f.Add([]byte("eyJhbGciOiJub25lIn0.e30."))
	f.Add([]byte("PK\x03\x04"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxDataDocumentBytes+1 {
			return
		}
		opts := Options{Trust: pinned}
		for _, report := range []*Report{VerifyDeletion(raw, opts), VerifyExport(raw, nil, opts)} {
			if report == nil || report.Format != ReportFormat {
				t.Fatal("missing verification report")
			}
		}
	})
}
