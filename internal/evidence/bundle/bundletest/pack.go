// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundletest

import (
	"crypto/ed25519"
	"encoding/json/v2"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
)

// Pack returns an evidence pack of the issuer's org (one transaction file
// and the issuer's current bundle) signed by a fresh evidence_packs key, and
// the trust file pinning that key with the issuer's others.
func (i *Issuer) Pack() (raw, trust []byte) {
	i.T.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		i.T.Fatal(err)
	}
	signer, err := jws.NewSigner("evidence-packs-test-1", priv)
	if err != nil {
		i.T.Fatal(err)
	}
	b := i.Bundle()
	files := []pack.File{
		{Path: "transactions/0192aaaa-bbbb-7ccc-8ddd-000000000001.json", Kind: pack.KindTransaction, Data: []byte(`{}`)},
		{Path: "proofs/bundle-0001.json", Kind: pack.KindBundle, Data: Encode(i.T, b)},
	}
	m := pack.Manifest{
		Format: pack.Format, Pack: "0192aaaa-bbbb-7ccc-8ddd-0000000000ff", Org: b.Org, Origin: b.Origin,
		Exporter: pack.Exporter{Type: "user", ID: "0192aaaa-bbbb-7ccc-8ddd-0000000000ee"},
		Created:  IssuedAt.Format(time.RFC3339), Expires: IssuedAt.Add(7 * 24 * time.Hour).Format(time.RFC3339),
		Scope:   pack.Scope{Kind: pack.ScopeTransactions, Transactions: []string{"0192aaaa-bbbb-7ccc-8ddd-000000000001"}},
		Include: pack.Include{Receipts: true}, Filters: []string{}, EffectStates: map[string]int{"NONE_RECORDED": 1},
		Transactions: []pack.TransactionState{{ID: "0192aaaa-bbbb-7ccc-8ddd-000000000001", Decision: "ALLOW", Execution: "AUTHORIZED"}},
		Retention:    []pack.Retention{}, Redactions: []string{}, Gaps: []pack.Gap{}, Statement: pack.Statement,
	}
	for _, f := range files {
		m.Items = append(m.Items, pack.ItemOf(f))
	}
	payload, err := pack.Canonical(m)
	if err != nil {
		i.T.Fatal(err)
	}
	compact, err := signer.Sign(pack.JWSType, payload)
	if err != nil {
		i.T.Fatal(err)
	}
	if raw, err = pack.Write(files, compact, nil, IssuedAt); err != nil {
		i.T.Fatal(err)
	}
	var tr bundle.Trust
	if err := json.Unmarshal(i.Trust(), &tr); err != nil {
		i.T.Fatal(err)
	}
	tr.Keys = append(tr.Keys, bundle.TrustedKey{
		KID: signer.KeyID(), Purpose: bundle.PurposeEvidencePacks, Algorithm: bundle.AlgEdDSA, PublicKey: pub,
		NotBefore: IssuedAt.Add(-time.Hour), State: bundle.StateActive,
	})
	if trust, err = json.Marshal(tr); err != nil {
		i.T.Fatal(err)
	}
	return raw, trust
}
