// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundletest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Snapshot is a coverage snapshot ledger body (G0 M9, HR-217).
type Snapshot struct {
	ID         string `json:"id"`
	Agent      string `json:"agent"`
	Connection string `json:"connection"`
	Operation  string `json:"operation"`
	State      string `json:"state"`
	ExpiresAt  string `json:"expires_at,omitzero"`
	ComputedAt string `json:"computed_at"`
}

// Claim is a decision receipt's coverage claim.
type Claim struct {
	State      string `json:"state"`
	Snapshot   string `json:"snapshot"`
	Digest     string `json:"digest"`
	Agent      string `json:"agent"`
	Connection string `json:"connection"`
	Operation  string `json:"operation"`
}

// AppendSnapshot chains a coverage.snapshot entry with body s and returns
// the "sha256:" digest of its body.
func (i *Issuer) AppendSnapshot(s Snapshot) string {
	body, err := domain.CanonicalBody(s)
	if err != nil {
		i.T.Fatal(err)
	}
	seq := int64(len(i.Entries)) + 1
	i.Entries = append(i.Entries, bundle.Entry{
		Seq: seq, ID: ids.NewV7().String(), Kind: bundle.SnapshotKind, Actor: domain.Actor{Type: "system", ID: "coverage-reassess"},
		TS: domain.Timestamp(IssuedAt.Add(time.Duration(seq) * time.Second)), Body: jsontext.Value(body),
	})
	i.rechain(seq)
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// AppendClaim chains a decision receipt of agent through connection that
// carries claim c, and its decision entry.
func (i *Issuer) AppendClaim(c Claim, agent, connection string) {
	seq := int64(len(i.Entries)) + 1
	txn := ids.NewV7().String()
	payload, _ := json.Marshal(map[string]any{
		"iss": "https://pantherclaw.test", "jti": txn + "/1", "iat": IssuedAt.Unix(),
		"pap": map[string]any{
			"v": 1, "kind": "decision", "org": i.Org.String(), "txn": txn, "decision": "ALLOW", "connection": connection,
			"identity": map[string]any{"agent": agent}, "coverage": c,
		},
	}, json.Deterministic(true))
	r, err := i.receipts.Sign("pap-decision+jwt", payload)
	if err != nil {
		i.T.Fatal(err)
	}
	sum := sha256.Sum256([]byte(r))
	body, err := domain.CanonicalBody(map[string]string{"txn": txn, "decision": "ALLOW", "receipt_sha256": hex.EncodeToString(sum[:])})
	if err != nil {
		i.T.Fatal(err)
	}
	i.Receipts = append(i.Receipts, r)
	i.Entries = append(i.Entries, bundle.Entry{
		Seq: seq, ID: ids.NewV7().String(), Kind: "authz.decision", Actor: domain.Actor{Type: "gateway", ID: "gw-1"},
		TS: domain.Timestamp(IssuedAt.Add(time.Duration(seq) * time.Second)), Body: jsontext.Value(body),
	})
	i.rechain(seq)
}
