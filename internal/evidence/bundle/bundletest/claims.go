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

// Scope is a coverage scope.
type Scope struct {
	Agent      string `json:"agent"`
	Connection string `json:"connection"`
	Operation  string `json:"operation"`
}

// Snapshot is a coverage.snapshot ledger body (G0 M9, HR-217).
type Snapshot struct {
	V            int      `json:"v"`
	Scope        Scope    `json:"scope"`
	State        string   `json:"state"`
	Snapshot     string   `json:"snapshot"`
	ComputedAt   string   `json:"computed_at"`
	ExpiresAt    string   `json:"expires_at,omitzero"`
	Exclusions   []string `json:"exclusions"`
	RoutesDigest string   `json:"routes_digest"`
	Closure      string   `json:"closure,omitzero"`
}

// Invalidation is a coverage.invalidation ledger body.
type Invalidation struct {
	V          int    `json:"v"`
	ID         string `json:"id"`
	Connection string `json:"connection"`
	Agent      string `json:"agent,omitzero"`
	Kind       string `json:"kind"`
	OccurredAt string `json:"occurred_at"`
}

// Claim is a decision receipt's coverage claim (PAP-1 §9.1).
type Claim struct {
	V             int      `json:"v"`
	State         string   `json:"state"`
	Snapshot      string   `json:"snapshot"`
	Scope         Scope    `json:"scope"`
	SnapshotState string   `json:"snapshot_state"`
	Lapsed        bool     `json:"lapsed"`
	Reason        string   `json:"reason,omitzero"`
	Exclusions    []string `json:"exclusions"`
	ExpiresAt     string   `json:"expires_at,omitzero"`
}

// AppendSnapshot chains a coverage.snapshot entry with body s.
func (i *Issuer) AppendSnapshot(s Snapshot) {
	i.appendCoverage(bundle.SnapshotKind, s)
}

// AppendInvalidation chains a coverage.invalidation entry with body x.
func (i *Issuer) AppendInvalidation(x Invalidation) {
	i.appendCoverage(bundle.InvalidationKind, x)
}

// AppendCoverageBody chains a coverage entry of kind with the ledger body
// the server wrote, as it is.
func (i *Issuer) AppendCoverageBody(kind string, body []byte) {
	i.appendCoverage(kind, jsontext.Value(body))
}

func (i *Issuer) appendCoverage(kind string, v any) {
	body, err := domain.CanonicalBody(v)
	if err != nil {
		i.T.Fatal(err)
	}
	seq := int64(len(i.Entries)) + 1
	i.Entries = append(i.Entries, bundle.Entry{
		Seq: seq, ID: ids.NewV7().String(), Kind: kind, Actor: domain.Actor{Type: "system", ID: "coverage-reassess"},
		TS: domain.Timestamp(IssuedAt.Add(time.Duration(seq) * time.Second)), Body: jsontext.Value(body),
	})
	i.rechain(seq)
}

// AppendClaim chains a decision receipt of agent through connection that
// carries claim c (a Claim, or any other coverage value), and its
// decision entry.
func (i *Issuer) AppendClaim(c any, agent, connection string) {
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
