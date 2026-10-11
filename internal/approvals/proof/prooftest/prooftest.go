// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package prooftest builds approvals for tests of HR-038: software security
// keys that sign a binding as the approval page's ceremony would, the
// approver keys file that pins them, and a permit's approval claim.
package prooftest

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"testing"
	"time"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/approvals/proof"
	"github.com/katocxl/pantherclaw/internal/authn/webauthntest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// RPID is the relying party the approvers' keys are registered for.
const RPID = "approvals.example.test"

// Approver is a person with one security key.
type Approver struct {
	User string
	Key  *webauthntest.Authenticator
	alg  webauthntest.Alg
}

// NewApprover returns a person with a fresh key of alg for RPID.
func NewApprover(t testing.TB, alg webauthntest.Alg) *Approver {
	t.Helper()
	k, err := webauthntest.New("https://"+RPID, RPID, alg)
	if err != nil {
		t.Fatal(err)
	}
	return &Approver{User: ids.NewV7().String(), Key: k, alg: alg}
}

// With returns a copy of the approver whose key misbehaves as edit says
// (another relying party, no user verification, ...).
func (a *Approver) With(edit func(*webauthntest.Authenticator)) *Approver {
	k := *a.Key
	edit(&k)
	return &Approver{User: a.User, Key: &k, alg: a.alg}
}

// FileKey is the approver's key as the file pins it.
func (a *Approver) FileKey(t testing.TB) proof.FileKey {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(a.Key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return proof.NewFileKey(a.User, a.User+"@example.test", "key", a.Key.CredentialID(), int(a.alg), der)
}

// File returns an approver keys file for org pinning the approvers' keys.
func File(t testing.TB, org string, approvers ...*Approver) []byte {
	t.Helper()
	f := proof.File{Format: proof.FileFormat, Org: org, RPID: RPID, ExportedAt: time.Now().UTC().Truncate(time.Second)}
	for _, a := range approvers {
		f.Keys = append(f.Keys, a.FileKey(t))
	}
	b, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Binding returns an action binding over the requested and effective
// action hashes (hex) with requirements.
func Binding(t testing.TB, actionHash, effectiveHash string, reqs ...apdomain.Requirement) apdomain.Binding {
	t.Helper()
	if len(reqs) == 0 {
		reqs = []apdomain.Requirement{{Kind: apdomain.KindApproval, Role: "approver", Count: 1}}
	}
	b, err := apdomain.ActionParts{
		ActionHash: actionHash, EffectiveActionHash: effectiveHash, BasisDigest: hash(1), FactsDigest: hash(2),
		DefinitionDigest: hash(3), GrantID: ids.NewV7(), GrantRevision: 1, RunID: ids.NewV7(), Instance: ids.NewV7(),
		JKT: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", Requirements: reqs,
		ExpiresAt: time.Now().Add(time.Hour).Truncate(time.Second), DisplayHash: [32]byte{4},
	}.Binding()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func hash(n byte) string {
	b := make([]byte, 32)
	b[0] = n
	return base64.RawURLEncoding.EncodeToString(b)
}

// Assert has the approver sign challenge (a binding or a batch hash) for
// requirement req, as the approval page's ceremony does.
func (a *Approver) Assert(t testing.TB, challenge []byte, req int) proof.Assertion {
	t.Helper()
	opts, err := json.Marshal(map[string]any{"publicKey": map[string]any{
		"challenge": base64.RawURLEncoding.EncodeToString(challenge), "rpId": RPID,
		"allowCredentials": []map[string]any{{"id": base64.RawURLEncoding.EncodeToString(a.Key.CredentialID()), "type": "public-key"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := a.Key.Assert(opts)
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		Response struct {
			ClientDataJSON    string `json:"clientDataJSON"`
			AuthenticatorData string `json:"authenticatorData"`
			Signature         string `json:"signature"`
		} `json:"response"`
	}
	if err := json.Unmarshal(raw, &r, json.RejectUnknownMembers(false)); err != nil {
		t.Fatal(err)
	}
	return proof.Assertion{
		Requirement: req, CredentialID: proof.B64(a.Key.CredentialID()), AuthenticatorData: r.Response.AuthenticatorData,
		ClientDataJSON: r.Response.ClientDataJSON, Signature: r.Response.Signature,
	}
}

// Approval is a permit's approval claim over b with assertions.
func Approval(b apdomain.Binding, as ...proof.Assertion) *proof.Approval {
	return &proof.Approval{Binding: b.String(), Input: proof.B64(b.Input), Assertions: as}
}
