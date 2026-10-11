// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package proof is the approval a permit carries and its verification at
// a customer-hosted gateway (G0 M6 slice 23, HR-038, T-030; founder
// decision 2026-10-10, "pinned file, fail closed").
//
// A permit whose decision rested on an approval carries, in pap.approval
// (PAP-1 §7.2), the binding, the canonical binding input it hashes, and the
// WebAuthn assertion of every approver who counted. The gateway checks
// them against the approver keys file its operator installed and reviewed
// (keys.go), never against anything the server says about keys, so an
// approval forged in the database, or signed with a key added there, is
// refused before BeginDispatch. The package has no I/O beyond reading that
// file; the Authority builds Approval and the gateway verifies it.
package proof

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
)

// Limits of what a permit carries.
const (
	// MaxInput bounds the binding input (the schema's bound).
	MaxInput = 16 << 10
	// MaxAssertions bounds the assertions: 16 requirements of at most 5
	// approvers each.
	MaxAssertions = apdomain.MaxRequirements * apdomain.MaxApprovers
	maxPart       = 4096
)

// Approval is pap.approval: the approval a permit rests on (PAP-1 §7.2).
// Byte strings are base64url without padding.
type Approval struct {
	// Binding is SHA-256 of Input, the WebAuthn challenge (PAP-1 §8).
	Binding string `json:"binding"`
	// Input is the canonical binding input (RFC 8785).
	Input string `json:"input"`
	// Assertions are the counted approvers' assertions.
	Assertions []Assertion `json:"assertions"`
}

// Assertion is one approver's WebAuthn assertion over the binding, or over
// the hash of a batch that contains it.
type Assertion struct {
	// Requirement is the index of the requirement in the binding input's
	// approver_requirements that the response counted toward.
	Requirement       int    `json:"requirement"`
	CredentialID      string `json:"credential_id"`
	AuthenticatorData string `json:"authenticator_data"`
	ClientDataJSON    string `json:"client_data_json"`
	Signature         string `json:"signature"`
	// Batch lists the bindings of a batch approval, sorted, when the
	// assertion signed the batch hash (PAP-1 §8).
	Batch []string `json:"batch,omitzero"`
}

// B64 encodes bytes as PAP-1 does: base64url without padding.
func B64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// Errors of Verify. Each wraps ErrUnverified; the detail is for logs.
var (
	// ErrUnverified: the approval does not verify, so the action must not
	// be dispatched.
	ErrUnverified = errors.New("approval unverified")
	// ErrNoKeys: no approver keys file is installed, or it does not load.
	ErrNoKeys = fmt.Errorf("%w: no pinned approver keys", ErrUnverified)
)

func unverified(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrUnverified}, a...)...)
}

// Want is what the approval must bind: the hex SHA-256 of the requested
// action, and of the action the permit binds (the effective one).
type Want struct {
	ActionHash    string
	EffectiveHash string
}

// boundInput is the part of the binding input the gateway checks; the
// rest is covered by the binding hash.
type boundInput struct {
	V                    int                         `json:"v"`
	ActionHash           string                      `json:"action_hash"`
	EffectiveActionHash  string                      `json:"effective_action_hash"`
	ApproverRequirements []apdomain.BoundRequirement `json:"approver_requirements"`
}

type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
}

// WebAuthn flags in the authenticator data.
const (
	flagUserPresent  = 0x01
	flagUserVerified = 0x04
	minAuthData      = 37
)

// Verify checks a permit's approval against the pinned keys (HR-038):
//
//   - SHA-256 of the input is the binding, and the input binds the
//     requested and the effective action the permit carries;
//   - each assertion is a webauthn.get over the binding (or over the hash
//     of a batch that contains it), for the pinned relying party, with
//     user presence and user verification, signed by a pinned key;
//   - no person and no key counts twice, and every requirement has as many
//     people as it asks for.
//
// Every assertion the permit carries must verify. Any failure wraps
// ErrUnverified.
func (k *Keys) Verify(a *Approval, w Want) error {
	if k == nil {
		return ErrNoKeys
	}
	if a == nil {
		return unverified("no approval")
	}
	binding, err := raw32(a.Binding)
	if err != nil {
		return unverified("binding: %v", err)
	}
	input, err := base64.RawURLEncoding.Strict().DecodeString(a.Input)
	if err != nil || len(input) < 2 || len(input) > MaxInput {
		return unverified("binding input")
	}
	if sum := sha256.Sum256(input); !bytes.Equal(sum[:], binding) {
		return unverified("the binding is not the hash of its input")
	}
	var in boundInput
	if err := json.Unmarshal(input, &in); err != nil || in.V != apdomain.BindingVersion {
		return unverified("binding input does not parse as version %d", apdomain.BindingVersion)
	}
	if !sameHash(in.ActionHash, w.ActionHash) || !sameHash(in.EffectiveActionHash, w.EffectiveHash) {
		return unverified("the binding names another action")
	}
	needed, err := needs(in.ApproverRequirements)
	if err != nil {
		return err
	}
	if len(a.Assertions) == 0 || len(a.Assertions) > MaxAssertions {
		return unverified("%d assertions", len(a.Assertions))
	}
	people, creds := map[string]bool{}, map[string]bool{}
	got := make([]int, len(needed))
	for i, as := range a.Assertions {
		key, err := k.check(as, binding)
		if err != nil {
			return fmt.Errorf("assertion %d: %w", i, err)
		}
		if as.Requirement < 0 || as.Requirement >= len(needed) {
			return unverified("assertion %d counts toward no requirement", i)
		}
		if people[key.User] || creds[key.credential] {
			return unverified("a person or a key counts twice")
		}
		people[key.User], creds[key.credential] = true, true
		got[as.Requirement]++
	}
	for i, n := range needed {
		if got[i] < n {
			return unverified("requirement %d has %d of %d approvers", i, got[i], n)
		}
	}
	return nil
}

// needs returns how many people each bound requirement asks for.
func needs(reqs []apdomain.BoundRequirement) ([]int, error) {
	if len(reqs) == 0 || len(reqs) > apdomain.MaxRequirements {
		return nil, unverified("%d requirements", len(reqs))
	}
	out := make([]int, len(reqs))
	for i, r := range reqs {
		switch {
		case r.Kind == apdomain.KindApproval && r.Count >= 1 && r.Count <= apdomain.MaxApprovers:
			out[i] = r.Count
		case r.Kind == apdomain.KindStepUp:
			out[i] = 1
		default:
			return nil, unverified("requirement %d: kind %q", i, r.Kind)
		}
	}
	return out, nil
}

// check verifies one assertion and returns the pinned key that signed it.
func (k *Keys) check(as Assertion, binding []byte) (*Key, error) {
	cred, err := part(as.CredentialID)
	if err != nil {
		return nil, unverified("credential id")
	}
	key, ok := k.byCredential[string(cred)]
	if !ok {
		return nil, unverified("the key that signed is not pinned")
	}
	authData, err1 := part(as.AuthenticatorData)
	cdj, err2 := part(as.ClientDataJSON)
	sig, err3 := part(as.Signature)
	if err1 != nil || err2 != nil || err3 != nil || len(authData) < minAuthData {
		return nil, unverified("malformed assertion")
	}
	var cd clientData
	if err := json.Unmarshal(cdj, &cd); err != nil {
		return nil, unverified("client data does not parse")
	}
	if cd.Type != "webauthn.get" {
		return nil, unverified("client data type %q", cd.Type)
	}
	challenge, err := base64.RawURLEncoding.DecodeString(cd.Challenge)
	if err != nil {
		return nil, unverified("challenge encoding")
	}
	want, err := expected(binding, as.Batch)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(challenge, want) {
		return nil, unverified("the assertion signed another challenge")
	}
	rp := sha256.Sum256([]byte(k.RPID))
	if !bytes.Equal(authData[:32], rp[:]) {
		return nil, unverified("the assertion is for another relying party")
	}
	if flags := authData[32]; flags&flagUserPresent == 0 || flags&flagUserVerified == 0 {
		return nil, unverified("no user presence and verification")
	}
	cdHash := sha256.Sum256(cdj)
	if !key.verify(append(bytes.Clone(authData), cdHash[:]...), sig) {
		return nil, unverified("the signature does not verify with the pinned key")
	}
	return key, nil
}

// expected is the challenge an assertion signed: the binding, or for a
// batch the hash of its sorted bindings, which must contain this one.
func expected(binding []byte, batch []string) ([]byte, error) {
	if len(batch) == 0 {
		return binding, nil
	}
	if len(batch) > apdomain.MaxBatch {
		return nil, unverified("a batch of %d", len(batch))
	}
	all := make([][32]byte, 0, len(batch))
	found := false
	for _, s := range batch {
		b, err := raw32(s)
		if err != nil {
			return nil, unverified("batch binding: %v", err)
		}
		found = found || bytes.Equal(b, binding)
		all = append(all, [32]byte(b))
	}
	if !found {
		return nil, unverified("the batch does not contain this approval")
	}
	h, err := apdomain.BatchChallenge(all)
	if err != nil {
		return nil, unverified("batch: %v", err)
	}
	return h.Hash[:], nil
}

// verify checks a WebAuthn signature over data with the key's algorithm.
func (k *Key) verify(data, sig []byte) bool {
	digest := sha256.Sum256(data)
	switch pub := k.pub.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(pub, digest[:], sig)
	case ed25519.PublicKey:
		return ed25519.Verify(pub, data, sig)
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig) == nil
	}
	return false
}

func part(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) == 0 || len(b) > maxPart {
		return nil, errors.New("bad part")
	}
	return b, nil
}

func raw32(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != sha256.Size {
		return nil, errors.New("not a base64url SHA-256")
	}
	return b, nil
}

// sameHash compares a binding's base64url hash with a hex one.
func sameHash(b64, hexHash string) bool {
	a, err1 := raw32(b64)
	b, err2 := hex.DecodeString(hexHash)
	return err1 == nil && err2 == nil && bytes.Equal(a, b)
}
