// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"unicode"
)

// HoldsPrivateKey reports whether a credential's bytes hold a private key
// in any form one is commonly kept in: a PEM block, a base64-encoded PEM
// file (an environment variable's usual form), the bare base64 body of a
// PEM block, or DER (PKCS #1, PKCS #8 or SEC 1). A static credential goes
// to the target in a header, so such bytes are never sealed as one nor
// placed on a request (HR-204): an App's key is sealed with --github-app.
func HoldsPrivateKey(b []byte) bool {
	if bytes.Contains(b, []byte("-----BEGIN")) || bytes.Contains(b, []byte("LS0tLS1CRUdJTi")) || bytes.Contains(b, []byte(opensshBase64)) ||
		derPrivateKey(b) || bytes.HasPrefix(b, []byte(opensshMagic)) {
		return true
	}
	compact := bytes.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, b)
	// The whole value, wrapped over lines, or any word of it: a key behind
	// a prefix ("Bearer <base64>") is found too (#353 review).
	candidates := [][]byte{compact}
	if words := bytes.Fields(b); len(words) > 1 {
		candidates = append(candidates, words...)
	}
	for _, c := range candidates {
		if len(c) < 64 {
			continue // shorter than any key's encoding
		}
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if d, err := enc.DecodeString(string(c)); err == nil && keyBytes(d) {
				return true
			}
		}
	}
	return false
}

// The magic an OpenSSH private key's body starts with, and its base64.
const (
	opensshMagic  = "openssh-key-v1\x00"
	opensshBase64 = "b3BlbnNzaC1rZXktdjE"
)

// keyBytes reports whether decoded bytes are a private key: PEM, DER, or
// an OpenSSH key body without its armour (#353 review).
func keyBytes(d []byte) bool {
	return bytes.Contains(d, []byte("-----BEGIN")) || derPrivateKey(d) || bytes.HasPrefix(d, []byte(opensshMagic))
}

// derPrivateKey reports whether b is a DER-encoded private key.
func derPrivateKey(b []byte) bool {
	if len(b) < 32 || b[0] != 0x30 { // a DER SEQUENCE
		return false
	}
	if _, err := x509.ParsePKCS1PrivateKey(b); err == nil {
		return true
	}
	if _, err := x509.ParsePKCS8PrivateKey(b); err == nil {
		return true
	}
	_, err := x509.ParseECPrivateKey(b)
	return err == nil
}
