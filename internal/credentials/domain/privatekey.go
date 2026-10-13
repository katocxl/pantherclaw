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
	if bytes.Contains(b, []byte("-----BEGIN")) || bytes.Contains(b, []byte("LS0tLS1CRUdJTi")) || derPrivateKey(b) {
		return true
	}
	compact := bytes.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, b)
	if len(compact) < 64 {
		return false // shorter than any key's encoding
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if d, err := enc.DecodeString(string(compact)); err == nil && (bytes.Contains(d, []byte("-----BEGIN")) || derPrivateKey(d)) {
			return true
		}
	}
	return false
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
