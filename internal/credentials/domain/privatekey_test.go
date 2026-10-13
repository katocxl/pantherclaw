// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
)

// TestHR204_APrivateKeyIsRecognizedInEveryCommonForm: a private key is
// found whether it is a PEM file, a base64-encoded PEM file, a PEM block's
// bare body (with or without line breaks), or DER, in PKCS #1, PKCS #8 and
// SEC 1; ordinary tokens are not (#257 review follow-up).
func TestHR204_APrivateKeyIsRecognizedInEveryCommonForm(t *testing.T) {
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(rk)
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := x509.MarshalECPrivateKey(ek)
	if err != nil {
		t.Fatal(err)
	}
	pkcs1 := x509.MarshalPKCS1PrivateKey(rk)
	file := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: pkcs1})
	body := strings.Join(strings.Split(string(file), "\n")[1:len(strings.Split(string(file), "\n"))-2], "\n")
	for name, b := range map[string][]byte{
		"a PEM file":              file,
		"a PEM file in base64":    []byte(base64.StdEncoding.EncodeToString(file)),
		"a PEM file in base64url": []byte(base64.RawURLEncoding.EncodeToString(file)),
		"a PEM body with breaks":  []byte(body),
		"a PEM body on one line":  []byte(strings.ReplaceAll(body, "\n", "")),
		"PKCS #1 DER":             pkcs1,
		"PKCS #8 DER":             pkcs8,
		"SEC 1 DER":               sec1,
		"PKCS #8 DER in base64":   []byte(base64.StdEncoding.EncodeToString(pkcs8)),
		"an OpenSSH key":          []byte("-----" + "BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjE=\n"),
	} {
		if !HoldsPrivateKey(b) {
			t.Errorf("%s was not recognized", name)
		}
	}
	for name, b := range map[string][]byte{
		"a classic token":     []byte("ghp_" + strings.Repeat("A", 36)),
		"a fine-grained PAT":  []byte("github_pat_" + strings.Repeat("a1B2", 20)),
		"an API key":          []byte("sk_test_" + strings.Repeat("x", 48)),
		"a long base64 value": []byte(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("not a key, just a long opaque secret ", 4)))),
	} {
		if HoldsPrivateKey(b) {
			t.Errorf("%s was taken for a private key", name)
		}
	}
}
