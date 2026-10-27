// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package oidcrp

import (
	"bytes"
	"crypto/fips140"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"net/http"
	"strings"
)

// MinFIPSRSABits is the smallest RSA key a FIPS build accepts from an
// identity provider (G0 M13 D35, HR-396): FIPS 186-5 allows RSA
// signatures with keys of 2048 bits or more only.
const MinFIPSRSABits = 2048

// fipsMode reports FIPS 140-3 mode; tests replace it.
var fipsMode = fips140.Enabled

// keysClient is the client for the provider's JWKS. In FIPS mode it drops
// every RSA key under MinFIPSRSABits from the key set, so an ID token or a
// subject token signed with one fails verification like one signed with an
// unknown key.
func keysClient(base *http.Client) *http.Client {
	if !fipsMode() {
		return base
	}
	c := *base
	next := c.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	c.Transport = rsaFloor{next: next}
	return &c
}

// rsaFloor removes small RSA keys from JWKS responses.
type rsaFloor struct{ next http.RoundTripper }

// maxJWKS bounds the key set read (it is re-encoded in memory).
const maxJWKS = 1 << 20

func (f rsaFloor) RoundTrip(r *http.Request) (*http.Response, error) {
	res, err := f.next.RoundTrip(r)
	if err != nil || res.StatusCode != http.StatusOK {
		return res, err
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxJWKS+1))
	_ = res.Body.Close()
	if err != nil {
		return nil, err
	}
	out := body
	if len(body) <= maxJWKS {
		out = dropSmallRSA(body)
	}
	res.Body = io.NopCloser(bytes.NewReader(out))
	res.ContentLength = int64(len(out))
	res.Header.Del("Content-Length")
	return res, nil
}

// dropSmallRSA returns the key set without its RSA keys under
// MinFIPSRSABits. A body that is not a key set is returned unchanged (the
// key set parser refuses it).
func dropSmallRSA(body []byte) []byte {
	var set struct {
		Keys []jsontext.Value `json:"keys"`
	}
	if json.Unmarshal(body, &set) != nil {
		return body
	}
	kept := make([]jsontext.Value, 0, len(set.Keys))
	for _, k := range set.Keys {
		var key struct {
			Kty string `json:"kty"`
			N   string `json:"n"`
		}
		if json.Unmarshal(k, &key) == nil && key.Kty == "RSA" && rsaBits(key.N) < MinFIPSRSABits {
			continue
		}
		kept = append(kept, k)
	}
	out, err := json.Marshal(map[string]any{"keys": kept})
	if err != nil {
		return body
	}
	return out
}

// rsaBits is the bit length of a base64url modulus (0 when malformed).
func rsaBits(n string) int {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(n, "="))
	if err != nil {
		return 0
	}
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	if len(b) == 0 {
		return 0
	}
	bits := (len(b) - 1) * 8
	for v := b[0]; v > 0; v >>= 1 {
		bits++
	}
	return bits
}
