// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/json/v2"
	"testing"

	"github.com/katocxl/pantherclaw/internal/idaccess/ports"
)

// TestHR701_TheDocumentDigestCoversTheDPoPBinding (G0 M30 D1211): a
// document that starts or stops asking for bound tokens has another digest,
// so the change is filed like any other changed document and confirmed
// before it applies; an unbound document keeps the digest of the fields
// before the binding was part of it, so clients already allowed do not
// show a change.
func TestHR701_TheDocumentDigestCoversTheDPoPBinding(t *testing.T) {
	md := ports.ClientMetadata{ClientID: "https://client.example.test/md.json", Name: "client", RedirectURIs: []string{"http://127.0.0.1/cb"}}
	bound := md
	bound.DPoPBound = true
	if bytes.Equal(DocumentDigest(md), DocumentDigest(bound)) {
		t.Fatal("the binding does not change the digest")
	}
	before, err := json.Marshal(struct {
		ClientID     string   `json:"client_id"`
		Name         string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
	}{md.ClientID, md.Name, md.RedirectURIs})
	if err != nil {
		t.Fatal(err)
	}
	if h := sha256.Sum256(before); !bytes.Equal(DocumentDigest(md), h[:]) {
		t.Fatal("an unbound document's digest changed")
	}
}
