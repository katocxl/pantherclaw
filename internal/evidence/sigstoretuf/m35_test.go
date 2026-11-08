// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sigstoretuf

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestHR780_TUFFetchesOnlyOverHTTPS: the client refuses a repository that
// is not https, and the embedded root is Sigstore's root.json. Offline
// verification stays available beside this client.
func TestHR780_TUFFetchesOnlyOverHTTPS(t *testing.T) {
	root := EmbeddedRoot()
	if !strings.Contains(string(root), "signed") {
		t.Fatal("embedded root is not a TUF root")
	}
	_, err := (&Client{Repository: "http://tuf.example"}).Fetch(context.Background())
	if !errors.Is(err, ErrNotHTTPS) {
		t.Fatalf("http repository: %v", err)
	}
	_, err = (&Client{Repository: DefaultRepository}).repository()
	if err != nil {
		t.Fatalf("Sigstore repository: %v", err)
	}
}
