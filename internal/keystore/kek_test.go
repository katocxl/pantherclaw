// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package keystore

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// Covers: HR-486, T-210
func TestHR486_StoredKEKIDMustMatchTheEnvelope(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "kek")
	if err := keys.GenerateKEKFile(path); err != nil {
		t.Fatal(err)
	}
	fp, err := keys.NewFileProvider([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	r, err := keys.NewRouter(keys.PrefixFile, fp, nil)
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("aad")
	w, err := r.Wrap(ctx, []byte("key"), aad)
	if err != nil {
		t.Fatal(err)
	}
	// Both the prefixed id and a pre-M18 unprefixed id route the value.
	for _, id := range []string{r.CurrentKEK(), fp.CurrentKEK()} {
		if pt, err := unwrapStored(ctx, r, id, w, aad); err != nil || string(pt) != "key" {
			t.Fatalf("kek_id %q: %q, %v", id, pt, err)
		}
	}
	// A kek_id that disagrees with the envelope fails closed.
	for _, id := range []string{"bao:pc-kek", "file:kek-0000000000000000", ""} {
		if pt, err := unwrapStored(ctx, r, id, w, aad); !errors.Is(err, keys.ErrUnwrap) || pt != nil {
			t.Fatalf("kek_id %q: %q, %v; want ErrUnwrap", id, pt, err)
		}
	}
}

func TestAuditErrorNamesTheKey(t *testing.T) {
	cause := errors.New("ledger unavailable")
	var err error = &AuditError{Object: "dek audit/3", KEKID: "bao:pc-kek", Err: cause}
	var ae *AuditError
	if !errors.As(err, &ae) || !errors.Is(err, cause) || ae.Object != "dek audit/3" {
		t.Fatalf("AuditError = %v", err)
	}
	if msg := err.Error(); !strings.Contains(msg, "dek audit/3") || !strings.Contains(msg, "bao:pc-kek") || !strings.Contains(msg, "not audited") {
		t.Fatalf("message %q", msg)
	}
}
