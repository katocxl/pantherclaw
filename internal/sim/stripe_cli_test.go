// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStripeStopsOnCancel(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyFile, []byte("rk_test_0123456789abcdefABCDEF\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	var out, errb bytes.Buffer
	args := []string{
		"stripe", "--addr", "127.0.0.1:0", "--key-file", keyFile, "--settle-after", "1s", "--fail-after-pending",
		"--bank-changed-recently", "--livemode-key", "sk_live_simulatedLiveKey000000",
	}
	if code := Run(ctx, args, &out, &errb); code != 0 {
		t.Fatalf("stripe: %d %s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "sim.stripe_listening") {
		t.Fatalf("no listening log: %s", errb.String())
	}
	if code := Run(context.Background(), []string{"stripe", "--bogus"}, &out, &errb); code == 0 {
		t.Fatalf("bad flag: %d", code)
	}
	if code := Run(context.Background(), []string{"stripe", "--key-file", filepath.Join(t.TempDir(), "missing")}, &out, &errb); code != 1 {
		t.Fatalf("missing key file: %d", code)
	}
}
