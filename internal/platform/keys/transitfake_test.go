// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package keys

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/keys/keystest"
)

func newTransitFake(t *testing.T) *keystest.Transit { return keystest.NewTransit(t) }

func writeSecret(t *testing.T, name, value string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// tokenConfig is a Transit config for the fake with token-file auth.
func tokenConfig(t *testing.T, f *keystest.Transit) OpenBaoConfig {
	return OpenBaoConfig{
		Address: f.Srv.URL, KeyName: "pc-kek",
		Auth: OpenBaoAuth{Kind: AuthToken, TokenFile: writeSecret(t, "token", f.Token)},
	}
}

func baoProvider(t *testing.T, f *keystest.Transit) *OpenBaoProvider {
	t.Helper()
	c, err := NewTransitClient(tokenConfig(t, f))
	if err != nil {
		t.Fatal(err)
	}
	return NewOpenBaoProvider(c)
}
