// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package broker_test

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

func stateKey(t *testing.T) *broker.Key {
	t.Helper()
	dir := t.TempDir()
	kek := filepath.Join(dir, "kek")
	if err := keys.GenerateKEKFile(kek); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "broker.json")
	if _, err := broker.Generate(t.Context(), path, []string{kek}); err != nil {
		t.Fatal(err)
	}
	k, err := broker.Load(t.Context(), path, []string{kek})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestHR411_ATaskBodyOpensOnlyAsItsOwnEntryWithTheGatewaysKey: a task body
// sealed to the broker key opens with that key for the same org, gateway,
// kind and entry key, and for nothing else; the sealed bytes do not carry
// the plaintext (G0 M15 D13).
func TestHR411_ATaskBodyOpensOnlyAsItsOwnEntryWithTheGatewaysKey(t *testing.T) {
	k, other := stateKey(t), stateKey(t)
	entry := bytes.Repeat([]byte{7}, 32)
	aad := broker.StateAAD("org-1", "gw-1", "TASK", entry)
	plain := []byte(`{"action":"secret-action","result":null}`)
	sealed, err := k.SealState(aad, plain)
	if err != nil || bytes.Contains(sealed, []byte("secret-action")) {
		t.Fatalf("seal: %v", err)
	}
	if got, err := k.OpenState(aad, sealed); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("open: %q %v", got, err)
	}
	for name, a := range map[string][]byte{
		"org":     broker.StateAAD("org-2", "gw-1", "TASK", entry),
		"gateway": broker.StateAAD("org-1", "gw-2", "TASK", entry),
		"kind":    broker.StateAAD("org-1", "gw-1", "HOLD", entry),
		"key":     broker.StateAAD("org-1", "gw-1", "TASK", bytes.Repeat([]byte{8}, 32)),
	} {
		if _, err := k.OpenState(a, sealed); !errors.Is(err, broker.ErrStateOpen) {
			t.Errorf("another %s opened the body: %v", name, err)
		}
	}
	if _, err := other.OpenState(aad, sealed); !errors.Is(err, broker.ErrStateOpen) {
		t.Fatalf("another broker key opened the body: %v", err)
	}
	var none *broker.Key
	if _, err := none.SealState(aad, plain); !errors.Is(err, broker.ErrNoBroker) {
		t.Fatalf("no key: %v", err)
	}
}
