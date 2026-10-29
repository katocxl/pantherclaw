// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package broker

import (
	"encoding/hex"
	"errors"

	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
)

// MCP task bodies (G0 M15 D13, HR-411): a task the gateway keeps on the
// server is sealed to its own broker key, which every replica of the
// gateway shares, so any replica opens it and the server never does.
// The associated data binds the org, the gateway, the kind and the
// entry's key, so a body opens only as the entry it was sealed for.

// stateInfo is the HPKE info of a sealed MCP state body.
var stateInfo = []byte("pc.mcp_state.v1")

// ErrStateOpen: the body does not open (another key, a rotated key, or
// another entry's body).
var ErrStateOpen = errors.New("broker: the MCP state body does not open")

// StateAAD is the associated data of an MCP state body (D13).
func StateAAD(org, gateway, kind string, key []byte) []byte {
	return []byte("pc.mcp_state.v1|" + org + "|" + gateway + "|" + kind + "|" + hex.EncodeToString(key))
}

// SealState seals an MCP state body to the key's public half.
func (k *Key) SealState(aad, plaintext []byte) ([]byte, error) {
	if k == nil {
		return nil, ErrNoBroker
	}
	return pccrypto.Seal(k.priv.PublicKey(), stateInfo, aad, plaintext)
}

// OpenState opens an MCP state body sealed with SealState.
func (k *Key) OpenState(aad, sealed []byte) ([]byte, error) {
	if k == nil {
		return nil, ErrNoBroker
	}
	pt, err := pccrypto.Open(k.priv, stateInfo, aad, sealed)
	if err != nil {
		return nil, ErrStateOpen
	}
	return pt, nil
}
