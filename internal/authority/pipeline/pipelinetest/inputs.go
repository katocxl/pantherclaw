// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipelinetest

import (
	"context"
	"crypto/sha256"

	"github.com/katocxl/pantherclaw/internal/authority/recording"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// InputKey names one evaluation of a transaction.
type InputKey struct {
	Transaction ids.UUID
	Evaluation  int
}

// Inputs returns the sealed inputs the world stored with an evaluation's
// receipt (G0 M7 design decision 11), or nil.
func (w *World) Inputs(txn ids.UUID, evaluation int) *recording.Sealed {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.fin().receipts[InputKey{txn, evaluation}].Inputs
}

// Receipt returns the decision receipt the world stored for an evaluation,
// or "".
func (w *World) Receipt(txn ids.UUID, evaluation int) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.fin().receipts[InputKey{txn, evaluation}].JWS
}

// KeepInputs makes the scenario's Authority seal every evaluation's inputs
// with a test key, and returns the Sealer that opens them.
func (s *Scenario) KeepInputs() *recording.Sealer {
	sealer := recording.NewSealer(pccrypto.NewEnvelope(TestDEKs{}))
	s.Authority.Inputs = sealer
	return sealer
}

// TestDEKs is a DEK source with one fixed key per org and purpose, for
// tests only.
type TestDEKs struct{}

// CurrentDEK implements crypto.DEKSource.
func (TestDEKs) CurrentDEK(ctx context.Context, org ids.OrgID, purpose string) (uint32, pclog.Secret[[]byte], error) {
	k, err := TestDEKs{}.DEK(ctx, org, purpose, 1)
	return 1, k, err
}

// DEK implements crypto.DEKSource.
func (TestDEKs) DEK(_ context.Context, org ids.OrgID, purpose string, version uint32) (pclog.Secret[[]byte], error) {
	if version != 1 {
		return pclog.Secret[[]byte]{}, pccrypto.ErrUnknownDEK
	}
	k := sha256.Sum256([]byte("pipelinetest|" + org.String() + "|" + purpose))
	return pclog.NewSecret(k[:]), nil
}
