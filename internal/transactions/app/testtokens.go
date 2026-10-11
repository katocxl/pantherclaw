// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/actiontoken"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// A target_verifier connection test (G0 M8 track C, N15, founder decision
// 2026-10-11): under its live lease, the connection's gateway gets
// test-purpose action tokens for the package's test read only, and sends
// that read four times: without a token, with a token bound to another
// body, with a fresh token and with the same token again. Only the read is
// ever tokened, so a test never writes.

// TestTokens are a target_verifier test's action tokens: Fresh binds the
// test read's empty body, Mismatch another body, so a verifier must refuse
// it.
type TestTokens struct {
	Fresh, Mismatch string
}

// VerifierTest is a live target_verifier test lease: the test, its
// connection and the test read's operation.
type VerifierTest struct {
	Test, Connection ids.UUID
	Operation        string
}

// mismatchedBody is what the Mismatch token binds instead of the read's
// empty body.
const mismatchedBody = "pantherclaw:target_verifier:body_mismatch"

// ErrNoActionTokens: the server has no action_tokens key.
var ErrNoActionTokens = pcerr.New(pcerr.Unavailable, "ACTION_TOKENS_UNAVAILABLE", "action tokens are not configured")

// MintTestTokens mints a target_verifier test's action tokens for gw's
// live lease of task. Any other lease, or a lease of another kind of test,
// is ErrLease.
func (s *Service) MintTestTokens(ctx context.Context, org ids.OrgID, gateway, task ids.UUID, secret []byte) (TestTokens, error) {
	if s.ActionTokens == nil {
		return TestTokens{}, ErrNoActionTokens
	}
	if len(secret) != 32 {
		return TestTokens{}, ErrLease
	}
	t, err := s.Store.VerifierTest(ctx, org, gateway, task, secret)
	if err != nil {
		return TestTokens{}, err
	}
	issuer := s.Issuer
	if issuer == "" {
		issuer = "pantherclaw"
	}
	act := sha256.Sum256([]byte("connection_test:" + t.Test.String()))
	empty, other := sha256.Sum256(nil), sha256.Sum256([]byte(mismatchedBody))
	tok := actiontoken.Token{
		Issuer: issuer, Audience: t.Connection, Transaction: t.Test, Act: act[:], Operation: t.Operation,
		TargetType: defs.ConnectionTarget, TargetID: t.Connection.String(), Now: time.Now(),
	}
	var out TestTokens
	tok.BodySHA256 = empty[:]
	if out.Fresh, _, err = actiontoken.Mint(s.ActionTokens, tok); err != nil {
		return TestTokens{}, err
	}
	tok.BodySHA256 = other[:]
	if out.Mismatch, _, err = actiontoken.Mint(s.ActionTokens, tok); err != nil {
		return TestTokens{}, err
	}
	return out, nil
}
