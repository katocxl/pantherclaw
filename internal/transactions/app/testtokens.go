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
// ever tokened, so a test never writes. This is HR-188's one exception to
// "minted only at BeginDispatch" (founder decision 2026-10-13): one mint of
// the two tokens per lease attempt, each mint recorded on the test and
// audited. The tokens expire no later than the lease they were minted
// under.

// TestTokens are a target_verifier test's action tokens: Fresh binds the
// test read's empty body, Mismatch another body, so a verifier must refuse
// it.
type TestTokens struct {
	Fresh, Mismatch string
}

// MintedTokens are a mint's tokens and their ids, which its audit event
// names.
type MintedTokens struct {
	TestTokens
	FreshID, MismatchID ids.UUID
}

// VerifierTest is a live target_verifier test lease: the test, its
// connection, the test read's operation, the lease's attempt and when the
// lease ends, which its tokens do not outlive.
type VerifierTest struct {
	Test, Connection ids.UUID
	Operation        string
	Attempt          int32
	LeaseExpires     time.Time
}

// mismatchedBody is what the Mismatch token binds instead of the read's
// empty body.
const mismatchedBody = "pantherclaw:target_verifier:body_mismatch"

var (
	// ErrNoActionTokens: the server has no action_tokens key.
	ErrNoActionTokens = pcerr.New(pcerr.Unavailable, "ACTION_TOKENS_UNAVAILABLE", "action tokens are not configured")
	// ErrTestTokensMinted: this attempt of the test already got its tokens.
	ErrTestTokensMinted = pcerr.New(pcerr.FailedPrecondition, "TEST_TOKENS_ALREADY_MINTED",
		"this attempt of the connection test already got its action tokens")
	// ErrTestTokensRefused: the test's connection or read no longer allows
	// test tokens.
	ErrTestTokensRefused = pcerr.New(pcerr.FailedPrecondition, "TEST_TOKENS_NOT_POSSIBLE",
		"test tokens need an ACTIVE target_enforced connection, its package's test read and no kill switch")
)

// MintTestTokens mints a target_verifier test's action tokens for gw's
// live lease of task, once per lease attempt. Any other lease, or a lease
// of another kind of test, is ErrLease.
func (s *Service) MintTestTokens(ctx context.Context, org ids.OrgID, gateway, task ids.UUID, secret []byte) (TestTokens, error) {
	if s.ActionTokens == nil {
		return TestTokens{}, ErrNoActionTokens
	}
	if len(secret) != 32 {
		return TestTokens{}, ErrLease
	}
	issuer := s.Issuer
	if issuer == "" {
		issuer = "pantherclaw"
	}
	return s.Store.MintTestTokens(ctx, org, gateway, task, secret, func(t VerifierTest) (MintedTokens, error) {
		act := sha256.Sum256([]byte("connection_test:" + t.Test.String()))
		empty, other := sha256.Sum256(nil), sha256.Sum256([]byte(mismatchedBody))
		tok := actiontoken.Token{
			Issuer: issuer, Audience: t.Connection, Transaction: t.Test, Act: act[:], Operation: t.Operation,
			TargetType: defs.ConnectionTarget, TargetID: t.Connection.String(), Now: time.Now(), NotAfter: t.LeaseExpires,
		}
		var out MintedTokens
		var err error
		tok.BodySHA256 = empty[:]
		if out.Fresh, out.FreshID, err = actiontoken.Mint(s.ActionTokens, tok); err != nil {
			return MintedTokens{}, err
		}
		tok.BodySHA256 = other[:]
		if out.Mismatch, out.MismatchID, err = actiontoken.Mint(s.ActionTokens, tok); err != nil {
			return MintedTokens{}, err
		}
		return out, nil
	})
}
