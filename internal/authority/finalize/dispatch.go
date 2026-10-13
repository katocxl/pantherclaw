// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize

import (
	"net/url"
	"regexp"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/actiontoken"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Action tokens (G0 M6 design decision 17, PAP-1 §10, HR-188).
const (
	// TypeActionToken is the JOSE type of an action token.
	TypeActionToken = actiontoken.Type
	// ActionTokenTTL is an action token's lifetime.
	ActionTokenTTL = actiontoken.TTL
	// AccessTargetEnforced is the access mode whose dispatches carry an
	// action token.
	AccessTargetEnforced = "target_enforced"
)

// Errors of the commit point.
var (
	ErrOutbound = pcerr.New(pcerr.InvalidArgument, "OUTBOUND_INVALID",
		"the outbound request is a method and an absolute http(s) URL, with an optional SHA-256 of the body")
	ErrOutboundRequired = pcerr.New(pcerr.FailedPrecondition, "OUTBOUND_REQUIRED",
		"a target-enforced connection needs the outbound request and the SHA-256 of its exact body")
)

// Outbound is the request the gateway built and is about to send (PAP-1
// §7.3): recorded with the permit, and what an action token binds.
type Outbound struct {
	Method     string
	URL        string
	BodySHA256 []byte
}

var methodRe = regexp.MustCompile(`^[A-Z]{3,7}$`)

func (o Outbound) check() error {
	if (o.Method == "") != (o.URL == "") || (len(o.BodySHA256) != 0 && len(o.BodySHA256) != 32) {
		return ErrOutbound
	}
	if o.Method == "" {
		return nil
	}
	u, err := url.Parse(o.URL)
	if !methodRe.MatchString(o.Method) || err != nil || len(o.URL) > 4096 || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
		u.User != nil || u.Fragment != "" {
		return ErrOutbound
	}
	return nil
}

// Dispatching is what the Authority bound for a permit that just moved to
// DISPATCHING: the store reads it in the same transaction.
type Dispatching struct {
	Transaction   ids.UUID
	Connection    *ids.UUID
	AccessMode    string // the connection's; "" without one
	Operation     string
	TargetType    string
	TargetID      string
	EffectiveHash []byte
	Now           time.Time
}

// actionToken mints the action token of a target-enforced dispatch (HR-188):
// audience the connection, at most 60 seconds, a single-use id, and the
// transaction, effective action hash, body hash, operation and target. It
// returns no token for any other access mode.
func (a *Authority) actionToken(d Dispatching, out Outbound) (string, *ids.UUID, error) {
	if d.AccessMode != AccessTargetEnforced {
		return "", nil, nil
	}
	if d.Connection == nil || len(out.BodySHA256) != 32 || out.Method == "" {
		return "", nil, ErrOutboundRequired
	}
	if a.ActionTokens == nil {
		return "", nil, pcerr.New(pcerr.Unavailable, "ACTION_TOKENS_UNAVAILABLE", "action tokens are not configured")
	}
	tok, jti, err := actiontoken.Mint(a.ActionTokens, actiontoken.Token{
		Issuer: a.issuer(), Audience: *d.Connection, Transaction: d.Transaction, Act: d.EffectiveHash, BodySHA256: out.BodySHA256,
		Operation: d.Operation, TargetType: d.TargetType, TargetID: d.TargetID, Now: d.Now,
	})
	if err != nil {
		return "", nil, err
	}
	return tok, &jti, nil
}
