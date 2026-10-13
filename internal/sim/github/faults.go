// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package github

import (
	"net/http"
	"time"
)

// Faults makes the simulator misbehave the ways GitHub can (G0 M8 G2).
type Faults struct {
	// TokenStatus, when set, is what the access-token endpoint answers
	// instead of minting (for example 500 or 403).
	TokenStatus int
	// TokenDelay holds every access-token answer this long.
	TokenDelay time.Duration
	// WiderGrant mints every token for all the installation's repositories
	// and permissions, whatever was asked.
	WiderGrant bool
	// LoseMerge merges and then drops the connection without an answer:
	// an unknown outcome whose effect happened.
	LoseMerge bool
	// RevokeStatus, when set, is what token revocation answers instead of
	// revoking: the token stays valid until it expires.
	RevokeStatus int
}

// SetFaults replaces the simulator's faults from the next request on.
func (s *Server) SetFaults(f Faults) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = f
}

// tokenFault applies the token endpoint's faults before it mints; it
// returns the status it answered, or 0 to mint. It sleeps without the
// lock held.
func (s *Server) tokenFault(w http.ResponseWriter) int {
	s.mu.Lock()
	f := s.faults
	s.mu.Unlock()
	if f.TokenDelay > 0 {
		time.Sleep(f.TokenDelay)
	}
	if f.TokenStatus != 0 {
		return fail(w, f.TokenStatus, "Simulated token endpoint failure")
	}
	return 0
}
