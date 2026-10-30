// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package handshake is the simulator handshake every PantherClaw simulator
// serves (HR-221): the gateway asks before it sends anything to a simulated
// connection, so a mistyped base URL never reaches a real service.
package handshake

import (
	"encoding/json/v2"
	"net/http"
	"regexp"
)

// Path is the well-known handshake path.
const Path = "/.well-known/pantherclaw-sim"

// Simulator is the fixed name a simulator answers with.
const Simulator = "pantherclaw-sim"

var noncePattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Answer is the handshake response body.
type Answer struct {
	Simulator string `json:"simulator"`
	Kind      string `json:"kind"`
	Nonce     string `json:"nonce"`
}

// Wrap answers the handshake for kind (payments, mcp, github, stripe, slack,
// teams, aws, a2a, jira or gitlab) and passes every other request to next.
func Wrap(kind string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != Path {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Simulated", "true")
		nonce := r.URL.Query().Get("nonce")
		if r.Method != http.MethodGet || !noncePattern.MatchString(nonce) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.MarshalWrite(w, Answer{Simulator: Simulator, Kind: kind, Nonce: nonce})
	})
}
