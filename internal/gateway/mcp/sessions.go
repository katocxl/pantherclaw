// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcp

import (
	"crypto/sha256"
	"errors"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
)

// MCP 2025-11-25 sessions (G0 M6 design decision 13, HR-083). initialize
// opens a session: a 256-bit random id bound to the gateway's org, the
// connection, the verified instance, the key that signed the request and
// the run. Every later POST must carry the id and PAP/1 credentials of that
// instance and key in that run, and is verified again. A session ends
// after 30 idle minutes, after 8 hours, when its run expires or ends, or on
// DELETE; an instance keeps at most 16, and opening another ends its least
// recently used one. Sessions live in this gateway's memory: a restart
// ends them, and clients initialize again on the 404. Session ids are
// never logged.
const (
	// LegacyVersion is the MCP revision with sessions this face speaks.
	LegacyVersion = "2025-11-25"
	// HeaderSessionID carries the session id (2025-11-25 transport).
	HeaderSessionID = "Mcp-Session-Id"

	sessionIdle            = 30 * time.Minute
	sessionMax             = 8 * time.Hour
	maxSessionsPerInstance = 16
	maxSessions            = 10_000
)

// errSessionsFull: the gateway holds as many sessions as it may.
var errSessionsFull = errors.New("mcp: too many sessions")

// session is what a session id is bound to.
type session struct {
	conn, instance, jkt, run string
	seen, expires            time.Time
}

// binds reports whether a request on conn, whose token names instance and
// key jkt, in run (empty: the session's), belongs to the session. Values
// from the token are unverified here; the Authority verifies them on the
// same request.
func (s session) binds(conn string, in dispatch.Inbound) bool {
	return s.conn == conn && s.instance == in.Instance && s.jkt == in.JKT && (in.Run == "" || in.Run == s.run)
}

func sessionKey(id string) [sha256.Size]byte { return sha256.Sum256([]byte(id)) }

func (v *session) live(now time.Time) bool {
	return now.Before(v.expires) && now.Sub(v.seen) < sessionIdle
}

// sessionStore keeps a gateway's sessions (G0 M15 D14): in memory
// (state_memory.go) or on the server (state_server.go), where every
// replica sees them and only the SHA-256 of a session id is stored
// (HR-413).
type sessionStore interface {
	// open starts a session ending at most 8 hours from now and never
	// after runExpires, and returns its id; errSessionsFull when the
	// gateway holds as many as it may.
	open(conn, instance, jkt, run string, runExpires time.Time) (string, error)
	// get returns a live session; err when the store cannot be asked.
	get(id string) (sess session, ok bool, err error)
	// touch records a verified request in the session.
	touch(id string)
	// end ends a session.
	end(id string)
}
