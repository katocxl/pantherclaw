// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"crypto/rand"
	"testing"
)

// These tests check the sandbox schema (G0 M9 slice B4, migrations 00090
// and 00091): the second line of defense behind the sandbox module. Names
// are prefixed m9s.

const (
	m9sToken = `INSERT INTO pc.enrollment_tokens (org_id, id, agent_id, environment_id, token_hash, created_by, expires_at)
		SELECT $1, $2, $3, environment_id, $4, 'test', now() + interval '15 minutes' FROM pc.runs WHERE org_id = $1 AND id = $5`
	m9sSession = `INSERT INTO pc.sandbox_sessions (org_id, id, agent_id, launcher, enrollment_token_id, agent_image, edge_image,
		probe_image, config_digest, probe_jkt, probe_public_key, engine_version, api_version, runtime, expires_at)
		VALUES ($1, $2, $3, 'user:test', $4, $5, $5, $5, $5, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', $6, '29.8.2', '1.56',
		'runc', now() + $7::interval)`
	m9sNonce = `INSERT INTO pc.probe_nonces (org_id, id, session_id, kind, nonce_sha256, expires_at)
		VALUES ($1, $2, $3, 'SANDBOX', $4, now() + $5::interval)`
	m9sRun = `INSERT INTO pc.probe_runs (org_id, id, session_id, nonce_id, kind, report, report_sha256)
		VALUES ($1, $2, $3, $4, 'SANDBOX', 'a.b.c', $5)`
)

func m9sBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// sandboxSession inserts an open sandbox session of the fixture's agent,
// with its enrollment token, and returns its id; the error is the
// inserts'. Closures need one (coverage_closures_session_fk).
func (f m9cFixture) sandboxSession() (string, error) {
	token, id := m5ID(), m5ID()
	if err := f.exec(m9sToken, f.org, token, f.agent, m9sBytes(32), f.run); err != nil {
		return "", err
	}
	return id, f.exec(m9sSession, f.org, id, f.agent, token, m9cDigest, m9sBytes(32), "1 hour")
}

// TestHR215_ProbeReportsAreSingleUseEvidenceInSchema: a session lasts at
// most 24 hours; a nonce lives at most 15 minutes and is used once per
// report; reports are insert-only; a closure names a real session.
func TestHR215_ProbeReportsAreSingleUseEvidenceInSchema(t *testing.T) {
	f := newM9cFixture(t)
	session, err := f.sandboxSession()
	if err != nil {
		t.Fatal(err)
	}
	token := m5ID()
	f.mustExec(t, m9sToken, f.org, token, f.agent, m9sBytes(32), f.run)
	f.want(t, m5Check, "a session over 24 hours", m9sSession, f.org, m5ID(), f.agent, token, m9cDigest, m9sBytes(32), "25 hours")
	f.want(t, m5Check, "a probe key that is not Ed25519", m9sSession, f.org, m5ID(), f.agent, token, m9cDigest, m9sBytes(31), "1 hour")
	f.want(t, m5Check, "an image tag", m9sSession, f.org, m5ID(), f.agent, token, "latest", m9sBytes(32), "1 hour")

	nonce, hash := m5ID(), m9sBytes(32)
	f.mustExec(t, m9sNonce, f.org, nonce, session, hash, "15 minutes")
	f.want(t, m5Check, "a nonce over 15 minutes", m9sNonce, f.org, m5ID(), session, m9sBytes(32), "16 minutes")
	f.want(t, m5Unique, "a nonce issued twice", m9sNonce, f.org, m5ID(), session, hash, "5 minutes")

	f.mustExec(t, m9sRun, f.org, m5ID(), session, nonce, m9sBytes(32))
	f.want(t, m5Unique, "a nonce used by two reports", m9sRun, f.org, m5ID(), session, nonce, m9sBytes(32))
	f.want(t, m5Denied, "reports are insert-only", "UPDATE pc.probe_runs SET report = 'x.y.z'")
	f.want(t, m5Denied, "reports are never deleted", "DELETE FROM pc.probe_runs")
	f.want(t, m5Denied, "a nonce changes only when used", "UPDATE pc.probe_nonces SET expires_at = now() + interval '1 day'")
	f.mustExec(t, "UPDATE pc.probe_nonces SET used_at = now() WHERE id = $1", nonce)

	f.want(t, m7bFK, "a closure of no session", m9cClosure, f.org, m5ID(), f.agent, f.connection, m5ID(), "PASSED",
		true, m9cDigest, f.gateway, f.version, "1 minute", "1 hour")
	f.want(t, m5Check, "an ended session without its end", "UPDATE pc.sandbox_sessions SET state = 'ENDED' WHERE id = $1", session)
	f.mustExec(t, "UPDATE pc.sandbox_sessions SET state = 'ENDED', ended_at = now() WHERE id = $1", session)
	f.want(t, m5Denied, "a session's images never change", "UPDATE pc.sandbox_sessions SET agent_image = $1", m9cDigest)
}

// TestHR183_AgentHostsAreBoundedHostNamesInSchema: a connection names at
// most 16 agent hosts, each a lowercase host name.
func TestHR183_AgentHostsAreBoundedHostNamesInSchema(t *testing.T) {
	f := newM9cFixture(t)
	const set = "UPDATE pc.connections SET agent_hosts = $2 WHERE id = $1"
	f.mustExec(t, set, f.connection, []string{"api.github.com", "uploads.github.com"})
	f.want(t, m5Check, "an upper-case host", set, f.connection, []string{"API.github.com"})
	f.want(t, m5Check, "a host with a port", set, f.connection, []string{"api.github.com:443"})
	f.want(t, m5Check, "a URL", set, f.connection, []string{"https://api.github.com"})
	many := make([]string, 17)
	for i := range many {
		many[i] = "h" + string(rune('a'+i)) + ".example"
	}
	f.want(t, m5Check, "17 hosts", set, f.connection, many)
}
