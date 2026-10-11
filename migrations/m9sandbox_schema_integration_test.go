// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
)

// These tests check the sandbox schema (G0 M9 slice B4, migrations 00090
// and 00091): the second line of defense behind the sandbox module. Names
// are prefixed m9s.

const (
	m9sToken = `INSERT INTO pc.enrollment_tokens (org_id, id, agent_id, environment_id, token_hash, created_by, expires_at)
		SELECT $1, $2, $3, environment_id, $4, 'test', now() + interval '15 minutes' FROM pc.runs WHERE org_id = $1 AND id = $5`
	m9sSession = `INSERT INTO pc.sandbox_sessions (org_id, id, agent_id, launcher, enrollment_token_id, agent_image, edge_image,
		probe_image, config_digest, probe_jkt, probe_public_key, host_jkt, host_public_key, engine_version, api_version, runtime,
		expires_at)
		VALUES ($1, $2, $3, 'user:test', $4, $5, $5, $5, $5, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', $6,
		'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', sha256($6), '29.8.2', '1.56',
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
	f.want(t, m5Denied, "a nonce issued with its own time", `INSERT INTO pc.probe_nonces (org_id, id, session_id, kind, nonce_sha256,
		created_at, expires_at) VALUES ($1, $2, $3, 'SANDBOX', $4, now() + interval '1 day', now() + interval '1 day 10 minutes')`,
		f.org, m5ID(), session, m9sBytes(32))
	f.mustExec(t, "UPDATE pc.probe_nonces SET used_at = now() WHERE id = $1", nonce)
	f.want(t, m5Check, "a nonce used twice", "UPDATE pc.probe_nonces SET used_at = now() WHERE id = $1", nonce)
	f.want(t, m5Check, "a used nonce made unused", "UPDATE pc.probe_nonces SET used_at = NULL WHERE id = $1", nonce)

	f.want(t, m7bFK, "a closure of no session", m9cClosure, f.org, m5ID(), f.agent, f.connection, m5ID(), "PASSED",
		true, m9cDigest, f.gateway, f.version, "1 minute", "1 hour")
	f.want(t, m5Check, "an ended session without its end", "UPDATE pc.sandbox_sessions SET state = 'ENDED' WHERE id = $1", session)
	f.mustExec(t, "UPDATE pc.sandbox_sessions SET state = 'ENDED', ended_at = now() WHERE id = $1", session)
	f.want(t, m5Denied, "a session's images never change", "UPDATE pc.sandbox_sessions SET agent_image = $1", m9cDigest)
}

// TestHR183_AgentHostsAreBoundedHostNamesInSchema: a connection names at
// most 16 agent hosts, each a lowercase host name, none twice, no IP
// literal, empty or NULL element.
func TestHR183_AgentHostsAreBoundedHostNamesInSchema(t *testing.T) {
	f := newM9cFixture(t)
	const set = "UPDATE pc.connections SET agent_hosts = $2 WHERE id = $1"
	f.mustExec(t, set, f.connection, []string{"api.github.com", "uploads.github.com"})
	f.want(t, m5Check, "an upper-case host", set, f.connection, []string{"API.github.com"})
	f.want(t, m5Check, "a host with a port", set, f.connection, []string{"api.github.com:443"})
	f.want(t, m5Check, "a URL", set, f.connection, []string{"https://api.github.com"})
	f.want(t, m5Check, "an empty host after a valid one", set, f.connection, []string{"api.github.com", ""})
	f.want(t, m5Check, "a NULL host", "UPDATE pc.connections SET agent_hosts = ARRAY['api.github.com', NULL] WHERE id = $1", f.connection)
	f.want(t, m5Check, "a host twice", set, f.connection, []string{"api.github.com", "api.github.com"})
	f.want(t, m5Check, "an IP literal", set, f.connection, []string{"140.82.112.6"})
	many := make([]string, 17)
	for i := range many {
		many[i] = "h" + string(rune('a'+i)) + ".example"
	}
	f.want(t, m5Check, "17 hosts", set, f.connection, many)
}

// TestHR215_SessionsKeysNoncesAndInstancesHoldInSchema: the probe and host
// keys differ; pc_app sets no session or report time; a report's nonce is
// of its own session and kind; a session changes only forward; and a
// sandbox instance belongs only to the session whose enrollment token
// enrolled it, once (design decision 2).
func TestHR215_SessionsKeysNoncesAndInstancesHoldInSchema(t *testing.T) {
	f := newM9cFixture(t)
	token, session := m5ID(), m5ID()
	f.mustExec(t, m9sToken, f.org, token, f.agent, m9sBytes(32), f.run)
	f.mustExec(t, m9sSession, f.org, session, f.agent, token, m9cDigest, m9sBytes(32), "1 hour")

	other := m5ID()
	f.mustExec(t, m9sToken, f.org, other, f.agent, m9sBytes(32), f.run)
	key := m9sBytes(32)
	f.want(t, m5Check, "one key for both", `INSERT INTO pc.sandbox_sessions (org_id, id, agent_id, launcher, enrollment_token_id,
		agent_image, edge_image, probe_image, config_digest, probe_jkt, probe_public_key, host_jkt, host_public_key, engine_version,
		api_version, runtime, expires_at) VALUES ($1, $2, $3, 'user:test', $4, $5, $5, $5, $5, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
		$6, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', $6, '29.8.2', '1.56', 'runc', now() + interval '1 hour')`,
		f.org, m5ID(), f.agent, other, m9cDigest, key)
	f.want(t, m5Denied, "a session opened at the caller's time", `INSERT INTO pc.sandbox_sessions (org_id, id, agent_id, launcher,
		enrollment_token_id, agent_image, edge_image, probe_image, config_digest, probe_jkt, probe_public_key, host_jkt, host_public_key,
		engine_version, api_version, runtime, opened_at, expires_at) VALUES ($1, $2, $3, 'user:test', $4, $5, $5, $5, $5,
		'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', $6, 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', sha256($6), '29.8.2', '1.56',
		'runc', now() + interval '1 year', now() + interval '1 year 1 hour')`, f.org, m5ID(), f.agent, other, m9cDigest, key)
	f.want(t, m5Denied, "a session opened already bound", `INSERT INTO pc.sandbox_sessions (org_id, id, agent_id, launcher,
		enrollment_token_id, agent_image, edge_image, probe_image, config_digest, probe_jkt, probe_public_key, host_jkt, host_public_key,
		engine_version, api_version, runtime, run_id, expires_at) VALUES ($1, $2, $3, 'user:test', $4, $5, $5, $5, $5,
		'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', $6, 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', sha256($6), '29.8.2', '1.56',
		'runc', $7, now() + interval '1 hour')`, f.org, m5ID(), f.agent, other, m9cDigest, key, f.run)

	// A report's nonce: its own session's, of its own kind.
	nonce := m5ID()
	f.mustExec(t, m9sNonce, f.org, nonce, session, m9sBytes(32), "15 minutes")
	run := `INSERT INTO pc.probe_runs (org_id, id, session_id, nonce_id, kind, report, report_sha256) VALUES ($1, $2, $3, $4, $5, 'a.b.c', $6)`
	f.want(t, m7bFK, "a canary report on a sandbox nonce", run, f.org, m5ID(), session, nonce, "CANARY", m9sBytes(32))
	otherSession := m5ID()
	f.mustExec(t, m9sSession, f.org, otherSession, f.agent, other, m9cDigest, m9sBytes(32), "1 hour")
	f.want(t, m7bFK, "a report on another session's nonce", run, f.org, m5ID(), otherSession, nonce, "SANDBOX", m9sBytes(32))
	f.want(t, m5Denied, "a report received at the caller's time", `INSERT INTO pc.probe_runs (org_id, id, session_id, nonce_id, kind,
		report, report_sha256, received_at) VALUES ($1, $2, $3, $4, 'SANDBOX', 'a.b.c', $5, now() - interval '1 day')`,
		f.org, m5ID(), session, nonce, m9sBytes(32))

	// An instance is the session's when its token enrolled it, once.
	instance := `INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via, enrollment_token_id,
		sandbox_session_id) VALUES ($1, $2, $3, $4, '{}', 'ADMITTED', 'enrollment_token', $5, $6)`
	jkt := func() string { return base64.RawURLEncoding.EncodeToString(m9sBytes(32)) }
	f.want(t, m5Check, "an instance another token enrolled", instance, f.org, m5ID(), f.agent, jkt(), other, session)
	mine := m5ID()
	f.mustExec(t, instance, f.org, mine, f.agent, jkt(), token, session)
	f.want(t, m5Check, "an instance moved to another session", "UPDATE pc.agent_instances SET sandbox_session_id = $2 WHERE id = $1",
		mine, otherSession)
	f.want(t, m5Check, "an instance taken out of its session", "UPDATE pc.agent_instances SET sandbox_session_id = NULL WHERE id = $1", mine)
	later := m5ID()
	f.mustExec(t, instance, f.org, later, f.agent, jkt(), other, nil)
	f.want(t, m5Check, "an instance joined to a session its token did not open",
		"UPDATE pc.agent_instances SET sandbox_session_id = $2 WHERE id = $1", later, session)
	f.mustExec(t, "UPDATE pc.agent_instances SET sandbox_session_id = $2 WHERE id = $1", later, otherSession)

	// A session changes only forward.
	f.mustExec(t, "UPDATE pc.sandbox_sessions SET instance_id = $2, run_id = $3 WHERE id = $1", session, mine, f.run)
	f.want(t, m5Check, "an instance rebound", "UPDATE pc.sandbox_sessions SET instance_id = $2 WHERE id = $1", session, later)
	f.want(t, m5Check, "a run unbound", "UPDATE pc.sandbox_sessions SET run_id = NULL WHERE id = $1", session)
	f.mustExec(t, "UPDATE pc.sandbox_sessions SET state = 'ENDED', ended_at = now() WHERE id = $1", session)
	f.want(t, m5Check, "an ended session reopened", "UPDATE pc.sandbox_sessions SET state = 'OPEN', ended_at = NULL WHERE id = $1", session)
	f.want(t, m5Check, "an ended session expired", "UPDATE pc.sandbox_sessions SET state = 'EXPIRED' WHERE id = $1", session)
}
