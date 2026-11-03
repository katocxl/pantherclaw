// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"net/http"
	"strings"
	"testing"

	iddomain "github.com/katocxl/pantherclaw/internal/idaccess/domain"
)

// TestE2E_M26_IdpAccessExit is the IdP-native access part of M26's exit
// (G0 M26 D403): an agent uses an existing grant through the test IdP, one
// token and one run per task; an assertion for a person with no grant is
// refused; a revoked grant stops the next call. The real tenant check is
// pending (F801).
//
// Covers: F910, F912
func TestE2E_M26_IdpAccessExit(t *testing.T) {
	s := start(t, options{budget: "1000.00"})
	a := s.idpAccessOn(t)

	var runs []string
	t.Run("an agent uses the person's existing grant, per task", func(t *testing.T) {
		before := s.sim.Stats().Refunds
		for i, amount := range []string{"11.00", "12.00"} {
			res, err := a.exchange(t, a.assert(t, idpPerson, idpClientID))
			if err != nil {
				code, desc := oauthErr(err)
				t.Fatalf("task %d: %s %s", i, code, desc)
			}
			if status, body := a.bearer(t, res.AccessToken, amount); !succeeded(status, body) {
				t.Fatalf("task %d: %d %s", i, status, body)
			}
			runs = append(runs, res.RunID)
		}
		if runs[0] == runs[1] {
			t.Fatal("two tasks shared a run")
		}
		if got := s.sim.Stats().Refunds - before; got != 2 {
			t.Fatalf("%d refunds reached the target, want 2", got)
		}
		var n int
		s.query(t, `SELECT count(*) FROM pc.runs WHERE id = ANY($1::uuid[]) AND principal_source = 'id_jag' AND principal_user_id = $2
			AND grant_id = $3 AND launcher_instance_id = $4`, []any{runs, a.person, a.grant.String(), a.instance}, &n)
		if n != 2 {
			t.Fatalf("%d of the runs are the person's own over their grant", n)
		}
		s.query(t, "SELECT count(*) FROM pc.grants WHERE principal_user_id = $1", []any{a.person}, &n)
		if n != 1 {
			t.Fatalf("the person has %d grants, want the one they already had", n)
		}
	})

	t.Run("the token works only as a bearer token on its own server", func(t *testing.T) {
		before := s.sim.Stats().Refunds
		res, err := a.exchange(t, a.assert(t, idpPerson, idpClientID))
		if err != nil {
			t.Fatal(err)
		}
		if status, body := a.papRoute(t, res.AccessToken, res.RunID, "13.00"); succeeded(status, body) {
			t.Fatalf("an MCP access token passed on the PAP/1 route: %d %s", status, body)
		}
		status, challenge, body := a.call(t, iddomain.ResourcePath+idpConnection, idpRefund("13.00"),
			map[string]string{"Authorization": "Bearer " + s.token})
		if succeeded(status, body) || status != http.StatusUnauthorized || !strings.Contains(challenge, "resource_metadata=") {
			t.Fatalf("a workload token passed as a bearer token: %d %q %s", status, challenge, body)
		}
		if s.sim.Stats().Refunds != before {
			t.Fatal("a refused call reached the target")
		}
	})

	t.Run("an assertion for a person with no grant is refused", func(t *testing.T) {
		_, err := a.exchange(t, a.assert(t, idpNobody, idpClientID))
		if code, desc := oauthErr(err); code != "access_denied" || !strings.Contains(desc, "NO_GRANT") {
			t.Fatalf("no grant: %s %s", code, desc)
		}
	})

	t.Run("a revoked grant stops the next call", func(t *testing.T) {
		res, err := a.exchange(t, a.assert(t, idpPerson, idpClientID))
		if err != nil {
			t.Fatal(err)
		}
		if status, body := a.bearer(t, res.AccessToken, "14.00"); !succeeded(status, body) {
			t.Fatalf("before the revocation: %d %s", status, body)
		}
		before := s.sim.Stats().Refunds
		a.revoke(t)
		status, body := a.bearer(t, res.AccessToken, "15.00")
		if succeeded(status, body) || !strings.Contains(body, "GRANT_REVOKED") {
			t.Fatalf("the call after the revocation: %d %s", status, body)
		}
		if s.sim.Stats().Refunds != before {
			t.Fatal("a call after the revocation reached the target")
		}
		_, err = a.exchange(t, a.assert(t, idpPerson, idpClientID))
		if code, desc := oauthErr(err); code != "access_denied" || !strings.Contains(desc, "NO_GRANT") {
			t.Fatalf("a new task after the revocation: %s %s", code, desc)
		}
	})
}
