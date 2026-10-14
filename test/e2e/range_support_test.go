// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
	"github.com/katocxl/pantherclaw/internal/server"
)

// rangeExtra holds what only some scenarios need.
type rangeExtra struct {
	otherKey   ed25519.PrivateKey
	otherToken string
	sandbox    *sandboxRig
}

func (e *rangeExtra) available() bool { return sandboxBuilt }

func (e *rangeExtra) setup(d *rangeDriver) error {
	if !requires(d.sc, "sandbox") {
		return nil
	}
	return sandboxSetup(d)
}

func (e *rangeExtra) probe(d *rangeDriver, st domain.Step) (domain.Observation, error) {
	return sandboxProbe(d, st)
}

func (e *rangeExtra) mutateMCP(*rangeDriver, string, jsontext.Value) (domain.Observation, error) {
	return domain.Observation{}, errors.New("the harness driver cannot change the MCP simulator yet")
}

func runServerCmd(out, errb *bytes.Buffer, args ...string) int {
	return server.Run(context.Background(), args, out, errb, noEnv)
}

func refundableMore(t *testing.T, s *stack, charges ...string) {
	t.Helper()
	refundable(t, s.apiURL, s.factsKey, charges...)
}

func stolenClient(key ed25519.PrivateKey, token string) *http.Client {
	return &http.Client{Timeout: 60 * time.Second, Transport: &workloadclient.Transport{
		Key: key, Token: func() string { return token }, Base: http.DefaultTransport,
	}}
}

// doRecorded sends req signed as the seeded workload through rec, which
// keeps the request as it left the client.
func doRecorded(s *stack, rec *rangeRecorder, req *http.Request) error {
	c := &http.Client{Timeout: 60 * time.Second, Transport: &workloadclient.Transport{
		Key: s.key, Token: func() string { return s.token }, Base: rec,
	}}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

// enrolOtherInstance enrols another instance of the agent.
func enrolOtherInstance(t *testing.T, _ *stack) (ed25519.PrivateKey, string) {
	t.Helper()
	t.Fatal("the harness driver cannot enrol a second instance yet")
	return nil, ""
}

func (d *rangeDriver) refusedApproval(*callRec, string) (domain.Observation, error) {
	return domain.Observation{}, fmt.Errorf("the harness driver cannot try an approval as the launcher or the developer yet")
}

// objectID is the id of an object of this stack's organisation.
func (s *stack) objectID(t *testing.T, object string) ids.UUID {
	t.Helper()
	var id string
	switch object {
	case "transaction":
		code, r := s.refund(t, ids.NewV7(), "30.00")
		if code != http.StatusOK {
			t.Fatalf("a refund in the second organisation: %d %+v", code, r)
		}
		id = r.TransactionID
	case "approval":
		code, r := s.refund(t, ids.NewV7(), "85.00")
		if code != http.StatusForbidden {
			t.Fatalf("a held refund in the second organisation: %d %+v", code, r)
		}
		s.query(t, "SELECT id::text FROM pc.approval_requests WHERE transaction_id = $1 LIMIT 1", []any{r.TransactionID}, &id)
	case "run":
		id = s.run
	}
	return mustUUID(t, id)
}

// revokeSeededGrant has the seeded grant's issuer revoke it.
func (s *stack) revokeSeededGrant(t *testing.T) {
	t.Helper()
	var id string
	s.query(t, "SELECT id::text FROM pc.grants ORDER BY created_at LIMIT 1", nil, &id)
	t.Fatalf("the harness driver cannot revoke grant %s yet", id)
}

// runHeader is the run a call is made in.
func (d *rangeDriver) runHeader() string {
	if d.asRun != "" {
		return d.asRun
	}
	return d.s.run
}
