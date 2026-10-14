// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/jsontext"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"

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

	// The MCP simulator the payments connection dispatches to, clean and as it turns bad.
	mcpClean, mcpPoisoned http.Handler
	mcpCurrent            atomic.Pointer[http.Handler]
}

func (e *rangeExtra) available() bool { return sandboxBuilt }

func (e *rangeExtra) setup(d *rangeDriver) error {
	if !requires(d.sc, "sandbox") {
		return nil
	}
	return sandboxSetup(d)
}

func (e *rangeExtra) probe(d *rangeDriver, st domain.Step, vars map[string]string) (domain.Observation, error) {
	return sandboxProbe(d, st, vars)
}

func (e *rangeExtra) mutateMCP(d *rangeDriver, change string, args jsontext.Value) (domain.Observation, error) {
	return d.mutateMCP(change, args)
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

// runHeader is the run a call is made in.
func (d *rangeDriver) runHeader() string {
	if d.asRun != "" {
		return d.asRun
	}
	if d.defaultRun != "" {
		return d.defaultRun
	}
	return d.s.run
}

// seedUnlisted adds a connection to an address the gateway's egress guard
// does not allow, which registration accepts (S12).
func (d *rangeDriver) seedUnlisted() {
	t, s := d.t, d.s
	gw := s.gatewayID(t)
	conns := capp.New(s.pool, nil, s.apiURL, "")
	if _, err := conns.Seed(context.Background(), s.org, "range", capp.CreateInput{
		Name: "unlisted", Kind: capp.KindHTTP, Package: mockpayments.Name, BaseURL: "http://127.0.0.2:9", Gateway: gw,
		DestinationClass: capp.ClassInternal, AccessMode: capp.AccessNone, DefaultMode: capp.ModeEnforce,
	}); err != nil {
		t.Fatal(err)
	}
	s.waitConfig(t, s.configVersion(t, gw))
}

// seedReal adds a connection that is not simulated, to the same target.
func (d *rangeDriver) seedReal() {
	t, s := d.t, d.s
	gw := s.gatewayID(t)
	conns := capp.New(s.pool, nil, s.apiURL, "")
	if _, err := conns.Seed(context.Background(), s.org, "range", capp.CreateInput{
		Name: "real", Kind: capp.KindHTTP, Package: mockpayments.Name, BaseURL: s.simURL, Gateway: gw,
		DestinationClass: capp.ClassInternal, AccessMode: capp.AccessNone, DefaultMode: capp.ModeEnforce,
	}); err != nil {
		t.Fatal(err)
	}
	s.waitConfig(t, s.configVersion(t, gw))
}

// makeRangeStack marks what the stack seeded as a range's: the agent is a
// range agent, its run and every connection but "real" are simulated
// (HR-220, HR-221). dev seed predates the mark, so the flags are set the way
// the migration leaves them settable only: by the database's owner.
func (d *rangeDriver) makeRangeStack() {
	t, s := d.t, d.s
	s.db.AdminExec(t, "UPDATE pc.agents SET range_agent = true WHERE org_id = $1", s.org)
	s.db.AdminExec(t, "UPDATE pc.runs SET simulated = true WHERE org_id = $1", s.org)
	s.db.AdminExec(t, "UPDATE pc.connections SET simulated = true WHERE org_id = $1 AND name <> 'real'", s.org)
	d.reloadGateway()
	d.simulated = true
}
