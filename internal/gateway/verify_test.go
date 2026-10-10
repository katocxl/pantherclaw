// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/sim/payments"
)

// simTarget runs the payments simulator as the connection's target and
// counts every request it gets.
func simTarget(sim *payments.Server, n *atomic.Int32) func(*harness) {
	return func(h *harness) {
		inner := sim.Handler()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n.Add(1)
			inner.ServeHTTP(w, r)
		}))
		h.targetURL = ts.URL
	}
}

// refundAt makes a refund in the simulator, as a dispatch with key would.
func refundAt(t *testing.T, sim *payments.Server, charge, key string) string {
	t.Helper()
	ts := httptest.NewServer(sim.Handler())
	defer ts.Close()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+"/v1/refunds",
		strings.NewReader(`{"charge":"`+charge+`","amount":"30.00","currency":"USD","reason":"duplicate"}`))
	req.Header.Set("Idempotency-Key", key)
	res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("refund: %v %v", res, err)
	}
	_ = res.Body.Close()
	refunds := sim.Refunds()
	return refunds[len(refunds)-1].ID
}

func reference(id string) []byte {
	return []byte(`{"mode":"reference","params":{},"target":{"id":"` + id + `","type":"payments.refund"}}`)
}

func lookup(charge string) []byte {
	return []byte(`{"mode":"lookup","params":{},"target":{"id":"` + charge + `","type":"payments.charge"}}`)
}

// TestHR190_TheGatewayReadsOnlyReviewedReadsAndDeclaredFields: a leased
// read is the package's reviewed GET, made through the connection, and
// reports only the fields the verifier declares; a lookup finds the
// write's effect by its idempotency key across pages.
func TestHR190_TheGatewayReadsOnlyReviewedReadsAndDeclaredFields(t *testing.T) {
	sim := payments.New(payments.Faults{}, pclog.Discard())
	var sent atomic.Int32
	h := setup(t, simTarget(sim, &sent))
	ctx := context.Background()
	id := refundAt(t, sim, "ch_1", "pc-txn-1")

	o, err := h.gw.engine.VerifyEffect(ctx, h.conn, dispatch.Lease{Operation: "payments.refund.get", Request: reference(id)})
	if err != nil || !o.Found || o.HTTPStatus != http.StatusOK || len(o.Digest) != 32 {
		t.Fatalf("reference: %+v %v", o, err)
	}
	want := map[string]string{"/charge": "ch_1", "/amount": "30.00", "/currency": "USD", "/status": "succeeded"}
	if len(o.Fields) != len(want) {
		t.Fatalf("fields %v, want only the declared %v", o.Fields, want)
	}
	for k, v := range want {
		if o.Fields[k] != v {
			t.Fatalf("fields %v, want %v", o.Fields, want)
		}
	}
	if o, _ := h.gw.engine.VerifyEffect(ctx, h.conn, dispatch.Lease{Operation: "payments.refund.get", Request: reference("re_missing")}); o.Found || o.HTTPStatus != http.StatusNotFound {
		t.Fatalf("a missing refund: %+v", o)
	}

	// Past one page of the charge's refunds, the lookup still finds it.
	for i := range 100 {
		refundAt(t, sim, "ch_2", "pc-other-"+strconv.Itoa(i))
	}
	refundAt(t, sim, "ch_2", "pc-txn-2")
	if o, err := h.gw.engine.VerifyEffect(ctx, h.conn, dispatch.Lease{Operation: "payments.refund.list", Request: lookup("ch_2"), Correlate: "pc-txn-2"}); err != nil || !o.Found || o.Fields["/status"] != "succeeded" {
		t.Fatalf("lookup across pages: %+v %v", o, err)
	}
	if o, err := h.gw.engine.VerifyEffect(ctx, h.conn, dispatch.Lease{Operation: "payments.refund.list", Request: lookup("ch_2"), Correlate: "pc-never"}); err != nil || o.Found || !o.Complete {
		t.Fatalf("an absent refund in a complete listing: %+v %v", o, err)
	}

	before := sent.Load()
	for name, l := range map[string]dispatch.Lease{
		"a write":                  {Operation: "payments.refund.create", Request: reference(id)},
		"a read no verifier names": {Operation: "payments.refund.recent", Request: lookup("ch_1")},
		"a lookup by reference":    {Operation: "payments.refund.list", Request: reference(id)},
		"an unknown field":         {Operation: "payments.refund.get", Request: []byte(`{"mode":"reference","target":{"id":"` + id + `","type":"payments.refund"},"params":{},"body":{}}`)},
	} {
		if _, err := h.gw.engine.VerifyEffect(ctx, h.conn, l); !errors.Is(err, dispatch.ErrNotReviewedRead) {
			t.Errorf("%s: %v, want ErrNotReviewedRead", name, err)
		}
	}
	h.containment.mu.Lock()
	h.containment.err = control.ErrKillSwitch
	h.containment.mu.Unlock()
	if _, err := h.gw.engine.VerifyEffect(ctx, h.conn, dispatch.Lease{Operation: "payments.refund.get", Request: reference(id)}); !errors.Is(err, dispatch.ErrContained) {
		t.Fatalf("under the kill switch: %v", err)
	}
	if sent.Load() != before {
		t.Fatalf("%d requests sent for refused reads", sent.Load()-before)
	}
}

// TestHR112_TheGatewayListsTheTargetLog: a target-log task lists every
// object the target created since the window's start, with its
// correlation value, only through the package's reviewed target-log read
// for this connection and the write it names.
func TestHR112_TheGatewayListsTheTargetLog(t *testing.T) {
	sim := payments.New(payments.Faults{}, pclog.Discard())
	var sent atomic.Int32
	h := setup(t, simTarget(sim, &sent))
	refundAt(t, sim, "ch_1", "pc-txn-1")
	refundAt(t, sim, "ch_2", "console-0001")
	request := func(conn, effectOf string) []byte {
		return []byte(`{"mode":"target_log","target":{"type":"pc.connection","id":"` + conn + `"},"params":{"created_gte":"0"},"effect_of":"` + effectOf + `"}`)
	}
	ctx := context.Background()
	o, err := h.gw.engine.VerifyEffect(ctx, h.conn, dispatch.Lease{
		Purpose: "target_log", Operation: "payments.refund.recent",
		Request: request(connID, "payments.refund.create"),
	})
	if err != nil || !o.Complete || len(o.Items) != 2 || o.Items[0].Correlation != "pc-txn-1" || o.Items[1].Correlation != "console-0001" ||
		o.Items[0].Created == 0 || !strings.HasPrefix(o.Items[0].ObjectRef, "re_") {
		t.Fatalf("target log %+v %v", o, err)
	}
	for name, l := range map[string]dispatch.Lease{
		"another connection":  {Purpose: "target_log", Operation: "payments.refund.recent", Request: request("01920000-0000-7000-8000-0000000000ff", "payments.refund.create")},
		"another write":       {Purpose: "target_log", Operation: "payments.refund.recent", Request: request(connID, "payments.refund.get")},
		"not the target log":  {Purpose: "target_log", Operation: "payments.refund.list", Request: request(connID, "payments.refund.create")},
		"a reference request": {Purpose: "target_log", Operation: "payments.refund.recent", Request: reference("re_1")},
	} {
		if _, err := h.gw.engine.VerifyEffect(ctx, h.conn, l); !errors.Is(err, dispatch.ErrNotReviewedRead) {
			t.Errorf("%s: %v, want ErrNotReviewedRead", name, err)
		}
	}
}

type fakeVerifications struct {
	mu      sync.Mutex
	leases  []dispatch.Lease
	reports []dispatch.Observation
}

func (f *fakeVerifications) Claim(context.Context, int) ([]dispatch.Lease, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	l := f.leases
	f.leases = nil
	return l, nil
}

func (f *fakeVerifications) Report(_ context.Context, _ dispatch.Lease, o dispatch.Observation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, o)
	return nil
}

// TestHR190_TheGatewayReportsWhatItRead: the runner claims, reads and
// reports; a task naming a write is never read nor reported.
func TestHR190_TheGatewayReportsWhatItRead(t *testing.T) {
	sim := payments.New(payments.Faults{}, pclog.Discard())
	var sent atomic.Int32
	h := setup(t, simTarget(sim, &sent))
	id := refundAt(t, sim, "ch_1", "pc-txn-1")
	f := &fakeVerifications{leases: []dispatch.Lease{
		{Connection: connID, Task: "t1", Operation: "payments.refund.get", Request: reference(id)},
		{Connection: connID, Task: "t2", Operation: "payments.refund.create", Request: reference(id)},
		{Connection: "01920000-0000-7000-8000-0000000000ff", Task: "t3", Operation: "payments.refund.get", Request: reference(id)},
	}}
	h.gw.verifications, h.gw.verifyEvery = f, time.Hour
	h.gw.verifyDue(context.Background())
	if len(f.reports) != 1 || !f.reports[0].Found || f.reports[0].Fields["/status"] != "succeeded" {
		t.Fatalf("reports %+v", f.reports)
	}
}
