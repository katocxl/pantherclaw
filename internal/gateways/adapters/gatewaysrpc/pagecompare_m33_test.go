// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gatewaysrpc

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect/v2"

	bsapp "github.com/katocxl/pantherclaw/internal/browsersites/app"
	gwapp "github.com/katocxl/pantherclaw/internal/gateways/app"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

type fakeCompares struct {
	calls         int
	org           ids.OrgID
	gateway, conn ids.UUID
	in            bsapp.PageCompare
	recorded      bool
	err           error
}

func (f *fakeCompares) ReportPageCompare(_ context.Context, org ids.OrgID, gateway, conn ids.UUID, in bsapp.PageCompare) (bool, error) {
	f.calls++
	f.org, f.gateway, f.conn, f.in = org, gateway, conn, in
	return f.recorded, f.err
}

// TestHR750_ThePageCompareReportCarriesTheCertificatesGateway: the org
// and the gateway come from the gateway's certificate alone; the report's
// digests and numbers pass through, and run and transaction are optional.
func TestHR750_ThePageCompareReportCarriesTheCertificatesGateway(t *testing.T) {
	f := &fakeCompares{recorded: true}
	h := (&GatewayHandler{}).WithPageCompares(f)
	id := gwapp.Identity{Org: ids.New[ids.Org](), Gateway: ids.NewV7(), Cert: ids.NewV7()}
	ctx := context.WithValue(context.Background(), identityKey{}, id)
	conn, run := ids.NewV7(), ids.NewV7()
	res, err := h.ReportPageCompare(ctx, &pantherclawv1.ReportPageCompareRequest{
		ConnectionId: conn.String(), RunId: run.String(), Host: "news.example.com", PathSha256: "ab",
		AgentStatus: 200, PlainStatus: 403, AgentBytes: 10, PlainBytes: 20, SimilarityPermille: 900,
	})
	if err != nil || !res.GetRecorded() || f.calls != 1 || f.org != id.Org || f.gateway != id.Gateway || f.conn != conn ||
		f.in.Run != run || !f.in.Transaction.IsZero() || f.in.Host != "news.example.com" || f.in.PlainStatus != 403 ||
		f.in.SimilarityPermille != 900 || f.in.PlainBytes != 20 {
		t.Fatalf("%v %v, passed %+v", res, err, f)
	}
}

// TestHR750_APageCompareReportWithoutAGatewayIsRefused: no gateway
// certificate, no page compares served, and malformed ids are refused
// before anything is recorded; the store's refusal is passed on.
func TestHR750_APageCompareReportWithoutAGatewayIsRefused(t *testing.T) {
	f := &fakeCompares{}
	h := (&GatewayHandler{}).WithPageCompares(f)
	id := gwapp.Identity{Org: ids.New[ids.Org](), Gateway: ids.NewV7()}
	ctx := context.WithValue(context.Background(), identityKey{}, id)
	ok := ids.NewV7().String()
	if _, err := h.ReportPageCompare(context.Background(), &pantherclawv1.ReportPageCompareRequest{ConnectionId: ok}); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("no certificate: %v", err)
	}
	if _, err := (&GatewayHandler{}).ReportPageCompare(ctx, &pantherclawv1.ReportPageCompareRequest{ConnectionId: ok}); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Errorf("not served: %v", err)
	}
	for name, req := range map[string]*pantherclawv1.ReportPageCompareRequest{
		"connection":  {ConnectionId: "nope"},
		"run":         {ConnectionId: ok, RunId: "nope"},
		"transaction": {ConnectionId: ok, TransactionId: "nope"},
	} {
		if _, err := h.ReportPageCompare(ctx, req); !errors.Is(err, errInvalidID) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if f.calls != 0 {
		t.Fatalf("%d calls reached the store", f.calls)
	}
	f.err = bsapp.ErrCompareHost
	if _, err := h.ReportPageCompare(ctx, &pantherclawv1.ReportPageCompareRequest{ConnectionId: ok, Host: "x.example"}); !errors.Is(err, bsapp.ErrCompareHost) {
		t.Errorf("store refusal: %v", err)
	}
}
