// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize

import (
	"encoding/base64"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// rawSigner returns header.payload.sig with the payload as given.
type rawSigner struct{}

func (rawSigner) Sign(_ string, payload []byte) (string, error) {
	return "h." + base64.RawURLEncoding.EncodeToString(payload) + ".s", nil
}

// TestM14_TheExecutionReceiptStatesTheDataScope: what the gateway's data
// scope did to an answer goes on the execution receipt as the record key
// and counts, never a value; without it the receipt says nothing about it
// (G0 M14 D102).
func TestM14_TheExecutionReceiptStatesTheDataScope(t *testing.T) {
	a := &Authority{Receipts: rawSigner{}}
	gw := Gateway{ID: "gw", Org: ids.New[ids.Org]()}
	x := Executed{Transaction: ids.NewV7(), AccessMode: AccessPantherClawHeld}
	payload := func(e Execution) map[string]any {
		r, err := a.executionReceipt(gw, e, x, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(strings.Split(r.JWS, ".")[1])
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		return out["pap"].(map[string]any)
	}
	pap := payload(Execution{Permit: ids.NewV7(), Outcome: Accepted, DataScope: &DataScopeApplied{
		RecordsKey: "customer", Rows: 3, ValuesRedacted: 7, Truncated: true,
	}})
	scope, ok := pap["data_scope"].(map[string]any)
	if !ok || scope["records_key"] != "customer" || scope["rows"] != float64(3) || scope["values_redacted"] != float64(7) || scope["truncated"] != true {
		t.Fatalf("data scope %v", pap["data_scope"])
	}
	if _, ok := payload(Execution{Permit: ids.NewV7(), Outcome: Accepted})["data_scope"]; ok {
		t.Fatal("a receipt without a data scope states one")
	}
}
