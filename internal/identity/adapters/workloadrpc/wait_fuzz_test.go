// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package workloadrpc

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	approvals "github.com/katocxl/pantherclaw/internal/approvals/app"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// waitStates are the states a wait handle shows (HR-174).
var waitStates = []string{
	apdomain.WaitPending, apdomain.WaitEvidenceRequested, apdomain.WaitReady, apdomain.WaitDeclined, apdomain.WaitNarrowerProposed,
	apdomain.WaitExpired, apdomain.WaitSuperseded, apdomain.WaitInvalidated, apdomain.WaitConsumed,
}

// FuzzWaitRequest (G0 M5 part 2, HR-174): no Wait request, in Connect's
// binary or JSON encoding, panics the handler's parsing, and its run and
// handle are taken only as UUIDv7s that are one spelling of the id the
// request names. A state the handle shows reaches the waiter as the
// enum of that name, so the known state a waiter sends back (pclaw
// workload wait --follow) is exactly the state Wait compares with; any
// other text maps to no state.
func FuzzWaitRequest(f *testing.F) {
	run, handle := ids.NewV7().String(), ids.NewV7().String()
	for _, req := range []*pantherclawv1.WaitRequest{
		{RunId: run, Handle: handle, KnownState: pantherclawv1.WaitState_WAIT_STATE_PENDING, TimeoutSeconds: 30},
		{RunId: run, Handle: handle, TimeoutSeconds: -1},
		{RunId: strings.ToUpper(run), Handle: "{" + handle + "}", KnownState: 42, TimeoutSeconds: 1 << 30},
		{RunId: "019a0000-0000-4000-8000-000000000001", Handle: handle},
	} {
		b, err := proto.Marshal(req)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b, false, apdomain.WaitReady)
		j, err := protojson.Marshal(req)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(j, true, "WAIT_STATE_READY")
	}
	f.Add([]byte(`{"runId":"`+run+`","handle":"`+handle+`","knownState":"WAIT_STATE_CONSUMED","timeoutSeconds":"30"}`), true, "")
	for _, s := range waitStates {
		f.Add([]byte{}, false, s)
	}
	f.Fuzz(func(t *testing.T, wire []byte, asJSON bool, state string) {
		var req pantherclawv1.WaitRequest
		var err error
		if asJSON {
			err = protojson.Unmarshal(wire, &req)
		} else {
			err = proto.Unmarshal(wire, &req)
		}
		if err == nil {
			if r, h, err := runAndHandle(req.GetRunId(), req.GetHandle()); err == nil {
				for in, got := range map[string]ids.UUID{req.GetRunId(): r, req.GetHandle(): h} {
					again, err := ids.ParseUUID(got.String())
					if got.Version() != 7 || !strings.EqualFold(got.String(), in) || err != nil || again != got {
						t.Fatalf("took %q as the id %s", in, got)
					}
				}
			}
		}
		shown := WaitInfo(approvals.WaitView{Handle: ids.NewV7(), State: state}).GetState()
		known := strings.TrimPrefix(shown.String(), "WAIT_STATE_") // as Wait reads KnownState
		isState := false
		for _, s := range waitStates {
			isState = isState || s == state
		}
		switch {
		case isState && known != state:
			t.Fatalf("the state %q is shown as %s", state, shown)
		case !isState && shown != pantherclawv1.WaitState_WAIT_STATE_UNSPECIFIED:
			t.Fatalf("the text %q is shown as the state %s", state, shown)
		}
	})
}
