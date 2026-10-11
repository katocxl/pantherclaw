// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package capture

import (
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR199_ProfileLimits: the limits of design decision 10.
func TestHR199_ProfileLimits(t *testing.T) {
	ok := ProfileRequest{
		Purpose: "dispute", Connections: []ids.UUID{ids.NewV7()}, Operations: []string{"payments.refund.create"},
		Response: true, ByteCap: MaxBytes, RetentionDays: MaxRetentionDays, ExpiresInDays: MaxExpiryDays,
	}
	if err := ok.check(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*ProfileRequest){
		"a purpose over 500":   func(r *ProfileRequest) { r.Purpose = strings.Repeat("p", MaxPurpose+1) },
		"invalid UTF-8":        func(r *ProfileRequest) { r.Purpose = string([]byte{0xff}) },
		"33 connections":       func(r *ProfileRequest) { r.Connections = make([]ids.UUID, 33) },
		"a zero connection":    func(r *ProfileRequest) { r.Connections = []ids.UUID{{}} },
		"65 operations":        func(r *ProfileRequest) { r.Operations = make([]string, 65) },
		"neither body":         func(r *ProfileRequest) { r.Response = false },
		"a zero cap":           func(r *ProfileRequest) { r.ByteCap = 0 },
		"a cap over 64 KiB":    func(r *ProfileRequest) { r.ByteCap = MaxBytes + 1 },
		"no retention":         func(r *ProfileRequest) { r.RetentionDays = 0 },
		"an expiry of 91 days": func(r *ProfileRequest) { r.ExpiresInDays = MaxExpiryDays + 1 },
		"an operation pattern": func(r *ProfileRequest) { r.Operations = []string{"refund"} },
	} {
		r := ok
		mutate(&r)
		if err := r.check(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// TestHR199_AProfileCoversItsConnectionsOperationsAndDirections.
func TestHR199_AProfileCoversItsConnectionsOperationsAndDirections(t *testing.T) {
	conn := ids.NewV7()
	p := dbq.ActiveCaptureProfileRow{Connections: []ids.UUID{conn}, Operations: []string{"payments.refund.create"}, CaptureRequest: true}
	if !covers(p, conn, "payments.refund.create", Request) {
		t.Fatal("the profile does not cover its own request")
	}
	for name, ok := range map[string]bool{
		"the response":         covers(p, conn, "payments.refund.create", Response),
		"another connection":   covers(p, ids.NewV7(), "payments.refund.create", Request),
		"another operation":    covers(p, conn, "payments.charge.create", Request),
		"an unknown direction": covers(p, conn, "payments.refund.create", "headers"),
	} {
		if ok {
			t.Errorf("the profile covers %s", name)
		}
	}
}
