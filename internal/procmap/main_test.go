// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package main

import (
	"bytes"
	json "encoding/json/v2"
	"maps"
	"testing"

	"github.com/katocxl/pantherclaw/internal/server"
)

// TestRunPrintsTheProcedureMap (G0 M22 D9): the output round-trips to the
// server's map and is byte-stable between runs.
func TestRunPrintsTheProcedureMap(t *testing.T) {
	var first, second bytes.Buffer
	if err := run(&first); err != nil {
		t.Fatal(err)
	}
	if err := run(&second); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Error("two runs differ")
	}
	var got map[string]server.ProcedureInfo
	if err := json.Unmarshal(first.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(got, server.ProcedureMap()) {
		t.Error("output differs from server.ProcedureMap")
	}
}
