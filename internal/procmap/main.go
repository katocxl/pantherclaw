// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Command procmap prints every procedure the server serves as JSON (G0 M22
// D9), with the permission and plan-gate class it enforces:
//
//	{"<procedure>":{"permission":"…","class":"…"}}
//
// Keys are sorted, so the output is stable between runs. It lives here and not
// under tools/ because tools/ is its own module, which cannot reach
// internal/server from `go run` at the repository root.
//
//	go run ./internal/procmap
package main

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"fmt"
	"io"
	"os"

	"github.com/katocxl/pantherclaw/internal/server"
)

func main() {
	if err := run(os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "procmap:", err)
		os.Exit(1)
	}
}

func run(w io.Writer) error {
	out, err := json.Marshal(server.ProcedureMap(), json.Deterministic(true), jsontext.Multiline(true))
	if err != nil {
		return err
	}
	_, err = w.Write(append(out, '\n'))
	return err
}
