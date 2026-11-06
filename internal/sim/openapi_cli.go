// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/katocxl/pantherclaw/internal/definitions/openapi"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/version"
	simopenapi "github.com/katocxl/pantherclaw/internal/sim/openapi"
)

// runOpenAPI serves a generic simulated target from an OpenAPI 3 spec (G0
// M31 D954): each operation answers with its first example, or {}.
func runOpenAPI(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("openapi", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", defaultAddrs["openapi"], "listen address (loopback)")
	specFile := fs.String("spec", "", "the OpenAPI 3.0 or 3.1 spec to serve (JSON or YAML)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *specFile == "" || fs.NArg() != 0 {
		return errors.New("openapi needs --spec FILE")
	}
	f, err := os.Open(*specFile)
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(f, openapi.MaxSpecBytes+1))
	_ = f.Close()
	if err != nil {
		return err
	}
	if len(raw) > openapi.MaxSpecBytes {
		return fmt.Errorf("the spec is larger than %d bytes", openapi.MaxSpecBytes)
	}
	s, err := openapi.Parse(raw)
	if err != nil {
		return err
	}
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-sim", Version: version.Get().Version})
	return serve(ctx, *addr, simopenapi.New(s, log).Handler(), log, "sim.openapi_listening")
}
