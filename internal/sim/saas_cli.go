// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"context"
	"flag"
	"io"
	"os"
	"strings"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/version"
	"github.com/katocxl/pantherclaw/internal/sim/chatgptenterprise"
	"github.com/katocxl/pantherclaw/internal/sim/copilotstudio"
)

// runCopilotStudio serves the simulated Copilot Studio environment (G0 M26
// D407).
func runCopilotStudio(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("copilot-studio", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", defaultAddrs["copilot-studio"], "listen address (loopback)")
	deny := fs.Bool("deny-components", false, "answer botcomponents 403")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-sim", Version: version.Get().Version})
	return serve(ctx, *addr, copilotstudio.New(copilotstudio.Faults{DenyComponents: *deny}, log).Handler(), log, "sim.copilot_studio_listening")
}

// runChatGPTEnterprise serves the simulated ChatGPT Enterprise Compliance API
// (G0 M26 D407).
func runChatGPTEnterprise(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("chatgpt-enterprise", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", defaultAddrs["chatgpt-enterprise"], "listen address (loopback)")
	keyFile := fs.String("key-file", "", "file holding the only accepted key (otherwise any is)")
	deny := fs.Bool("deny", false, "answer the list 403")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var key string
	if *keyFile != "" {
		b, err := os.ReadFile(*keyFile)
		if err != nil {
			return err
		}
		key = strings.TrimSpace(string(b))
	}
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-sim", Version: version.Get().Version})
	return serve(ctx, *addr, chatgptenterprise.New(key, chatgptenterprise.Faults{Deny: *deny}, log).Handler(), log, "sim.chatgpt_enterprise_listening")
}
