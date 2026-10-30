// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/platform/config"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// errHostedConnectors: a PantherClaw-hosted gateway never runs connectors
// (HR-084), whatever its configuration says.
var errHostedConnectors = errors.New("gateway: a PantherClaw-hosted gateway runs no connectors (HR-084)")

// checkHosted refuses a hosted gateway's configuration that could run
// connectors, or that names a second way to enroll.
func checkHosted(cfg *Config, enrollFile, hostedTokenFile string) error {
	if hostedTokenFile == "" {
		return nil
	}
	if enrollFile != "" {
		return errors.New("gateway: --hosted-token-file and --enroll-file exclude each other")
	}
	if cfg.Connectors.Enabled {
		return errHostedConnectors
	}
	if cfg.Control.APIURL == "" || cfg.Control.CASHA256 == "" {
		return errors.New("gateway: a hosted gateway needs control.api_url and control.ca_sha256")
	}
	return nil
}

// LoadOrEnrollHosted loads the hosted gateway's saved identity, or enrolls
// with the single-use token its host agent wrote to the process's private
// tmpfs (G0 M19 D203, HR-502). The token is read only as a secret file,
// never from the environment, and is never logged; once used it is
// worthless, and the host agent removes it.
func LoadOrEnrollHosted(ctx context.Context, cfg *Config, tokenFile string, log *slog.Logger) (*control.Identity, error) {
	id, err := control.Load(cfg.Control.IdentityDir, cfg.Control.CASHA256)
	if err == nil && !id.Expired(time.Now()) {
		return id, nil
	}
	tok, ferr := config.ReadSecretFile(tokenFile)
	if ferr != nil {
		if err == nil {
			return nil, errors.New("gateway: the gateway certificate expired and no enrollment token is waiting")
		}
		return nil, ferr
	}
	log.InfoContext(ctx, "gateway.enrolling", slog.String("api_url", cfg.Control.APIURL), slog.Bool("hosted", true))
	return enroll(ctx, cfg, cfg.Control.APIURL, cfg.Control.CASHA256, pclog.NewSecret(strings.TrimSpace(string(tok.Reveal()))))
}
