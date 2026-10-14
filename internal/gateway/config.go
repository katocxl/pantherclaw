// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package gateway is the PantherClaw gateway (G0 M6): the enforcement
// point between agents and their targets. It has no database access
// (ADR-0002). It proves which org it serves with a certificate from
// PantherClaw's internal CA and talks to the Authority over mutual TLS
// (HR-180, HR-181); workloads prove who they are with PAP/1, which the
// gateway forwards for the Authority to verify (HR-021).
package gateway

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/connectors"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/platform/config"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Config is the pantherclaw-gateway configuration (JSON file + PC_GW_* env).
type Config struct {
	Log struct {
		Level string `json:"level" env:"PC_GW_LOG_LEVEL"`
	} `json:"log"`
	// Listen is the agent-facing address. Plain HTTP only on loopback;
	// otherwise set tls.cert_file and tls.key_file.
	Listen string `json:"listen" env:"PC_GW_LISTEN"`
	TLS    struct {
		CertFile string `json:"cert_file" env:"PC_GW_TLS_CERT_FILE"`
		KeyFile  string `json:"key_file" env:"PC_GW_TLS_KEY_FILE"`
	} `json:"tls"`
	// PublicURL is the base URL workloads call; request proofs are checked
	// against it, never against the Host header (PAP-1 §4).
	PublicURL string `json:"public_url" env:"PC_GW_PUBLIC_URL"`
	Control   struct {
		// APIURL is the server's public API, used only to enroll.
		APIURL string `json:"api_url" env:"PC_GW_CONTROL_API_URL"`
		// CASHA256 pins the internal CA ("sha256:<hex>", given with the
		// enrollment token).
		CASHA256 string `json:"ca_sha256" env:"PC_GW_CONTROL_CA_SHA256"`
		// GatewayURL overrides the gateway listener URL the server named at
		// enrollment.
		GatewayURL string `json:"gateway_url" env:"PC_GW_CONTROL_GATEWAY_URL"`
		// IdentityDir keeps the gateway's key and certificate (0700).
		IdentityDir string          `json:"identity_dir" env:"PC_GW_IDENTITY_DIR"`
		Timeout     config.Duration `json:"timeout" env:"PC_GW_CONTROL_TIMEOUT"`
		// VerifyEvery is how often the gateway claims verification tasks
		// (G0 M7): 1 second to 10 minutes, default 10 seconds.
		VerifyEvery config.Duration `json:"verify_every" env:"PC_GW_CONTROL_VERIFY_EVERY"`
	} `json:"control"`
	// Egress is what the gateway may reach (HR-071, HR-077). The targets
	// themselves are the connections the server configures.
	Egress struct {
		// AllowedPrefixes re-allow private ranges the operator's targets
		// live in, for example 10.0.0.0/8, or 127.0.0.1/32 for
		// pantherclaw-sim. Cloud metadata stays denied. Only the operator
		// sets this; nothing a tenant configures widens it.
		AllowedPrefixes []string `json:"allowed_prefixes" env:"PC_GW_EGRESS_ALLOWED_PREFIXES"`
	} `json:"egress"`
	// Broker holds the broker key (G0 M6 design decision 8): the key file
	// from `broker-key generate` and the key-encryption key files that
	// unwrap it (first current, others for rotation). Without it, no
	// pantherclaw_held credential can be used.
	Broker struct {
		KeyFile  string   `json:"key_file" env:"PC_GW_BROKER_KEY_FILE"`
		KEKFiles []string `json:"kek_files" env:"PC_GW_BROKER_KEK_FILES"`
	} `json:"broker"`
	// Approvals is how the gateway checks approvals itself (HR-038).
	Approvals struct {
		// ApproverKeysFile is the approver keys file the operator exported
		// with `pclaw approver-keys export` and reviewed. An action whose
		// permit carries an approval is dispatched only when every
		// approver's WebAuthn assertion verifies against a key in it; with
		// no file, every such action is refused. The file is read again
		// when it changes.
		ApproverKeysFile string `json:"approver_keys_file" env:"PC_GW_APPROVALS_APPROVER_KEYS_FILE"`
	} `json:"approvals"`
	// Connectors runs connector connections (G0 M9 track C): off unless
	// enabled, and only on a customer-hosted gateway that runs as a host
	// process (HR-084).
	Connectors connectors.Config `json:"connectors"`
	// GitHub is how the gateway reads GitHub for its GitHub App
	// connections (G0 M8).
	GitHub struct {
		// FactTimeout bounds the reads of the github.* facts before a
		// decision: at most 5 seconds, default 2. A fact not read in time
		// is not reported, so the decision sees it missing.
		FactTimeout config.Duration `json:"fact_timeout" env:"PC_GW_GITHUB_FACT_TIMEOUT"`
		// APIURL is GitHub's REST API, where a GitHub App connection to
		// GitHub's MCP server mints its per-action tokens and reads its
		// facts (ADR-0021); a connection to the REST API uses its own base
		// URL. Default https://api.github.com; for GitHub Enterprise Server
		// https://HOST/api/v3. Plain http only on loopback (the simulator).
		APIURL string `json:"api_url" env:"PC_GW_GITHUB_API_URL"`
	} `json:"github"`
}

// DefaultConfig returns development defaults.
func DefaultConfig() Config {
	var c Config
	c.Log.Level = "info"
	c.Listen = "127.0.0.1:8090"
	c.PublicURL = "http://127.0.0.1:8090"
	c.Control.APIURL = "http://127.0.0.1:8080"
	c.Control.IdentityDir = "deploy/dev/secrets/gateway"
	c.Control.Timeout = config.Duration(2 * time.Second)
	c.Control.VerifyEvery = config.Duration(VerifyEvery)
	c.GitHub.FactTimeout = config.Duration(dispatch.DefaultFactTimeout)
	c.GitHub.APIURL = dispatch.DefaultGitHubAPIURL
	return c
}

var pinPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Validate implements config.Validator.
func (c *Config) Validate() error {
	var errs []error
	if _, ok := pclog.ParseLevel(c.Log.Level); !ok {
		errs = append(errs, errors.New("log.level must be debug, info, warn or error"))
	}
	if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		errs = append(errs, errors.New("tls.cert_file and tls.key_file must be set together"))
	}
	if c.TLS.CertFile == "" && !loopback(c.Listen) {
		errs = append(errs, errors.New("listen must be a loopback address unless tls.cert_file and tls.key_file are set"))
	}
	if c.Control.IdentityDir == "" {
		errs = append(errs, errors.New("control.identity_dir is required"))
	}
	if d := c.Control.VerifyEvery.D(); d != 0 && (d < time.Second || d > 10*time.Minute) {
		errs = append(errs, errors.New("control.verify_every must be between 1s and 10m"))
	}
	if d := c.GitHub.FactTimeout.D(); d < 0 || d > 5*time.Second {
		errs = append(errs, errors.New("github.fact_timeout must be at most 5s"))
	}
	if err := apiURL(c.GitHub.APIURL); err != nil {
		errs = append(errs, fmt.Errorf("github.api_url: %w", err))
	}
	if c.Control.CASHA256 != "" && !pinPattern.MatchString(c.Control.CASHA256) {
		errs = append(errs, errors.New("control.ca_sha256 must be sha256: and 64 hex digits"))
	}
	if c.Control.APIURL != "" {
		if u, err := baseURL(c.Control.APIURL); err != nil {
			errs = append(errs, fmt.Errorf("control.api_url: %w", err))
		} else if u.Scheme == "http" && !loopback(u.Host) {
			errs = append(errs, errors.New("control.api_url may use plain http only on loopback"))
		}
	}
	if c.Control.GatewayURL != "" {
		if u, err := baseURL(c.Control.GatewayURL); err != nil || u.Scheme != "https" {
			errs = append(errs, errors.New("control.gateway_url must be https://host[:port]"))
		}
	}
	if _, err := c.allowedPrefixes(); err != nil {
		errs = append(errs, err)
	}
	if (c.Broker.KeyFile == "") != (len(c.Broker.KEKFiles) == 0) {
		errs = append(errs, errors.New("broker.key_file and broker.kek_files must be set together"))
	}
	if c.Control.Timeout.D() <= 0 {
		errs = append(errs, errors.New("control.timeout must be positive"))
	}
	if _, err := baseURL(c.PublicURL); err != nil {
		errs = append(errs, fmt.Errorf("public_url: %w", err))
	}
	return errors.Join(errs...)
}

// allowedPrefixes parses egress.allowed_prefixes.
func (c *Config) allowedPrefixes() ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(c.Egress.AllowedPrefixes))
	for _, s := range c.Egress.AllowedPrefixes {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("egress.allowed_prefixes: %q is not a CIDR prefix", s)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// baseURL accepts only scheme://host[:port] with no path, query or userinfo.
func baseURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	switch {
	case err != nil:
		return nil, errors.New("does not parse")
	case u.Scheme != "http" && u.Scheme != "https":
		return nil, errors.New("scheme must be http or https")
	case u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "":
		return nil, errors.New("must be scheme://host[:port] only")
	}
	u.Path = ""
	return u, nil
}

// apiURL checks GitHub's API URL: http or https, a host and an optional
// path (GitHub Enterprise Server's /api/v3), nothing else; plain http only
// on loopback. Empty is the default.
func apiURL(s string) error {
	if s == "" {
		return nil
	}
	u, err := url.Parse(s)
	switch {
	case err != nil:
		return errors.New("does not parse")
	case u.Scheme != "http" && u.Scheme != "https":
		return errors.New("scheme must be http or https")
	case u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "":
		return errors.New("must be scheme://host[:port][/path] only")
	case u.Scheme == "http" && !loopback(u.Host):
		return errors.New("may use plain http only on loopback")
	}
	return nil
}

func loopback(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}
