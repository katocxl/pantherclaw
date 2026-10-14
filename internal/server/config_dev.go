// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
)

// DevConfig holds development-only settings. DEVELOPMENT ONLY.
type DevConfig struct {
	// PackageKeyFile is the public JWKS of the development package key
	// that `dev seed` keeps (deploy/dev/secrets/package-dev.pub.json); the
	// private key is the .key file beside it. The API then also trusts
	// that key for package imports (HR-163, G0 M4 decision 3). A
	// configuration naming it is refused unless the server can be reached
	// only from this machine (localOnly). It has no environment variable:
	// only a configuration file turns it on.
	PackageKeyFile string `json:"package_key_file"`
}

const (
	devPublicSuffix  = ".pub.json"
	devPrivateSuffix = ".key"
)

// devPrivateKeyFile is the private half of the development package key
// named by public, as `pclaw package-key create` names its pairs.
func devPrivateKeyFile(public string) string {
	return strings.TrimSuffix(public, devPublicSuffix) + devPrivateSuffix
}

func (c *Config) validateDev() []error {
	if c.Dev.PackageKeyFile == "" {
		return nil
	}
	var errs []error
	if !strings.HasSuffix(c.Dev.PackageKeyFile, devPublicSuffix) {
		errs = append(errs, errors.New("dev.package_key_file must name the .pub.json file of the development package key"))
	}
	if err := c.localOnly(); err != nil {
		errs = append(errs, fmt.Errorf("dev.package_key_file is development-only (HR-163): %w", err))
	}
	return errs
}

// localOnly reports why this server could be reached, or could present
// itself, beyond this machine: a listener or public URL off loopback, a
// declared proxy, or live API keys (HR-163).
func (c *Config) localOnly() error {
	var errs []error
	if !loopback(c.HTTP.Addr) {
		errs = append(errs, errors.New("http.addr must be loopback"))
	}
	if c.HTTP.PlaintextBehindProxy || len(c.HTTP.TrustedProxies) > 0 {
		errs = append(errs, errors.New("no proxy may be declared (http.plaintext_behind_proxy, http.trusted_proxies)"))
	}
	if !loopbackURL(c.Auth.PublicURL) {
		errs = append(errs, errors.New("auth.public_url must be on loopback"))
	}
	g := c.GatewayAPI
	if g.Addr != "" && !loopback(g.Addr) {
		errs = append(errs, errors.New("gateway_api.addr must be loopback"))
	}
	for _, h := range g.Hostnames {
		if !loopbackHost(h) {
			errs = append(errs, errors.New("gateway_api.hostnames must all be loopback"))
			break
		}
	}
	if g.URL != "" && !loopbackURL(g.URL) {
		errs = append(errs, errors.New("gateway_api.url must be on loopback"))
	}
	if credential.Env(c.Auth.APIKeyEnv) == credential.EnvLive {
		errs = append(errs, errors.New("auth.api_key_env must not be live"))
	}
	return errors.Join(errs...)
}

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

func loopbackURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && loopbackHost(u.Hostname())
}

// localDatabase reports a database host off this machine: dev seed needs
// loopback or a unix socket directory (an absolute path, as libpq reads it).
// pgx takes a comma-separated list and falls back along it, so every host
// listed must be local.
func localDatabase(host string) error {
	for h := range strings.SplitSeq(host, ",") {
		if !loopbackHost(h) && !strings.HasPrefix(h, "/") {
			return errors.New("database.host must be loopback or a unix socket (every host it lists)")
		}
	}
	return nil
}
