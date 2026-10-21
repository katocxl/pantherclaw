// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/katocxl/pantherclaw/internal/extension"
)

// errDeploymentConfig prefixes every start-up refusal of the deployment
// settings (error code DEPLOYMENT_CONFIG, ADR-0031).
const errDeploymentConfig = "DEPLOYMENT_CONFIG: "

// deployment returns the configured deployment (validated by Validate); an
// unset one is development.
func (c *Config) deployment() extension.Deployment {
	if c.Deployment == "" {
		return extension.DeploymentDevelopment
	}
	return extension.Deployment(c.Deployment)
}

func (c *Config) validateDeployment() []error {
	if !c.deployment().Valid() {
		return []error{errors.New(errDeploymentConfig + "deployment must be development, staging or production")}
	}
	var errs []error
	if c.deployment() == extension.DeploymentProduction {
		// A development identity provider signs anyone in (HR-346).
		// So does one on a loopback issuer, which only a local mock or
		// Keycloak has, flagged or not.
		for i, p := range c.Auth.OIDCProviders {
			if p.Dev || p.AllowInsecureLoopback || loopbackIssuer(p.Issuer) {
				errs = append(errs, fmt.Errorf("%sauth.oidc_providers[%d] (%q) is a development provider (dev: true, "+
					"allow_insecure_loopback or a loopback issuer), which a production deployment refuses",
					errDeploymentConfig, i, p.Name))
			}
		}
	}
	return errs
}

// loopbackIssuer reports a URL whose host is localhost (or a subdomain of it)
// or a loopback address.
func loopbackIssuer(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	h := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	a, err := netip.ParseAddr(h)
	return err == nil && a.Unmap().IsLoopback()
}

// checkDeploymentFor refuses to serve a build with an extension unless
// `deployment` was set explicitly: a hosted production config that forgot
// it must not run as development (HR-346, D48).
func (c *Config) checkDeploymentFor(ext extension.Set) error {
	if ext.Present() && c.Deployment == "" {
		return errors.New(errDeploymentConfig + "a build with an extension needs an explicit deployment " +
			"(development, staging or production)")
	}
	return nil
}
